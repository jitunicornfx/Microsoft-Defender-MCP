package com.jitunicornfx.defender.mcp

import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.core.Context
import com.github.ajalt.clikt.core.ProgramResult
import com.github.ajalt.clikt.core.main
import com.github.ajalt.clikt.parameters.options.default
import com.github.ajalt.clikt.parameters.options.flag
import com.github.ajalt.clikt.parameters.options.help
import com.github.ajalt.clikt.parameters.options.multiple
import com.github.ajalt.clikt.parameters.options.option
import com.github.ajalt.clikt.parameters.options.switch
import com.github.ajalt.clikt.parameters.types.choice
import com.github.ajalt.clikt.parameters.types.int
import io.ktor.server.cio.CIO
import io.ktor.server.engine.EmbeddedServer
import io.ktor.server.engine.embeddedServer
import io.ktor.server.routing.routing
import io.modelcontextprotocol.kotlin.sdk.server.StdioServerTransport
import io.modelcontextprotocol.kotlin.sdk.server.mcpStreamableHttp
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.server.ServerSession
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import kotlinx.io.asSink
import kotlinx.io.asSource
import kotlinx.io.buffered
import java.io.File
import java.io.InputStream
import java.util.concurrent.atomic.AtomicBoolean
import java.io.PrintStream

const val DEFAULT_HTTP_HOST = "127.0.0.1"
const val DEFAULT_HTTP_PORT = 3074
const val STREAMABLE_HTTP_PATH = "/mcp"
const val LEGACY_SSE_PATH = "/sse"
internal const val HTTP_MAX_LIVE_SESSIONS = 32

internal enum class Transport { STDIO, HTTP }

/**
 * Command-line entry point (Clikt). Configuration comes from `DEFENDER_*` environment variables
 * (secrets never belong on a command line, where any local user can read them from the process
 * list); flags select the transport and may adjust the safety settings.
 *
 * [configProvider], [serve] and [selfTest] are seams so tests can drive parsing and dispatch
 * without the real environment, a real tenant or a blocking server.
 */
class DefenderMcpCommand internal constructor(
    private val configProvider: () -> Config,
    private val serve: (transport: Transport, host: String, port: Int, config: Config) -> Unit,
    private val selfTest: (Config) -> Boolean,
) : CliktCommand(name = "microsoft-defender-mcp") {

    constructor() : this({ Config.fromEnv() }, ::runServer, { runSelfTestAll(it) })

    override fun help(context: Context): String =
        "Run the Microsoft Defender for Endpoint MCP server over stdio (default) or Streamable HTTP/SSE."

    override fun helpEpilog(context: Context): String =
        """
        |Required environment: ${Config.ENV_TENANT_ID}, ${Config.ENV_CLIENT_ID}, ${Config.ENV_CLIENT_SECRET} (an Entra ID app registration with Defender API application permissions).
        |
        |Several tenants: set ${Config.ENV_TENANTS}=contoso,fabrikam instead, then DEFENDER_<NAME>_TENANT_ID, DEFENDER_<NAME>_CLIENT_ID, DEFENDER_<NAME>_CLIENT_SECRET and optionally DEFENDER_<NAME>_CLOUD, DEFENDER_<NAME>_REGION, DEFENDER_<NAME>_ACCESS_LEVEL for each (names: lowercase letters, digits and '-'; '-' becomes '_' in variable names). Every tool then takes a 'tenant' argument, required unless ${Config.ENV_DEFAULT_TENANT} names one.
        |
        |Optional: ${Config.ENV_CLOUD} (${CloudEnvironment.entries.joinToString("|") { it.code }}), ${Config.ENV_REGION} (${DefenderRegion.entries.joinToString("|") { it.code }}; default global https://api.security.microsoft.com), ${Config.ENV_ACCESS_LEVEL} (read-only|write|destructive), ${Config.ENV_CONFIRMATION} (elicit|none), ${Config.ENV_MAX_ACTIONS_PER_HOUR}, ${Config.ENV_MAX_CONCURRENT_REQUESTS}, ${Config.ENV_TIMEOUT_MS}, ${Config.ENV_MAX_RESPONSE_BYTES}, ${Config.ENV_MAX_RESULT_CHARS}, ${Config.ENV_TOOLS}.
        |
        |Updates: on start the server checks GitHub for a newer release and, if one is published with a verified SHA-256 digest, installs it (restart to run it). ${Config.ENV_DISABLE_AUTO_UPDATE}=1 / --no-auto-update only reports it; ${Config.ENV_DISABLE_UPDATE_CHECK}=1 / --no-update-check skips the check.
        |
        |HTTP mode: ${Config.ENV_MCP_AUTH_TOKEN} (bearer token; mandatory and at least ${HttpSecurity.MIN_TOKEN_LENGTH} characters off loopback), ${Config.ENV_HTTP_ALLOWED_ORIGINS}.
        """.trimMargin()

    private val transport: Transport by option()
        .switch("--stdio" to Transport.STDIO, "--http" to Transport.HTTP)
        .default(Transport.STDIO)
        .help("Transport to run. Defaults to --stdio.")

    private val host: String by option("--host").default(DEFAULT_HTTP_HOST)
        .help("Address to listen on in HTTP mode. Defaults to $DEFAULT_HTTP_HOST (loopback).")

    private val port: Int by option("--port").int().default(DEFAULT_HTTP_PORT)
        .help("Port to listen on in HTTP mode. Defaults to $DEFAULT_HTTP_PORT.")

    private val access: String? by option("--access")
        .choice("read-only", "write", "destructive")
        .help("Access level, overriding ${Config.ENV_ACCESS_LEVEL}. Defaults to read-only.")

    private val region: String? by option("--region")
        .choice(*DefenderRegion.entries.map { it.code }.toTypedArray())
        .help("Regional Defender API endpoint, overriding ${Config.ENV_REGION}. Default: global https://api.security.microsoft.com.")

    private val noConfirm: Boolean by option("--no-confirm").flag(default = false)
        .help("Do not ask a human to approve state-changing calls (unattended automation only). Same as ${Config.ENV_CONFIRMATION}=none.")

    private val maxActionsPerHour: Int? by option("--max-actions-per-hour").int()
        .help("State-changing calls allowed per rolling hour, overriding ${Config.ENV_MAX_ACTIONS_PER_HOUR}.")

    private val tools: List<String> by option("--tools").multiple()
        .help("Glob(s) of tool names to expose, e.g. 'defender_get_*'. Repeatable, comma-separated allowed.")

    private val noUpdateCheck: Boolean by option("--no-update-check").flag(default = false)
        .help("Skip the startup check for a newer release (implies --no-auto-update). Same as ${Config.ENV_DISABLE_UPDATE_CHECK}=1.")

    private val noAutoUpdate: Boolean by option("--no-auto-update").flag(default = false)
        .help("Report a newer release but never download or install it. Same as ${Config.ENV_DISABLE_AUTO_UPDATE}=1.")

    private val check: Boolean by option("--check").flag(default = false)
        .help("Validate the configuration, acquire a token and exit (0 on success).")

    override fun run() {
        val fromEnv = try {
            configProvider()
        } catch (e: IllegalArgumentException) {
            echo("Configuration error: ${e.message}", err = true)
            throw ProgramResult(1)
        }
        if (region != null && fromEnv.isMultiTenant) {
            echo(
                "Configuration error: --region is ambiguous with several tenants; set DEFENDER_<NAME>_REGION for each tenant instead.",
                err = true,
            )
            throw ProgramResult(1)
        }
        val config = try {
            fromEnv.copy(
                region = region?.let(DefenderRegion::fromCode) ?: fromEnv.region,
                accessLevel = access?.let(Config::parseAccessLevel) ?: fromEnv.accessLevel,
                confirmation = if (noConfirm) ConfirmationMode.NONE else fromEnv.confirmation,
                maxActionsPerHour = maxActionsPerHour ?: fromEnv.maxActionsPerHour,
                toolGlobs = if (tools.isEmpty()) fromEnv.toolGlobs else tools.flatMap { Config.csv(it) },
                updateCheckDisabled = fromEnv.updateCheckDisabled || noUpdateCheck,
                autoUpdateDisabled = fromEnv.autoUpdateDisabled || noAutoUpdate || noUpdateCheck || fromEnv.updateCheckDisabled,
            )
        } catch (e: IllegalArgumentException) {
            echo("Configuration error: ${e.message}", err = true)
            throw ProgramResult(1)
        }

        ToolRegistry.unmatchedGlobs(config.toolGlobs).forEach {
            echo("[defender-mcp] WARNING: --tools glob '$it' matches no tool name.", err = true)
        }
        if (ToolRegistry.select(config).isEmpty()) {
            echo("Configuration error: the tool globs and access level select no API tools.", err = true)
            throw ProgramResult(1)
        }
        warnAboutSafety(config)

        if (check) {
            if (!selfTest(config)) throw ProgramResult(1)
            echo("[defender-mcp] Configuration OK.", err = true)
            return
        }
        if (transport == Transport.HTTP) checkBearerToken(config.httpAuthToken)
        serve(transport, host, port, config)
    }

    private fun warnAboutSafety(config: Config) {
        if (config.effectiveAccessLevel != AccessLevel.READ_ONLY && config.confirmation == ConfirmationMode.NONE) {
            echo(
                "[defender-mcp] WARNING: state-changing tools are enabled WITHOUT human approval. A prompt-injected " +
                    "agent could act on devices; only the ${config.maxActionsPerHour}/hour budget limits it.",
                err = true,
            )
        }
        config.accessCapNotices().forEach { echo("[defender-mcp] WARNING: $it", err = true) }
        if (config.effectiveAccessLevel == AccessLevel.DESTRUCTIVE) {
            echo("[defender-mcp] Access level 'destructive': bulk tagging, tag replacement and forensic collection are enabled.", err = true)
        }
    }

    /** Off loopback the bearer token is the only barrier to the Defender credentials; refuse a missing or weak one. */
    private fun checkBearerToken(token: String?) {
        val short = token != null && token.length < HttpSecurity.MIN_TOKEN_LENGTH
        if (isLoopback(host)) {
            if (short) echo("[defender-mcp] WARNING: ${Config.ENV_MCP_AUTH_TOKEN} is short; use `openssl rand -hex 32`.", err = true)
            return
        }
        if (token == null) {
            echo("Refusing to listen on $host without ${Config.ENV_MCP_AUTH_TOKEN}; set one or bind to loopback.", err = true)
            throw ProgramResult(2)
        }
        if (short) {
            echo(
                "Refusing to listen on $host: ${Config.ENV_MCP_AUTH_TOKEN} must be at least ${HttpSecurity.MIN_TOKEN_LENGTH} characters off loopback.",
                err = true,
            )
            throw ProgramResult(2)
        }
    }
}

fun main(args: Array<String>) {
    System.err.println(startupBanner(args))
    DefenderMcpCommand().main(args)
}

/** Version, runtime and which `DEFENDER_*` variables are present (names only, never values). */
internal fun startupBanner(args: Array<String>, env: Map<String, String> = System.getenv()): String {
    val present = env.keys.filter { it.startsWith("DEFENDER_") }.sorted()
    return "[defender-mcp] $SERVER_NAME $SERVER_VERSION starting - java ${System.getProperty("java.version")}, " +
        "${System.getProperty("os.name")} ${System.getProperty("os.arch")}\n" +
        "[defender-mcp] args: ${if (args.isEmpty()) "(none)" else args.joinToString(" ")}\n" +
        "[defender-mcp] environment: ${if (present.isEmpty()) "no DEFENDER_* variables set" else present.joinToString(", ")}"
}

/** `--check`: acquire a Defender API token and the Microsoft Graph token advanced hunting uses. */
internal fun runSelfTest(config: Config, client: DefenderClient = DefenderClient(config)): Boolean =
    runBlocking { checkTenant(config, client, label = null) }

/**
 * `--check` for every configured tenant, concurrently: each tenant's tokens are acquired with its
 * own client, and each result is reported under the tenant's name. True only if all succeed.
 */
internal fun runSelfTestAll(config: Config, clientFactory: (Config) -> DefenderClient = { DefenderClient(it) }): Boolean =
    runBlocking {
        coroutineScope {
            config.tenants.map { tenant ->
                async {
                    val view = config.forTenant(tenant)
                    checkTenant(view, clientFactory(view), label = tenant.name.takeIf { config.isMultiTenant })
                }
            }.awaitAll()
        }.all { it }
    }

/** Acquire the Defender and Graph tokens for one tenant. Messages are server-authored and secret-free. */
private suspend fun checkTenant(config: Config, client: DefenderClient, label: String?): Boolean = client.use {
    val prefix = "[defender-mcp] " + (label?.let { "tenant '$it': " } ?: "")
    try {
        it.tokens.token(config.cloud.scope)
        System.err.println("${prefix}Acquired a Defender API token for ${config.cloud.code}.")
        it.tokens.token(config.cloud.graphScope)
        System.err.println("${prefix}Acquired a Microsoft Graph token for advanced hunting.")
        true
    } catch (e: TokenAcquisitionException) {
        System.err.println("$prefix${e.message}")
        false
    }
}

/** Tenant names with their cloud and API host, for startup lines; never credentials. */
internal fun describeTenants(config: Config): String =
    config.tenants.joinToString("; ") { t ->
        (if (config.isMultiTenant) "${t.name}: " else "") + "${t.cloud.code}, ${t.apiBaseUrl}"
    }

/**
 * How long to wait, after a Streamable HTTP client says `initialized`, before pushing the update notice:
 * server-initiated messages travel on an event stream the client opens just after `initialized`, and the
 * SDK drops a message that has no open stream rather than queueing it.
 */
internal const val HTTP_NOTIFY_GRACE_MILLIS = 2_000L

/**
 * One JVM shutdown hook that runs in a fixed order: first everything that closes the server (API clients,
 * the HTTP engine), then the final steps (applying a staged update). The JVM runs separate hooks
 * concurrently and in no order, so a staged JAR swap registered as its own hook could rewrite the JAR
 * while another hook is still loading classes from it.
 */
internal object ShutdownSequence {
    private val closers = java.util.concurrent.CopyOnWriteArrayList<() -> Unit>()
    private val finalSteps = java.util.concurrent.CopyOnWriteArrayList<() -> Unit>()
    private val registered = AtomicBoolean(false)
    private val running = AtomicBoolean(false)

    /** Register the hook once. False if the JVM is already shutting down. */
    fun install(): Boolean = if (!registered.compareAndSet(false, true)) {
        true
    } else {
        runCatching { Runtime.getRuntime().addShutdownHook(Thread(::run, "defender-mcp-shutdown")) }.isSuccess
    }

    fun onClose(action: () -> Unit) {
        closers += action
    }

    /** Add a final step; false when shutdown has already begun (the step will not run). */
    fun atEnd(action: () -> Unit): Boolean {
        if (running.get()) return false
        finalSteps += action
        return true
    }

    /** Run every closer, then every final step; each failure is contained. */
    internal fun run() {
        if (!running.compareAndSet(false, true)) return
        closers.forEach { runCatching { it() } }
        finalSteps.forEach { runCatching { it() } }
    }

    internal fun resetForTests() {
        closers.clear()
        finalSteps.clear()
        running.set(false)
    }
}

/** Guards [autoInstall] so a release is downloaded and installed at most once per process. */
private val installAttempted = AtomicBoolean(false)

internal fun runServer(transport: Transport, host: String, port: Int, config: Config) {
    // Leftovers from an interrupted self-update (".new" staging files, ".bak") would accumulate beside the
    // JAR; sweep them first. The running lock tells a sibling server applying an update at exit that this
    // JAR is in use, so it is never rewritten underneath a live process.
    UpdateInstaller.runningJar()?.let { jar ->
        if (!UpdateInstaller.holdRunningLock(jar)) {
            System.err.println("[defender-mcp] Could not mark ${jar.name} as in use; an update applied by another server as it exits may break this one.")
        }
        val removed = UpdateInstaller.cleanupStaleArtifacts(jar)
        if (removed.isNotEmpty()) System.err.println("[defender-mcp] Removed stale update files: ${removed.joinToString(", ")}")
    }
    val runtime = DefenderRuntime(config)
    ShutdownSequence.install()
    ShutdownSequence.onClose { runtime.close() }
    System.err.println("[defender-mcp] ${runtime.summary()}")
    when (transport) {
        Transport.STDIO -> {
            // stdout carries JSON-RPC: keep the real stream for the transport and send stray prints to stderr.
            val protocolOut: PrintStream = System.out
            System.setOut(System.err)
            runStdio(runtime, protocolOut)
        }
        Transport.HTTP -> {
            val http = buildHttpRuntime(runtime, host, port)
            // Stop the engine before any staged update rewrites the JAR it loads classes from.
            ShutdownSequence.onClose { runCatching { http.engine.stop(500, 2_000) } }
            try {
                http.engine.start(wait = true)
            } finally {
                http.shutdown()
            }
        }
    }
}

/** Start the GitHub update check concurrently with startup, or return null when it is disabled. */
internal fun CoroutineScope.startUpdateCheck(config: Config): Deferred<UpdateChecker.Result>? =
    if (config.updateCheckDisabled) {
        System.err.println("[defender-mcp] Update check disabled via ${Config.ENV_DISABLE_UPDATE_CHECK} / --no-update-check.")
        UpdateStatus.markCheckDisabled()
        null
    } else {
        UpdateStatus.markCheckStarted()
        async(Dispatchers.IO) { UpdateChecker.check() }
    }

/**
 * Record [check]'s result in [UpdateStatus] as soon as it finishes, so `defender_server_info` is right
 * even when no session ever initializes.
 */
internal fun CoroutineScope.trackUpdateStatus(config: Config, check: Deferred<UpdateChecker.Result>?) {
    if (config.autoUpdateDisabled) UpdateStatus.markAutoInstallDisabled()
    if (check == null) return
    launch {
        runCatching { check.await() }
            .onSuccess(UpdateStatus::recordCheck)
            .onFailure { UpdateStatus.markCheckFailed() }
    }
}

/**
 * Install the release as soon as the check finishes (that needs no client), and tell [session] about it
 * once the session is initialized.
 *
 * The SDK starts reading the transport inside `createSession`, so a fast client may already have
 * initialized before any hook could be registered. The hook is therefore backed by a direct look at the
 * session's client capabilities, which are set by `initialize`: either path completes [initialized].
 */
internal fun CoroutineScope.notifyWhenInitialized(
    server: Server,
    session: ServerSession,
    updateCheck: Deferred<UpdateChecker.Result>?,
    config: Config,
) {
    if (updateCheck == null) return
    val initialized = CompletableDeferred<Unit>()
    session.onInitialized { initialized.complete(Unit) }
    if (session.clientCapabilities != null) initialized.complete(Unit)
    launch {
        val result = runCatching { updateCheck.await() }.getOrNull() ?: return@launch
        if (result.updateAvailable) System.err.println("[defender-mcp] ${result.message()}")
        val outcome = if (result.updateAvailable) autoInstall(config, result) else null
        initialized.await()
        server.notifyUpdateAvailable(session, result)
        if (outcome != null) server.notifyUpdateInstalled(session, outcome)
    }
}

/**
 * Download, verify and install [result]'s release, unless automatic installation is off. Returns null
 * when nothing was attempted. On Windows the running JAR cannot be replaced, so the verified release is
 * staged and swapped in as the JVM exits.
 */
private suspend fun autoInstall(config: Config, result: UpdateChecker.Result): UpdateInstaller.Outcome? {
    if (!installAttempted.compareAndSet(false, true)) return null
    if (config.autoUpdateDisabled) {
        System.err.println("[defender-mcp] Automatic installation is disabled (${Config.ENV_DISABLE_AUTO_UPDATE} / --no-auto-update); update it manually.")
        UpdateStatus.markAutoInstallDisabled()
        return null
    }
    val outcome = UpdateInstaller.install(result)
    UpdateStatus.recordInstall(outcome)
    when (outcome) {
        is UpdateInstaller.Outcome.Installed -> System.err.println("[defender-mcp] Installed ${outcome.version}; restart to run it.")
        is UpdateInstaller.Outcome.Staged -> {
            System.err.println("[defender-mcp] Staged ${outcome.version}; it will be applied as this server exits.")
            val staged = File(outcome.stagedPath)
            val target = UpdateInstaller.runningJar()
            if (target != null) {
                // The stage must survive until this process exits, while siblings started meanwhile sweep old stages.
                val keepAlive = UpdateInstaller.keepStagedFresh(staged) {
                    UpdateStatus.markStagedLost()
                    System.err.println(
                        "[defender-mcp] Staged ${outcome.version} was removed from disk and will NOT be applied as this server exits.",
                    )
                }
                // Applied after the server has closed (ShutdownSequence), never alongside other shutdown work.
                val scheduled = ShutdownSequence.install() && ShutdownSequence.atEnd {
                    // First: on Windows the keep-alive holds the stage open, which would block the swap.
                    runCatching { keepAlive.close() }
                    runCatching { UpdateInstaller.installStagedAtShutdown(staged, target, outcome.sha256, outcome.targetSha256) }
                }
                if (scheduled) {
                    UpdateStatus.markStagedAppliesOnExit()
                } else {
                    runCatching { keepAlive.close() }
                    System.err.println("[defender-mcp] Shutting down already; ${outcome.version} remains staged at ${outcome.stagedPath}.")
                }
            }
        }
        is UpdateInstaller.Outcome.Failed -> System.err.println("[defender-mcp] Automatic update did not complete: ${outcome.reason}")
        UpdateInstaller.Outcome.Skipped -> Unit
    }
    return outcome
}

/**
 * Serve one session over [input]/[protocolOut] until the peer closes the stream. Blocks. [startCheck]
 * starts the update check; a parameter so tests never call GitHub.
 */
internal fun runStdio(
    runtime: DefenderRuntime,
    protocolOut: PrintStream,
    input: InputStream = System.`in`,
    startCheck: CoroutineScope.(Config) -> Deferred<UpdateChecker.Result>? = { startUpdateCheck(it) },
) = runBlocking {
    System.err.println("[defender-mcp] Serving over stdio (${describeTenants(runtime.config)}).")
    val checkScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    val updateCheck = checkScope.startCheck(runtime.config).also { checkScope.trackUpdateStatus(runtime.config, it) }
    val transport = StdioServerTransport(input = input.asSource().buffered(), output = protocolOut.asSink().buffered())
    val done = Job()
    transport.onClose { done.complete() }
    try {
        val server = buildServer(runtime)
        val session = server.createSession(transport)
        checkScope.notifyWhenInitialized(server, session, updateCheck, runtime.config)
        done.join()
    } finally {
        updateCheck?.cancel()
        checkScope.cancel()
        runtime.close()
    }
}

/** The `--http` engine and what it needs torn down; returned unstarted so tests can drive it. */
internal class HttpRuntime(
    val engine: EmbeddedServer<*, *>,
    val sessions: ServerGovernor,
    private val scope: CoroutineScope,
    private val runtime: DefenderRuntime,
    private val updateCheck: Deferred<UpdateChecker.Result>? = null,
) {
    fun shutdown() {
        updateCheck?.cancel()
        scope.cancel()
        runtime.close()
    }
}

internal fun buildHttpRuntime(
    runtime: DefenderRuntime,
    host: String,
    port: Int,
    maxLiveSessions: Int = HTTP_MAX_LIVE_SESSIONS,
    startCheck: CoroutineScope.(Config) -> Deferred<UpdateChecker.Result>? = { startUpdateCheck(it) },
    notifyGraceMillis: Long = HTTP_NOTIFY_GRACE_MILLIS,
): HttpRuntime {
    val config = runtime.config
    System.err.println("[defender-mcp] Serving over HTTP on $host:$port ($STREAMABLE_HTTP_PATH, legacy SSE $LEGACY_SSE_PATH).")
    if (config.httpAuthToken == null) {
        System.err.println("[defender-mcp] WARNING: no ${Config.ENV_MCP_AUTH_TOKEN}; any local process can call this server.")
    }
    val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    val updateCheck = scope.startCheck(config).also { scope.trackUpdateStatus(config, it) }
    val governor = ServerGovernor(maxLiveSessions, scope)
    val engine = embeddedServer(CIO, host = host, port = port) {
        installTransportSecurity(
            HttpSecurity(bindHost = host, bindPort = port, token = config.httpAuthToken, allowedOrigins = config.httpAllowedOrigins),
        )
        val newServer = {
            governor.admit(buildServer(runtime)).also { server ->
                if (updateCheck != null) {
                    server.attachUpdateNotifier(scope) { session ->
                        val result = runCatching { updateCheck.await() }.getOrNull()
                        if (result != null) {
                            delay(notifyGraceMillis) // see HTTP_NOTIFY_GRACE_MILLIS
                            server.notifyUpdateAvailable(session, result)
                            if (result.updateAvailable) {
                                val outcome = autoInstall(config, result)
                                if (outcome != null) server.notifyUpdateInstalled(session, outcome)
                            }
                        }
                    }
                }
            }
        }
        // Host/Origin checks are done by installTransportSecurity, which also understands allow-listed
        // origins; the SDK's own localhost-only DNS-rebinding guard would contradict it.
        mcpStreamableHttp(path = STREAMABLE_HTTP_PATH, enableDnsRebindingProtection = false) { newServer() }
        routing { legacySseTransport(LEGACY_SSE_PATH, newServer = newServer) }
    }
    return HttpRuntime(engine, governor, scope, runtime, updateCheck)
}
