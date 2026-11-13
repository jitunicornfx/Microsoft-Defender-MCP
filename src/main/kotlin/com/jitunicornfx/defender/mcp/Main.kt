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
import kotlinx.coroutines.CoroutineScope
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
import java.io.InputStream
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

internal fun runServer(transport: Transport, host: String, port: Int, config: Config) {
    val runtime = DefenderRuntime(config)
    Runtime.getRuntime().addShutdownHook(Thread { runCatching { runtime.close() } })
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
            try {
                http.engine.start(wait = true)
            } finally {
                http.shutdown()
            }
        }
    }
}

/** Serve one session over [input]/[protocolOut] until the peer closes the stream. Blocks. */
internal fun runStdio(runtime: DefenderRuntime, protocolOut: PrintStream, input: InputStream = System.`in`) = runBlocking {
    System.err.println("[defender-mcp] Serving over stdio (${describeTenants(runtime.config)}).")
    val transport = StdioServerTransport(input = input.asSource().buffered(), output = protocolOut.asSink().buffered())
    val done = Job()
    transport.onClose { done.complete() }
    try {
        buildServer(runtime).createSession(transport)
        done.join()
    } finally {
        runtime.close()
    }
}

/** The `--http` engine and what it needs torn down; returned unstarted so tests can drive it. */
internal class HttpRuntime(
    val engine: EmbeddedServer<*, *>,
    val sessions: ServerGovernor,
    private val scope: CoroutineScope,
    private val runtime: DefenderRuntime,
) {
    fun shutdown() {
        scope.cancel()
        runtime.close()
    }
}

internal fun buildHttpRuntime(
    runtime: DefenderRuntime,
    host: String,
    port: Int,
    maxLiveSessions: Int = HTTP_MAX_LIVE_SESSIONS,
): HttpRuntime {
    val config = runtime.config
    System.err.println("[defender-mcp] Serving over HTTP on $host:$port ($STREAMABLE_HTTP_PATH, legacy SSE $LEGACY_SSE_PATH).")
    if (config.httpAuthToken == null) {
        System.err.println("[defender-mcp] WARNING: no ${Config.ENV_MCP_AUTH_TOKEN}; any local process can call this server.")
    }
    val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    val governor = ServerGovernor(maxLiveSessions, scope)
    val engine = embeddedServer(CIO, host = host, port = port) {
        installTransportSecurity(
            HttpSecurity(bindHost = host, bindPort = port, token = config.httpAuthToken, allowedOrigins = config.httpAllowedOrigins),
        )
        val newServer = { governor.admit(buildServer(runtime)) }
        // Host/Origin checks are done by installTransportSecurity, which also understands allow-listed
        // origins; the SDK's own localhost-only DNS-rebinding guard would contradict it.
        mcpStreamableHttp(path = STREAMABLE_HTTP_PATH, enableDnsRebindingProtection = false) { newServer() }
        routing { legacySseTransport(LEGACY_SSE_PATH, newServer = newServer) }
    }
    return HttpRuntime(engine, governor, scope, runtime)
}
