package com.jitunicornfx.defender.mcp

import com.jitunicornfx.defender.mcp.testutil.FakeDefender
import com.jitunicornfx.defender.mcp.testutil.InMemoryTransport
import com.jitunicornfx.defender.mcp.testutil.testConfig
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldContainExactly
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.HttpStatusCode
import io.modelcontextprotocol.kotlin.sdk.client.Client
import io.modelcontextprotocol.kotlin.sdk.types.Implementation
import io.modelcontextprotocol.kotlin.sdk.types.LoggingMessageNotification
import io.modelcontextprotocol.kotlin.sdk.types.Method
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import java.io.File
import java.security.MessageDigest
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream
import kotlin.io.path.createTempDirectory

/**
 * Regression tests for the three confirmed review findings on the auto-updater:
 *  1. the release asset (name and manifest version) must match the tag, and identical bytes are never re-fetched;
 *  2. a staged swap runs only after every closer, in one ordered shutdown sequence;
 *  3. stdio notifies even when the client initialized before the hook could be registered.
 */
class UpdateHardeningSpec : FunSpec({
    val digest = "sha256:" + "a".repeat(64)
    fun asset(name: String) =
        """{"name":"$name","browser_download_url":"https://github.com/jitunicornfx/Microsoft-Defender-MCP/releases/download/v0.2.0/$name","digest":"$digest","size":100}"""
    fun release(tag: String, vararg assets: String) = """{"tag_name":"$tag","assets":[${assets.joinToString(",")}]}"""

    fun jar(file: File, version: String?): File {
        ZipOutputStream(file.outputStream().buffered()).use { zip ->
            if (version != null) {
                zip.putNextEntry(ZipEntry("META-INF/MANIFEST.MF"))
                zip.write("Manifest-Version: 1.0\r\nImplementation-Version: $version\r\n\r\n".toByteArray())
                zip.closeEntry()
            }
            zip.putNextEntry(ZipEntry("com/jitunicornfx/defender/mcp/MainKt.class"))
            zip.write(byteArrayOf(1, 2, 3))
            zip.closeEntry()
        }
        return file
    }
    fun sha(file: File) = MessageDigest.getInstance("SHA-256").digest(file.readBytes()).joinToString("") { "%02x".format(it) }

    context("1. the asset is tied to the release version") {
        test("expectedAssetName strips a v prefix") {
            UpdateChecker.expectedAssetName("v0.2.0") shouldBe "microsoft-defender-mcp-0.2.0-all.jar"
            UpdateChecker.expectedAssetName("0.2.0") shouldBe "microsoft-defender-mcp-0.2.0-all.jar"
        }

        test("an -all.jar built for another version is not offered for the tag") {
            val stale = release("v0.2.0", asset("microsoft-defender-mcp-0.1.0-all.jar"))
            UpdateChecker.evaluate(stale, "0.1.0").asset.shouldBeNull()
            UpdateChecker.evaluate(stale, "0.1.0").updateAvailable shouldBe true
        }

        test("the asset named for the tag is chosen even when listed after others") {
            val body = release("v0.2.0", asset("microsoft-defender-mcp-0.1.0-all.jar"), asset("other-all.jar"), asset("microsoft-defender-mcp-0.2.0-all.jar"))
            UpdateChecker.evaluate(body, "0.1.0").asset.shouldNotBeNull().name shouldBe "microsoft-defender-mcp-0.2.0-all.jar"
        }

        test("looksLikeServerJar requires the manifest version to equal the expected one") {
            val dir = createTempDirectory("hardening").toFile()
            try {
                val right = jar(File(dir, "right.jar"), "0.2.0")
                val wrong = jar(File(dir, "wrong.jar"), "0.1.0")
                val none = jar(File(dir, "none.jar"), null)
                UpdateInstaller.looksLikeServerJar(right, "0.2.0") shouldBe true
                UpdateInstaller.looksLikeServerJar(wrong, "0.2.0") shouldBe false
                UpdateInstaller.looksLikeServerJar(none, "0.2.0") shouldBe false
                UpdateInstaller.looksLikeServerJar(none) shouldBe true
                ZipFile(right).use { UpdateInstaller.manifestVersion(it) shouldBe "0.2.0" }
                ZipFile(none).use { UpdateInstaller.manifestVersion(it).shouldBeNull() }
            } finally {
                dir.deleteRecursively()
            }
        }

        test("a release whose bytes equal the running JAR is skipped before any download") {
            val dir = createTempDirectory("hardening").toFile()
            try {
                val running = jar(File(dir, "server.jar"), "0.1.0")
                val sameBytes = UpdateChecker.ReleaseAsset(
                    "microsoft-defender-mcp-0.2.0-all.jar",
                    "https://github.com/jitunicornfx/Microsoft-Defender-MCP/releases/download/v0.2.0/microsoft-defender-mcp-0.2.0-all.jar",
                    sha(running),
                    running.length(),
                )
                val engine = MockEngine { respond("never", HttpStatusCode.OK) }
                val outcome = UpdateInstaller.install(UpdateChecker.Result(true, "0.1.0", "0.2.0", asset = sameBytes), engine, running)
                outcome shouldBe UpdateInstaller.Outcome.Skipped
                engine.requestHistory.size shouldBe 0
            } finally {
                UpdateInstaller.releaseRunningLock()
                dir.deleteRecursively()
            }
        }

        test("a downloaded JAR reporting the wrong version is refused") {
            val dir = createTempDirectory("hardening").toFile()
            try {
                val running = jar(File(dir, "server.jar"), "0.1.0")
                val wrong = jar(File(dir, "download.jar"), "0.1.5")
                val bytes = wrong.readBytes()
                val asset = UpdateChecker.ReleaseAsset(
                    "microsoft-defender-mcp-0.2.0-all.jar",
                    "https://github.com/jitunicornfx/Microsoft-Defender-MCP/releases/download/v0.2.0/microsoft-defender-mcp-0.2.0-all.jar",
                    sha(wrong),
                    bytes.size.toLong(),
                )
                val engine = MockEngine { respond(bytes, HttpStatusCode.OK) }
                val outcome = UpdateInstaller.install(UpdateChecker.Result(true, "0.1.0", "0.2.0", asset = asset), engine, running)
                outcome.shouldBeInstanceOf<UpdateInstaller.Outcome.Failed>().reason shouldBe
                    "downloaded 0.2.0 is not a valid server JAR for that version — refusing to install"
                sha(running) shouldBe sha(jar(File(dir, "expected.jar"), "0.1.0"))
            } finally {
                UpdateInstaller.releaseRunningLock()
                dir.deleteRecursively()
            }
        }
    }

    context("2. ordered shutdown") {
        afterEach { ShutdownSequence.resetForTests() }

        test("every closer runs before any final step, whatever order they were added in") {
            val order = mutableListOf<String>()
            ShutdownSequence.atEnd { order += "swap" } shouldBe true
            ShutdownSequence.onClose { order += "close-runtime" }
            ShutdownSequence.onClose { error("a failing closer must not stop the rest") }
            ShutdownSequence.onClose { order += "stop-engine" }
            ShutdownSequence.run()
            order shouldContainExactly listOf("close-runtime", "stop-engine", "swap")
        }

        test("the sequence runs once, and final steps added after it started are refused") {
            var runs = 0
            ShutdownSequence.onClose { runs++ }
            ShutdownSequence.run()
            ShutdownSequence.run()
            runs shouldBe 1
            ShutdownSequence.atEnd { } shouldBe false
        }

        test("install registers the JVM hook once and reports success") {
            ShutdownSequence.install() shouldBe true
            ShutdownSequence.install() shouldBe true
        }
    }

    context("3. stdio notification without the onInitialized race") {
        test("a session that initialized before the hook was attached still gets the update notice") {
            val config = testConfig()
            DefenderRuntime(config, client = FakeDefender().client(config)).use { runtime ->
                val server = buildServer(runtime)
                val (clientTransport, serverTransport) = InMemoryTransport.createLinkedPair()
                val client = Client(Implementation("t", "1"))
                val notice = CompletableDeferred<LoggingMessageNotification>()
                client.setNotificationHandler<LoggingMessageNotification>(Method.Defined.NotificationsMessage) {
                    notice.complete(it)
                    CompletableDeferred(Unit)
                }
                var session: io.modelcontextprotocol.kotlin.sdk.server.ServerSession? = null
                coroutineScope {
                    launch { client.connect(clientTransport) }
                    launch { session = server.createSession(serverTransport) }
                }
                // The client has fully initialized; only now is the hook attached (the race the fix closes).
                session!!.clientCapabilities.shouldNotBeNull()
                val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
                try {
                    val result = UpdateChecker.Result(updateAvailable = true, currentVersion = "0.1.0", latestVersion = "0.2.0")
                    // autoUpdateDisabled (testConfig) means no install is attempted, only the notice.
                    scope.notifyWhenInitialized(server, session!!, CompletableDeferred(result), config)
                    val received = withTimeout(5_000) { notice.await() }
                    received.params.logger shouldBe UPDATE_LOGGER_NAME
                } finally {
                    scope.cancel()
                }
            }
        }
    }
})
