package com.jitunicornfx.defender.mcp

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.booleans.shouldBeFalse
import io.kotest.matchers.booleans.shouldBeTrue
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldContainExactly
import io.kotest.matchers.collections.shouldContainExactlyInAnyOrder
import io.kotest.matchers.ints.shouldBeLessThanOrEqual
import io.kotest.matchers.longs.shouldBeLessThan
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldEndWith
import io.kotest.matchers.string.shouldNotContain
import io.kotest.matchers.string.shouldStartWith
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.writeFully
import io.ktor.utils.io.writer
import kotlinx.coroutines.DelicateCoroutinesApi
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.runBlocking
import java.io.File
import java.io.RandomAccessFile
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import kotlin.io.path.createTempDirectory

/**
 * A response body produced lazily, 64 KiB at a time, counting how much was ever pulled, so a
 * streaming download can be told apart from one that buffers everything before its size cap runs.
 * Private to this spec (ported from the InsightVM project's MeteredBody) to avoid clashing helpers.
 */
private class InstallerMeteredBody(val totalBytes: Long) {
    val produced = AtomicLong()

    fun wasStreamed(kept: Long): Boolean = produced.get() < kept + READ_AHEAD_ALLOWANCE

    @OptIn(DelicateCoroutinesApi::class)
    fun channel(): ByteReadChannel = GlobalScope.writer(Dispatchers.IO) {
        val chunk = ByteArray(64 * 1024) { 'A'.code.toByte() }
        var remaining = totalBytes
        while (remaining > 0) {
            val next = if (remaining >= chunk.size) chunk else chunk.copyOf(remaining.toInt())
            channel.writeFully(next)
            channel.flush()
            produced.addAndGet(next.size.toLong())
            remaining -= next.size
        }
    }.channel

    companion object {
        const val READ_AHEAD_ALLOWANCE = 8L * 1024 * 1024
    }
}

private val IS_WINDOWS = System.getProperty("os.name").orEmpty().startsWith("Windows", ignoreCase = true)

/**
 * The component that installs code. The security-critical assertions prove that a *bad* download is
 * refused: a wrong digest, a non-GitHub host, a wrong artifact, or a size that disagrees with what the
 * release advertised must never reach the installed JAR. Every test works in its own temp directory
 * and talks only to a MockEngine.
 */
class UpdateInstallerSpec : FunSpec({

    lateinit var tempDir: File

    beforeTest { tempDir = createTempDirectory("installer-spec").toFile() }

    afterTest {
        // A test may have taken this process's running marker inside tempDir; Windows will not
        // delete a file that is still open.
        UpdateInstaller.releaseRunningLock()
        tempDir.deleteRecursively()
    }

    // Release JARs carry Implementation-Version = their version; the installer refuses one that does not match the tag.
    fun serverJar(file: File, marker: String = "v1", version: String? = "9.9.9"): File {
        ZipOutputStream(file.outputStream().buffered()).use { zip ->
            if (version != null) {
                zip.putNextEntry(ZipEntry("META-INF/MANIFEST.MF"))
                zip.write("Manifest-Version: 1.0\r\nImplementation-Version: $version\r\n\r\n".toByteArray())
                zip.closeEntry()
            }
            zip.putNextEntry(ZipEntry("com/jitunicornfx/defender/mcp/MainKt.class"))
            zip.write(marker.toByteArray())
            zip.closeEntry()
        }
        return file
    }

    fun sha256(file: File): String =
        MessageDigest.getInstance("SHA-256").digest(file.readBytes()).joinToString("") { "%02x".format(it) }

    fun assetFor(
        file: File,
        url: String = "https://github.com/jitunicornfx/Microsoft-Defender-MCP/releases/download/v9.9.9/microsoft-defender-mcp-9.9.9-all.jar",
    ) = UpdateChecker.ReleaseAsset(
        name = "microsoft-defender-mcp-9.9.9-all.jar",
        downloadUrl = url,
        sha256 = sha256(file),
        sizeBytes = file.length(),
    )

    fun result(asset: UpdateChecker.ReleaseAsset?) = UpdateChecker.Result(true, "0.1.0", "9.9.9", asset = asset)

    fun engineServing(bytes: ByteArray) = MockEngine {
        respond(bytes, HttpStatusCode.OK, headersOf(HttpHeaders.ContentLength, bytes.size.toString()))
    }

    fun stagedFiles(): List<String> =
        tempDir.listFiles()!!.filter { it.name.endsWith(UpdateInstaller.STAGED_SUFFIX) }.map { it.name }

    fun awaitTrue(timeoutMillis: Long = 5_000, condition: () -> Boolean): Boolean {
        val deadline = System.nanoTime() + timeoutMillis * 1_000_000
        while (System.nanoTime() < deadline) {
            if (condition()) return true
            Thread.sleep(10)
        }
        return condition()
    }

    // ---------------------------------------------------------------------
    // Outcome variants
    // ---------------------------------------------------------------------

    context("Outcome variants") {
        test("each variant carries its fields and has value semantics") {
            val installed = UpdateInstaller.Outcome.Installed("1.2.3", "/opt/x.jar")
            installed shouldBe UpdateInstaller.Outcome.Installed("1.2.3", "/opt/x.jar")
            installed.version shouldBe "1.2.3"
            installed.path shouldBe "/opt/x.jar"
            installed.toString() shouldContain "1.2.3"

            val staged = UpdateInstaller.Outcome.Staged("1.2.3", "/opt/x.jar.1.new", "aa", "bb")
            staged.copy(targetSha256 = "cc") shouldNotBe staged
            staged.stagedPath shouldBe "/opt/x.jar.1.new"
            staged.sha256 shouldBe "aa"
            staged.targetSha256 shouldBe "bb"

            UpdateInstaller.Outcome.Failed("why").reason shouldBe "why"
            UpdateInstaller.Outcome.Skipped.toString() shouldBe "Skipped"
            UpdateInstaller.LockResult.Unavailable("r").reason shouldBe "r"
        }
    }

    // ---------------------------------------------------------------------
    // Download + verification
    // ---------------------------------------------------------------------

    context("download verification") {
        test("a good download is verified and installed over the target") {
            val source = serverJar(File(tempDir, "source.jar"), marker = "NEW")
            val target = serverJar(File(tempDir, "installed.jar"), marker = "OLD")
            val engine = engineServing(source.readBytes())

            val outcome = UpdateInstaller.install(result(assetFor(source)), engine, target)

            outcome shouldBe UpdateInstaller.Outcome.Installed("9.9.9", target.absolutePath)
            sha256(target) shouldBe sha256(source)
            stagedFiles().shouldBeEmpty()
            val request = engine.requestHistory.single()
            request.headers[HttpHeaders.Accept] shouldBe "application/octet-stream"
            request.headers[HttpHeaders.UserAgent] shouldBe "$SERVER_NAME/$SERVER_VERSION"
            request.headers[HttpHeaders.Authorization].shouldBeNull()
        }

        test("the published digest is compared case-insensitively") {
            val source = serverJar(File(tempDir, "source.jar"), marker = "NEW")
            val target = serverJar(File(tempDir, "installed.jar"), marker = "OLD")
            val asset = assetFor(source).let { it.copy(sha256 = it.sha256.uppercase()) }

            UpdateInstaller.install(result(asset), engineServing(source.readBytes()), target)
                .shouldBeInstanceOf<UpdateInstaller.Outcome.Installed>()
            sha256(target) shouldBe sha256(source)
        }

        test("a digest mismatch refuses to install and leaves the original intact") {
            val source = serverJar(File(tempDir, "source.jar"), marker = "NEW")
            val target = serverJar(File(tempDir, "installed.jar"), marker = "OLD")
            val originalDigest = sha256(target)
            val asset = assetFor(source).copy(sha256 = "0".repeat(64))

            val outcome = UpdateInstaller.install(result(asset), engineServing(source.readBytes()), target)

            outcome.shouldBeInstanceOf<UpdateInstaller.Outcome.Failed>()
            outcome.reason shouldBe "SHA-256 mismatch for 9.9.9 — refusing to install"
            sha256(target) shouldBe originalDigest
            stagedFiles().shouldBeEmpty()
        }

        test("bytes that are not a server JAR are refused even with a matching digest") {
            // Correct hash, wrong artifact: a ZIP that carries another server's entry point.
            val impostor = File(tempDir, "impostor.jar")
            ZipOutputStream(impostor.outputStream()).use { zip ->
                zip.putNextEntry(ZipEntry("com/jitunicornfx/insightvm/mcp/MainKt.class"))
                zip.write("x".toByteArray())
                zip.closeEntry()
            }
            val target = serverJar(File(tempDir, "installed.jar"), marker = "OLD")
            val originalDigest = sha256(target)

            val outcome = UpdateInstaller.install(result(assetFor(impostor)), engineServing(impostor.readBytes()), target)

            outcome.shouldBeInstanceOf<UpdateInstaller.Outcome.Failed>()
            outcome.reason shouldContain "not a valid server JAR"
            sha256(target) shouldBe originalDigest
            stagedFiles().shouldBeEmpty()
        }

        test("a declared Content-Length larger than advertised is refused before any body is read") {
            val source = serverJar(File(tempDir, "source.jar"))
            val target = serverJar(File(tempDir, "installed.jar"), marker = "OLD")
            val originalDigest = sha256(target)
            val asset = assetFor(source).copy(sizeBytes = 10)

            val outcome = UpdateInstaller.install(result(asset), engineServing(ByteArray(500_000) { 'A'.code.toByte() }), target)

            outcome.shouldBeInstanceOf<UpdateInstaller.Outcome.Failed>()
            outcome.reason shouldBe "download of 9.9.9 failed or exceeded its advertised size"
            sha256(target) shouldBe originalDigest
            stagedFiles().shouldBeEmpty()
        }

        test("an undeclared body far larger than advertised is abandoned as a stream, not buffered") {
            val source = serverJar(File(tempDir, "source.jar"))
            val body = InstallerMeteredBody(totalBytes = 64L * 1024 * 1024)
            val engine = MockEngine { respond(body.channel(), HttpStatusCode.OK) }

            val digest = UpdateInstaller.downloadTo(assetFor(source).copy(sizeBytes = 1000), File(tempDir, "staged.new"), engine)

            digest.shouldBeNull()
            body.wasStreamed(kept = 1000).shouldBeTrue()
        }

        test("a truncated download is refused (size mismatch)") {
            val source = serverJar(File(tempDir, "source.jar"))
            val target = serverJar(File(tempDir, "installed.jar"), marker = "OLD")
            val originalDigest = sha256(target)
            val truncated = source.readBytes().copyOfRange(0, source.readBytes().size / 2)

            UpdateInstaller.install(result(assetFor(source)), engineServing(truncated), target)
                .shouldBeInstanceOf<UpdateInstaller.Outcome.Failed>()
            sha256(target) shouldBe originalDigest
        }

        test("downloadTo returns the digest of exactly the bytes written") {
            val source = serverJar(File(tempDir, "source.jar"))
            val dest = File(tempDir, "dl.bin")
            // No Content-Length header: the streamed size check alone decides.
            val engine = MockEngine { respond(ByteReadChannel(source.readBytes()), HttpStatusCode.OK) }

            UpdateInstaller.downloadTo(assetFor(source), dest, engine) shouldBe sha256(source)
            dest.readBytes().contentEquals(source.readBytes()).shouldBeTrue()
        }

        test("a download is never fetched from a non-GitHub host") {
            val source = serverJar(File(tempDir, "source.jar"))
            val target = serverJar(File(tempDir, "installed.jar"), marker = "OLD")
            val engine = engineServing(source.readBytes())

            val outcome = UpdateInstaller.install(result(assetFor(source, url = "https://attacker.example/evil-all.jar")), engine, target)

            outcome.shouldBeInstanceOf<UpdateInstaller.Outcome.Failed>()
            engine.requestHistory.size shouldBe 0
        }

        test("plain HTTP on an allowed host is refused without a request") {
            val source = serverJar(File(tempDir, "source.jar"))
            val engine = engineServing(source.readBytes())
            val asset = assetFor(source, url = "http://github.com/x/y-all.jar")

            UpdateInstaller.downloadTo(asset, File(tempDir, "d.new"), engine).shouldBeNull()
            engine.requestHistory.size shouldBe 0
        }

        test("without an injected engine the default client is built but a disallowed URL never reaches it") {
            val source = serverJar(File(tempDir, "source.jar"))
            // engine = null exercises the OkHttp branch; the allow-list stops it before any I/O.
            UpdateInstaller.downloadTo(assetFor(source, url = "https://attacker.example/x.jar"), File(tempDir, "d.new"))
                .shouldBeNull()
            File(tempDir, "d.new").exists().shouldBeFalse()
        }

        test("a redirect to a non-GitHub host is not followed") {
            val source = serverJar(File(tempDir, "source.jar"))
            val target = serverJar(File(tempDir, "installed.jar"), marker = "OLD")
            val originalDigest = sha256(target)
            val engine = MockEngine { request ->
                if (request.url.host == "github.com") {
                    respond("", HttpStatusCode.Found, headersOf(HttpHeaders.Location, "https://attacker.example/evil.jar"))
                } else {
                    respond(source.readBytes(), HttpStatusCode.OK)
                }
            }

            UpdateInstaller.install(result(assetFor(source)), engine, target)
                .shouldBeInstanceOf<UpdateInstaller.Outcome.Failed>()
            engine.requestHistory.size shouldBe 1
            sha256(target) shouldBe originalDigest
        }

        test("a redirect to a look-alike host is not followed") {
            val source = serverJar(File(tempDir, "source.jar"))
            val engine = MockEngine {
                respond("", HttpStatusCode.MovedPermanently, headersOf(HttpHeaders.Location, "https://objects.githubusercontent.com.evil.tld/x"))
            }
            UpdateInstaller.downloadTo(assetFor(source), File(tempDir, "d.new"), engine).shouldBeNull()
            engine.requestHistory.size shouldBe 1
        }

        test("a redirect to the GitHub CDN is followed and installed") {
            val source = serverJar(File(tempDir, "source.jar"), marker = "NEW")
            val target = serverJar(File(tempDir, "installed.jar"), marker = "OLD")
            val engine = MockEngine { request ->
                if (request.url.host == "github.com") {
                    respond("", HttpStatusCode.Found, headersOf(HttpHeaders.Location, "https://objects.githubusercontent.com/release/app-all.jar"))
                } else {
                    respond(source.readBytes(), HttpStatusCode.OK)
                }
            }

            UpdateInstaller.install(result(assetFor(source)), engine, target)
                .shouldBeInstanceOf<UpdateInstaller.Outcome.Installed>()
            engine.requestHistory.map { it.url.host } shouldContainExactly listOf("github.com", "objects.githubusercontent.com")
            sha256(target) shouldBe sha256(source)
        }

        test("exactly MAX_REDIRECTS hops are followed") {
            val source = serverJar(File(tempDir, "source.jar"))
            val calls = AtomicInteger()
            val engine = MockEngine {
                if (calls.incrementAndGet() <= UpdateInstaller.MAX_REDIRECTS) {
                    respond("", HttpStatusCode.TemporaryRedirect, headersOf(HttpHeaders.Location, "https://release-assets.githubusercontent.com/n"))
                } else {
                    respond(source.readBytes(), HttpStatusCode.OK)
                }
            }
            UpdateInstaller.downloadTo(assetFor(source), File(tempDir, "d.new"), engine) shouldBe sha256(source)
            engine.requestHistory.size shouldBe UpdateInstaller.MAX_REDIRECTS + 1
        }

        test("a redirect loop is abandoned after MAX_REDIRECTS hops") {
            val source = serverJar(File(tempDir, "source.jar"))
            val target = serverJar(File(tempDir, "installed.jar"), marker = "OLD")
            val engine = MockEngine {
                respond("", HttpStatusCode.Found, headersOf(HttpHeaders.Location, "https://objects.githubusercontent.com/next"))
            }

            UpdateInstaller.install(result(assetFor(source)), engine, target)
                .shouldBeInstanceOf<UpdateInstaller.Outcome.Failed>()
            engine.requestHistory.size shouldBeLessThanOrEqual UpdateInstaller.MAX_REDIRECTS + 1
            engine.requestHistory.size shouldBe UpdateInstaller.MAX_REDIRECTS + 1
        }

        test("a redirect without a Location header aborts") {
            val source = serverJar(File(tempDir, "source.jar"))
            val target = serverJar(File(tempDir, "installed.jar"), marker = "OLD")
            val originalDigest = sha256(target)
            val engine = MockEngine { respond("", HttpStatusCode.Found) }

            UpdateInstaller.install(result(assetFor(source)), engine, target)
                .shouldBeInstanceOf<UpdateInstaller.Outcome.Failed>()
            sha256(target) shouldBe originalDigest
        }

        test("an HTTP error response installs nothing") {
            val source = serverJar(File(tempDir, "source.jar"))
            val target = serverJar(File(tempDir, "installed.jar"), marker = "OLD")
            val originalDigest = sha256(target)
            val engine = MockEngine { respond("not found", HttpStatusCode.NotFound) }

            UpdateInstaller.install(result(assetFor(source)), engine, target)
                .shouldBeInstanceOf<UpdateInstaller.Outcome.Failed>()
            sha256(target) shouldBe originalDigest
        }

        test("a non-redirect, non-success status below 200 installs nothing") {
            val source = serverJar(File(tempDir, "source.jar"))
            val engine = MockEngine { respond(source.readBytes(), HttpStatusCode(199, "Odd")) }
            UpdateInstaller.downloadTo(assetFor(source), File(tempDir, "d.new"), engine).shouldBeNull()
        }

        test("an engine that throws degrades to a null digest") {
            val source = serverJar(File(tempDir, "source.jar"))
            val engine = MockEngine { throw java.io.IOException("connection reset") }
            UpdateInstaller.downloadTo(assetFor(source), File(tempDir, "d.new"), engine).shouldBeNull()
        }
    }

    // ---------------------------------------------------------------------
    // install(): the outcomes that never get as far as a download
    // ---------------------------------------------------------------------

    context("install preconditions") {
        test("install is skipped when there is no newer version") {
            val target = serverJar(File(tempDir, "installed.jar"))
            val engine = engineServing(ByteArray(0))
            UpdateInstaller.install(UpdateChecker.Result(false, "0.1.0"), engine, target) shouldBe UpdateInstaller.Outcome.Skipped
            engine.requestHistory.size shouldBe 0
        }

        test("install fails when the release publishes no verifiable asset") {
            val target = serverJar(File(tempDir, "installed.jar"), marker = "OLD")
            UpdateInstaller.install(result(null), engineServing(ByteArray(0)), target) shouldBe
                UpdateInstaller.Outcome.Failed("release 9.9.9 publishes no verifiable .jar asset")
            // All defaults (real engine, running JAR): still decided before any client exists.
            UpdateInstaller.install(result(null)) shouldBe
                UpdateInstaller.Outcome.Failed("release 9.9.9 publishes no verifiable .jar asset")
        }

        test("install fails cleanly when not running from a jar") {
            val source = serverJar(File(tempDir, "source.jar"))
            UpdateInstaller.install(result(assetFor(source)), engineServing(source.readBytes()), targetJar = null) shouldBe
                UpdateInstaller.Outcome.Failed("not running from a .jar, so there is nothing to replace")
        }

        test("the default targetJar is the running JAR, which is null under the test runner") {
            UpdateInstaller.runningJar().shouldBeNull()
            val source = serverJar(File(tempDir, "source.jar"))
            val engine = engineServing(source.readBytes())
            UpdateInstaller.install(result(assetFor(source)), engine).shouldBeInstanceOf<UpdateInstaller.Outcome.Failed>()
                .reason shouldContain "nothing to replace"
            engine.requestHistory.size shouldBe 0
        }

        test("an install is refused when the installed JAR cannot be read to record what it replaces") {
            val source = serverJar(File(tempDir, "source.jar"))
            val target = File(tempDir, "installed.jar").apply { mkdir().shouldBeTrue() }
            val engine = engineServing(source.readBytes())

            val outcome = UpdateInstaller.install(result(assetFor(source)), engine, target)

            outcome shouldBe UpdateInstaller.Outcome.Failed("could not read installed.jar, so an update cannot be checked against it")
            engine.requestHistory.size shouldBe 0
        }

        test("an install is refused when no staging file can be created beside the JAR") {
            // 240 chars: the lock sidecar (+12) still fits the 255-char name limit, but a staging name
            // (+ "." + ~19 random digits + ".new") does not, so only createTempFile fails.
            val name = "a".repeat(236) + ".jar"
            val target = serverJar(File(tempDir, name), marker = "OLD")
            val source = serverJar(File(tempDir, "source.jar"))
            val engine = engineServing(source.readBytes())

            val outcome = UpdateInstaller.install(result(assetFor(source)), engine, target)

            outcome shouldBe UpdateInstaller.Outcome.Failed("could not create a staging file next to $name")
            engine.requestHistory.size shouldBe 0
        }

        test("an install is refused while another holder has the install lock") {
            val source = serverJar(File(tempDir, "source.jar"))
            val target = serverJar(File(tempDir, "installed.jar"), marker = "OLD")
            val originalDigest = sha256(target)

            val held = UpdateInstaller.withInstallLock(target) {
                runBlocking { UpdateInstaller.install(result(assetFor(source)), engineServing(source.readBytes()), target) }
            }

            held.shouldBeInstanceOf<UpdateInstaller.LockResult.Acquired<UpdateInstaller.Outcome>>()
            held.value shouldBe UpdateInstaller.Outcome.Failed("another process is already installing an update")
            sha256(target) shouldBe originalDigest
        }

        test("an unusable install directory is reported as such, not as another process installing") {
            val source = serverJar(File(tempDir, "source.jar"))
            val target = serverJar(File(tempDir, "installed.jar"), marker = "OLD")
            val originalDigest = sha256(target)
            File(tempDir, target.name + UpdateInstaller.LOCK_SUFFIX).mkdir().shouldBeTrue()

            val outcome = UpdateInstaller.install(result(assetFor(source)), engineServing(source.readBytes()), target)

            outcome.shouldBeInstanceOf<UpdateInstaller.Outcome.Failed>()
            outcome.reason shouldContain "cannot create"
            outcome.reason shouldNotContain "another process"
            outcome.reason shouldNotContain tempDir.absolutePath
            sha256(target) shouldBe originalDigest
        }

        test("install sweeps stale staging files before downloading, and keeps the lock sidecar") {
            val source = serverJar(File(tempDir, "source.jar"))
            val target = serverJar(File(tempDir, "installed.jar"), marker = "OLD")
            val stale = File(tempDir, "installed.jar.0000.new").apply {
                writeText("old")
                setLastModified(System.currentTimeMillis() - 2 * UpdateInstaller.STALE_ARTIFACT_AGE_MILLIS).shouldBeTrue()
            }

            UpdateInstaller.install(result(assetFor(source)), engineServing(source.readBytes()), target)
                .shouldBeInstanceOf<UpdateInstaller.Outcome.Installed>()
            stale.exists().shouldBeFalse()
            File(tempDir, target.name + UpdateInstaller.LOCK_SUFFIX).isFile.shouldBeTrue()
        }

        test("each install stages to its own file rather than a shared predictable path") {
            val source = serverJar(File(tempDir, "source.jar"))
            val target = serverJar(File(tempDir, "installed.jar"), marker = "OLD")
            val squatter = File(tempDir, "installed.jar${UpdateInstaller.STAGED_SUFFIX}").apply { writeText("someone else's file") }

            UpdateInstaller.install(result(assetFor(source)), engineServing(source.readBytes()), target)

            squatter.readText() shouldBe "someone else's file"
        }

        test("a staged install on Windows records the JAR it will replace").config(enabled = IS_WINDOWS) {
            val source = serverJar(File(tempDir, "source.jar"), marker = "NEW")
            val target = serverJar(File(tempDir, "installed.jar"), marker = "OLD")
            val originalDigest = sha256(target)

            // Hold the target open as a running JVM does; Windows then refuses to move anything over it.
            val outcome = target.inputStream().use {
                UpdateInstaller.install(result(assetFor(source)), engineServing(source.readBytes()), target)
            }

            outcome.shouldBeInstanceOf<UpdateInstaller.Outcome.Staged>()
            outcome.version shouldBe "9.9.9"
            outcome.sha256 shouldBe sha256(source)
            outcome.targetSha256 shouldBe originalDigest
            sha256(target) shouldBe originalDigest
            val staged = File(outcome.stagedPath)
            staged.parentFile.canonicalFile shouldBe tempDir.canonicalFile
            staged.name shouldStartWith "installed.jar."
            staged.name shouldEndWith UpdateInstaller.STAGED_SUFFIX
            sha256(staged) shouldBe sha256(source)

            // ...and the shutdown swap then completes it.
            UpdateInstaller.installStagedAtShutdown(staged, target, outcome.sha256, outcome.targetSha256).shouldBeTrue()
            sha256(target) shouldBe sha256(source)
            staged.exists().shouldBeFalse()
        }

        test("an atomic install keeps the installed JAR's POSIX permissions").config(enabled = !IS_WINDOWS) {
            val source = serverJar(File(tempDir, "source.jar"), marker = "NEW")
            val target = serverJar(File(tempDir, "installed.jar"), marker = "OLD")
            val shared = PosixFilePermissions.fromString("rw-r--r--")
            Files.setPosixFilePermissions(target.toPath(), shared)

            UpdateInstaller.install(result(assetFor(source)), engineServing(source.readBytes()), target)
                .shouldBeInstanceOf<UpdateInstaller.Outcome.Installed>()
            Files.getPosixFilePermissions(target.toPath()) shouldBe shared
        }
    }

    // ---------------------------------------------------------------------
    // Swap mechanics
    // ---------------------------------------------------------------------

    context("swap mechanics") {
        test("tryAtomicSwap moves the staged file over the target") {
            val staged = serverJar(File(tempDir, "staged.jar"), marker = "NEW")
            val target = serverJar(File(tempDir, "target.jar"), marker = "OLD")
            val stagedDigest = sha256(staged)

            UpdateInstaller.tryAtomicSwap(staged, target).shouldBeTrue()
            sha256(target) shouldBe stagedDigest
            staged.exists().shouldBeFalse()
        }

        test("tryAtomicSwap reports false, without throwing, when the move fails") {
            val target = serverJar(File(tempDir, "target.jar"), marker = "OLD")
            val originalDigest = sha256(target)
            UpdateInstaller.tryAtomicSwap(File(tempDir, "absent.jar"), target).shouldBeFalse()
            sha256(target) shouldBe originalDigest
        }

        test("tryAtomicSwap on Windows is refused over a JAR that is held open").config(enabled = IS_WINDOWS) {
            val staged = serverJar(File(tempDir, "staged.jar"), marker = "NEW")
            val target = serverJar(File(tempDir, "target.jar"), marker = "OLD")
            target.inputStream().use { UpdateInstaller.tryAtomicSwap(staged, target).shouldBeFalse() }
            staged.isFile.shouldBeTrue()
        }

        test("overwriteInPlace replaces contents and removes the staged file and backup") {
            val staged = serverJar(File(tempDir, "staged.jar"), marker = "NEW")
            val target = serverJar(File(tempDir, "target.jar"), marker = "OLD")
            val stagedDigest = sha256(staged)

            UpdateInstaller.overwriteInPlace(staged, target, stagedDigest).shouldBeTrue()

            sha256(target) shouldBe stagedDigest
            staged.exists().shouldBeFalse()
            File(tempDir, "target.jar${UpdateInstaller.BACKUP_SUFFIX}").exists().shouldBeFalse()
        }

        test("the backup preserves the ORIGINAL jar, so a failed verification is rolled back") {
            val staged = serverJar(File(tempDir, "staged.jar"), marker = "NEW")
            val target = serverJar(File(tempDir, "target.jar"), marker = "ORIGINAL")
            val originalDigest = sha256(target)

            UpdateInstaller.overwriteInPlace(staged, target, "0".repeat(64)).shouldBeFalse()

            sha256(target) shouldBe originalDigest
            val backup = File(tempDir, "target.jar${UpdateInstaller.BACKUP_SUFFIX}")
            backup.exists().shouldBeTrue()
            sha256(backup) shouldBe originalDigest
            staged.exists().shouldBeTrue()
        }

        test("a write that fails outright is rolled back from the backup") {
            val target = serverJar(File(tempDir, "target.jar"), marker = "ORIGINAL")
            val originalDigest = sha256(target)

            // The staged file vanished: the write fails, and the original is restored from the backup.
            UpdateInstaller.overwriteInPlace(File(tempDir, "gone.jar"), target, originalDigest).shouldBeFalse()

            sha256(target) shouldBe originalDigest
            sha256(File(tempDir, "target.jar${UpdateInstaller.BACKUP_SUFFIX}")) shouldBe originalDigest
        }

        test("on Windows a write AND restore that both fail keep the backup for manual recovery").config(enabled = IS_WINDOWS) {
            val staged = serverJar(File(tempDir, "staged.jar"), marker = "NEW")
            val target = serverJar(File(tempDir, "target.jar"), marker = "ORIGINAL")
            val originalDigest = sha256(target)
            val backup = File(tempDir, "target.jar${UpdateInstaller.BACKUP_SUFFIX}")

            // A shared byte-range lock lets the backup READ the target but refuses every write to it,
            // so both the update write and the rollback write fail.
            RandomAccessFile(target, "r").use { holder ->
                holder.channel.lock(0, Long.MAX_VALUE, true)
                UpdateInstaller.overwriteInPlace(staged, target, sha256(staged)).shouldBeFalse()
            }

            backup.isFile.shouldBeTrue()
            sha256(backup) shouldBe originalDigest
            staged.isFile.shouldBeTrue()
        }

        test("overwriteInPlace refuses to touch a target it cannot back up") {
            val staged = serverJar(File(tempDir, "staged.jar"), marker = "NEW")
            // A directory where the backup must go: the backup write fails, so nothing is overwritten.
            val target = serverJar(File(tempDir, "target.jar"), marker = "ORIGINAL")
            val originalDigest = sha256(target)
            File(tempDir, "target.jar${UpdateInstaller.BACKUP_SUFFIX}").mkdir().shouldBeTrue()

            UpdateInstaller.overwriteInPlace(staged, target, sha256(staged)).shouldBeFalse()

            sha256(target) shouldBe originalDigest
            staged.exists().shouldBeTrue()
        }

        test("matchTargetPermissions copies the target's POSIX mode onto the stage").config(enabled = !IS_WINDOWS) {
            val staged = serverJar(File(tempDir, "staged.jar"), marker = "NEW")
            val target = serverJar(File(tempDir, "target.jar"), marker = "OLD")
            Files.setPosixFilePermissions(staged.toPath(), PosixFilePermissions.fromString("rw-------"))
            val shared = PosixFilePermissions.fromString("rw-r--r--")
            Files.setPosixFilePermissions(target.toPath(), shared)

            UpdateInstaller.matchTargetPermissions(staged, target)

            Files.getPosixFilePermissions(staged.toPath()) shouldBe shared
        }

        test("matchTargetPermissions is a no-op without POSIX attributes, and never throws") {
            val staged = serverJar(File(tempDir, "staged.jar"), marker = "NEW")
            val target = serverJar(File(tempDir, "target.jar"), marker = "OLD")
            val before = staged.readBytes()

            UpdateInstaller.matchTargetPermissions(staged, target)
            // A target that does not exist: getFileStore fails, so posix support is "false".
            UpdateInstaller.matchTargetPermissions(staged, File(tempDir, "missing/none.jar"))

            staged.readBytes().contentEquals(before).shouldBeTrue()
        }

        test("looksLikeServerJar accepts the Defender entry point and rejects everything else") {
            UpdateInstaller.looksLikeServerJar(serverJar(File(tempDir, "ok.jar"))).shouldBeTrue()
            UpdateInstaller.looksLikeServerJar(File(tempDir, "text.jar").apply { writeText("nope") }).shouldBeFalse()
            UpdateInstaller.looksLikeServerJar(File(tempDir, "missing.jar")).shouldBeFalse()
            val other = File(tempDir, "other.jar")
            ZipOutputStream(other.outputStream()).use { zip ->
                zip.putNextEntry(ZipEntry("com/jitunicornfx/defender/mcp/Main.class"))
                zip.closeEntry()
            }
            UpdateInstaller.looksLikeServerJar(other).shouldBeFalse()
        }

        test("sha256Of hashes the bytes on disk and is null for an unreadable file") {
            val file = File(tempDir, "f.bin").apply { writeBytes(ByteArray(200_000) { it.toByte() }) }
            UpdateInstaller.sha256Of(file) shouldBe sha256(file)
            UpdateInstaller.sha256Of(File(tempDir, "empty.bin").apply { writeBytes(ByteArray(0)) }) shouldBe
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            UpdateInstaller.sha256Of(File(tempDir, "absent")).shouldBeNull()
            UpdateInstaller.sha256Of(tempDir).shouldBeNull()
        }
    }

    // ---------------------------------------------------------------------
    // installStagedAtShutdown
    // ---------------------------------------------------------------------

    context("installStagedAtShutdown") {
        test("installs a verified stage when nothing else is running") {
            val target = serverJar(File(tempDir, "installed.jar"), marker = "OLD")
            val staged = serverJar(File(tempDir, "installed.jar.1.new"), marker = "NEW")
            val newDigest = sha256(staged)

            // Lowercase, as UpdateChecker's digest regex guarantees: overwriteInPlace compares case-sensitively.
            UpdateInstaller.installStagedAtShutdown(staged, target, newDigest, sha256(target)).shouldBeTrue()
            sha256(target) shouldBe newDigest
            staged.exists().shouldBeFalse()
        }

        test("is a no-op when nothing is staged") {
            val target = serverJar(File(tempDir, "target.jar"))
            val originalDigest = sha256(target)
            UpdateInstaller.installStagedAtShutdown(File(tempDir, "absent.jar"), target, "0".repeat(64), originalDigest).shouldBeFalse()
            sha256(target) shouldBe originalDigest
        }

        test("refuses a staged file that is not a server JAR, and discards it") {
            val staged = File(tempDir, "staged.jar").apply { writeText("not a jar at all") }
            val target = serverJar(File(tempDir, "target.jar"), marker = "OLD")
            val originalDigest = sha256(target)

            UpdateInstaller.installStagedAtShutdown(staged, target, sha256(staged), originalDigest).shouldBeFalse()
            sha256(target) shouldBe originalDigest
            staged.exists().shouldBeFalse()
        }

        test("refuses a staged file altered after verification, and discards it") {
            val staged = serverJar(File(tempDir, "staged.jar"), marker = "VERIFIED")
            val verifiedDigest = sha256(staged)
            val target = serverJar(File(tempDir, "target.jar"), marker = "ORIGINAL")
            val originalDigest = sha256(target)
            serverJar(staged, marker = "TAMPERED")
            sha256(staged) shouldNotBe verifiedDigest

            UpdateInstaller.installStagedAtShutdown(staged, target, verifiedDigest, originalDigest).shouldBeFalse()
            sha256(target) shouldBe originalDigest
            staged.exists().shouldBeFalse()
        }

        test("on Windows refuses a stage whose bytes cannot be read back").config(enabled = IS_WINDOWS) {
            val target = serverJar(File(tempDir, "installed.jar"), marker = "OLD")
            val originalDigest = sha256(target)
            val staged = serverJar(File(tempDir, "installed.jar.1.new"), marker = "NEW")
            val newDigest = sha256(staged)

            // An exclusive byte-range lock makes every other handle's read fail: sha256Of is null.
            RandomAccessFile(staged, "rw").use { holder ->
                holder.channel.lock()
                UpdateInstaller.installStagedAtShutdown(staged, target, newDigest, originalDigest).shouldBeFalse()
            }
            sha256(target) shouldBe originalDigest
        }

        test("discards a stage when the installed JAR changed after it was staged") {
            val target = serverJar(File(tempDir, "installed.jar"), marker = "0.2.1")
            val whenStaged = sha256(target)
            val staged = serverJar(File(tempDir, "installed.jar.1.new"), marker = "0.2.2")
            serverJar(File(tempDir, "newer.jar"), marker = "0.2.3").copyTo(target, overwrite = true)
            val replacement = sha256(target)

            UpdateInstaller.installStagedAtShutdown(staged, target, sha256(staged), whenStaged).shouldBeFalse()
            sha256(target) shouldBe replacement
            staged.exists().shouldBeFalse()
        }

        test("does not rewrite a JAR another server is still running from") {
            val target = serverJar(File(tempDir, "installed.jar"), marker = "OLD")
            val originalDigest = sha256(target)
            val staged = serverJar(File(tempDir, "installed.jar.1.new"), marker = "NEW")
            val stagedBytes = staged.readBytes()
            val newDigest = sha256(staged)

            RandomAccessFile(File(tempDir, target.name + UpdateInstaller.RUNNING_SUFFIX), "rw").use { sibling ->
                sibling.channel.lock(0, Long.MAX_VALUE, true)
                UpdateInstaller.installStagedAtShutdown(staged, target, newDigest, originalDigest).shouldBeFalse()
                sha256(target) shouldBe originalDigest
                staged.exists().shouldBeFalse()
            }

            staged.writeBytes(stagedBytes)
            UpdateInstaller.installStagedAtShutdown(staged, target, newDigest, originalDigest).shouldBeTrue()
            sha256(target) shouldBe newDigest
        }

        test("refuses, keeping the stage, when it cannot tell whether other servers are running") {
            val target = serverJar(File(tempDir, "installed.jar"), marker = "OLD")
            val originalDigest = sha256(target)
            val staged = serverJar(File(tempDir, "installed.jar.1.new"), marker = "NEW")
            File(tempDir, target.name + UpdateInstaller.RUNNING_SUFFIX).mkdir().shouldBeTrue()

            UpdateInstaller.installStagedAtShutdown(staged, target, sha256(staged), originalDigest).shouldBeFalse()
            sha256(target) shouldBe originalDigest
            staged.isFile.shouldBeTrue()
        }

        test("stands aside while the install lock is held or unusable") {
            val target = serverJar(File(tempDir, "installed.jar"), marker = "OLD")
            val originalDigest = sha256(target)
            val staged = serverJar(File(tempDir, "installed.jar.1.new"), marker = "NEW")
            val newDigest = sha256(staged)

            UpdateInstaller.withInstallLock(target) {
                UpdateInstaller.installStagedAtShutdown(staged, target, newDigest, originalDigest).shouldBeFalse()
            }
            sha256(target) shouldBe originalDigest
            staged.isFile.shouldBeTrue()

            File(tempDir, target.name + UpdateInstaller.LOCK_SUFFIX).let { it.delete() && it.mkdir() }.shouldBeTrue()
            UpdateInstaller.installStagedAtShutdown(staged, target, newDigest, originalDigest).shouldBeFalse()
            sha256(target) shouldBe originalDigest
        }

        test("a server's own running marker never blocks its own shutdown install") {
            val target = serverJar(File(tempDir, "installed.jar"), marker = "OLD")
            val staged = serverJar(File(tempDir, "installed.jar.1.new"), marker = "NEW")

            UpdateInstaller.holdRunningLock(target).shouldBeTrue()
            UpdateInstaller.holdRunningLock(target).shouldBeTrue()

            UpdateInstaller.installStagedAtShutdown(staged, target, sha256(staged), sha256(target)).shouldBeTrue()
        }
    }

    // ---------------------------------------------------------------------
    // Locks
    // ---------------------------------------------------------------------

    context("locks") {
        test("the lock sidecar is never deleted and does not block a later acquisition") {
            val target = serverJar(File(tempDir, "installed.jar"))
            val lockFile = File(tempDir, target.name + UpdateInstaller.LOCK_SUFFIX)

            UpdateInstaller.withInstallLock(target) { lockFile.isFile.shouldBeTrue(); 42 } shouldBe UpdateInstaller.LockResult.Acquired(42)
            lockFile.isFile.shouldBeTrue()
            lockFile.length() shouldBe 0L

            UpdateInstaller.withInstallLock(target) { 7 } shouldBe UpdateInstaller.LockResult.Acquired(7)

            UpdateInstaller.withInstallLock(target) {
                UpdateInstaller.withInstallLock(target) { "inner" } shouldBe UpdateInstaller.LockResult.Contended
                lockFile.isFile.shouldBeTrue()
            }
            lockFile.isFile.shouldBeTrue()
        }

        test("the install lock tells contention, an unusable sidecar and a failing block apart") {
            val target = serverJar(File(tempDir, "installed.jar"))
            val lockFile = File(tempDir, target.name + UpdateInstaller.LOCK_SUFFIX)

            UpdateInstaller.withInstallLock(target) { error("boom at ${tempDir.absolutePath}") } shouldBe
                UpdateInstaller.LockResult.Unavailable("unexpected IllegalStateException while holding ${lockFile.name}")
            UpdateInstaller.withInstallLock(target) { 1 } shouldBe UpdateInstaller.LockResult.Acquired(1)

            (lockFile.delete() && lockFile.mkdir()).shouldBeTrue()
            val unusable = UpdateInstaller.withInstallLock(target) { 1 }
            unusable.shouldBeInstanceOf<UpdateInstaller.LockResult.Unavailable>()
            unusable.reason shouldStartWith "cannot create ${lockFile.name}: "
            unusable.reason shouldEndWith "is the install directory writable?"
            unusable.reason shouldNotContain tempDir.absolutePath
        }

        test("a running marker excludes the rewrite until it is released, and is never deleted") {
            val target = serverJar(File(tempDir, "installed.jar"))
            val marker = File(tempDir, target.name + UpdateInstaller.RUNNING_SUFFIX)

            UpdateInstaller.holdRunningLock(target).shouldBeTrue()
            UpdateInstaller.withSoleUse(target) { "rewrite" } shouldBe UpdateInstaller.LockResult.Contended

            UpdateInstaller.releaseRunningLock()
            UpdateInstaller.releaseRunningLock() // idempotent
            UpdateInstaller.withSoleUse(target) { "rewrite" } shouldBe UpdateInstaller.LockResult.Acquired("rewrite")
            marker.isFile.shouldBeTrue()
            marker.length() shouldBe 0L
            UpdateInstaller.cleanupStaleArtifacts(target, maxAgeMillis = 0).shouldBeEmpty()
            marker.isFile.shouldBeTrue()

            RandomAccessFile(marker, "rw").use { other ->
                other.channel.lock(0, Long.MAX_VALUE, true)
                UpdateInstaller.holdRunningLock(target).shouldBeFalse()
            }
            (marker.delete() && marker.mkdir()).shouldBeTrue()
            UpdateInstaller.holdRunningLock(target).shouldBeFalse()
            UpdateInstaller.withSoleUse(target) { "rewrite" }.shouldBeInstanceOf<UpdateInstaller.LockResult.Unavailable>()
        }
    }

    // ---------------------------------------------------------------------
    // cleanupStaleArtifacts
    // ---------------------------------------------------------------------

    context("cleanupStaleArtifacts") {
        test("removes old staging and backup files but nothing else") {
            val target = serverJar(File(tempDir, "installed.jar"))
            val age = UpdateInstaller.STALE_ARTIFACT_AGE_MILLIS
            val now = System.currentTimeMillis()
            fun make(name: String, ageMillis: Long): File = File(tempDir, name).apply {
                writeText("x")
                setLastModified(now - ageMillis).shouldBeTrue()
            }
            val oldStaged = make("installed.jar.1234.new", age + 1)
            val oldStaged2 = make("installed.jar.5678.new", 2 * age)
            val exactlyStale = make("installed.jar.4321.new", age)
            val freshStaged = make("installed.jar.9999.new", 1_000)
            val oldBackup = make("installed.jar.bak", age + 1)
            val freshBackup = make("installed.jar.bak.keep", age + 1)
            val lock = make("installed.jar.update.lock", 3 * age)
            val running = make("installed.jar.running", 3 * age)
            val otherServer = make("other-server.jar.1111.new", 3 * age)
            val unrelated = make("installed.jar.notes.txt", 3 * age)
            val dirNamedNew = File(tempDir, "installed.jar.dir.new").apply { mkdir() }

            val removed = UpdateInstaller.cleanupStaleArtifacts(target, now = now)

            removed shouldContainExactlyInAnyOrder listOf(oldStaged.name, oldStaged2.name, exactlyStale.name, oldBackup.name)
            listOf(oldStaged, oldStaged2, exactlyStale, oldBackup).forEach { it.exists().shouldBeFalse() }
            listOf(freshStaged, freshBackup, lock, running, otherServer, unrelated, target).forEach { it.isFile.shouldBeTrue() }
            dirNamedNew.isDirectory.shouldBeTrue()

            UpdateInstaller.cleanupStaleArtifacts(target, now = now).shouldBeEmpty()
        }

        test("a missing or parentless directory yields nothing") {
            UpdateInstaller.cleanupStaleArtifacts(File(tempDir, "missing/dir/x.jar")).shouldBeEmpty()
            UpdateInstaller.cleanupStaleArtifacts(File("bare.jar")).shouldBeEmpty()
        }

        test("never removes the lock sidecar, held or not") {
            val target = serverJar(File(tempDir, "installed.jar"))
            val lockFile = File(tempDir, target.name + UpdateInstaller.LOCK_SUFFIX)
            val now = System.currentTimeMillis()
            lockFile.writeText("")
            lockFile.setLastModified(now - 30L * 24 * 60 * 60 * 1000).shouldBeTrue()

            UpdateInstaller.cleanupStaleArtifacts(target, now = now).shouldBeEmpty()
            lockFile.isFile.shouldBeTrue()

            UpdateInstaller.withInstallLock(target) {
                UpdateInstaller.cleanupStaleArtifacts(target, now = now).shouldBeEmpty()
                UpdateInstaller.withInstallLock(target) { "inner" } shouldBe UpdateInstaller.LockResult.Contended
            }
        }

        test("a stale stage that cannot be deleted is not reported as removed").config(enabled = IS_WINDOWS) {
            val target = serverJar(File(tempDir, "installed.jar"))
            val staged = File(tempDir, "installed.jar.7.new").apply { writeText("x") }
            val now = System.currentTimeMillis() + 2 * UpdateInstaller.STALE_ARTIFACT_AGE_MILLIS
            // Windows refuses to delete a file that is open without FILE_SHARE_DELETE.
            staged.inputStream().use {
                UpdateInstaller.cleanupStaleArtifacts(target, now = now).shouldBeEmpty()
            }
            staged.isFile.shouldBeTrue()
        }
    }

    // ---------------------------------------------------------------------
    // keepStagedFresh
    // ---------------------------------------------------------------------

    context("keepStagedFresh") {
        test("a pending stage kept fresh by its live owner survives a sibling's startup sweep") {
            val target = serverJar(File(tempDir, "installed.jar"))
            val staged = serverJar(File(tempDir, "installed.jar.1.new"), marker = "NEW")
            val overADay = UpdateInstaller.STALE_ARTIFACT_AGE_MILLIS + 60_000
            staged.setLastModified(System.currentTimeMillis() - overADay).shouldBeTrue()

            UpdateInstaller.keepStagedFresh(staged, intervalMillis = 10) { }.use {
                awaitTrue { System.currentTimeMillis() - staged.lastModified() < UpdateInstaller.STALE_ARTIFACT_AGE_MILLIS }
                    .shouldBeTrue()
                UpdateInstaller.cleanupStaleArtifacts(target).shouldBeEmpty()
                staged.isFile.shouldBeTrue()
                val heartbeats = Thread.getAllStackTraces().keys.filter { it.name == UpdateInstaller.HEARTBEAT_THREAD_NAME }
                (heartbeats.isNotEmpty() && heartbeats.all { it.isDaemon }).shouldBeTrue()
            }

            staged.setLastModified(System.currentTimeMillis() - overADay).shouldBeTrue()
            Thread.sleep(100)
            UpdateInstaller.cleanupStaleArtifacts(target) shouldContainExactly listOf(staged.name)
        }

        test("the heartbeat reports a stage that vanished, exactly once") {
            val staged = serverJar(File(tempDir, "installed.jar.1.new"))
            val reports = AtomicInteger()

            UpdateInstaller.keepStagedFresh(staged, intervalMillis = 10, pin = false) { reports.incrementAndGet() }.use {
                staged.delete().shouldBeTrue()
                awaitTrue { reports.get() > 0 }.shouldBeTrue()
                Thread.sleep(100)
                reports.get() shouldBe 1
            }
        }

        test("an onLost callback that throws is contained") {
            val staged = File(tempDir, "never-existed.new")
            val reports = AtomicInteger()
            // pin = true on a missing file: the pin silently fails and the heartbeat still runs.
            UpdateInstaller.keepStagedFresh(staged, intervalMillis = 10) {
                reports.incrementAndGet()
                error("boom")
            }.use {
                awaitTrue { reports.get() > 0 }.shouldBeTrue()
                Thread.sleep(50)
                reports.get() shouldBe 1
            }
        }

        test("the default interval is a sixth of the sweep threshold and close stops it promptly") {
            val staged = serverJar(File(tempDir, "installed.jar.2.new"))
            val stamped = System.currentTimeMillis() - 10_000
            staged.setLastModified(stamped).shouldBeTrue()
            val handle = UpdateInstaller.keepStagedFresh(staged, pin = false) { }
            val start = System.nanoTime()
            handle.close()
            ((System.nanoTime() - start) / 1_000_000) shouldBeLessThan 2_000L
            // No tick ran within the (4-hour) default interval.
            (staged.lastModified() / 1000) shouldBe (stamped / 1000)
        }

        test("on Windows the keep-alive pin refuses a sibling's delete of the stage").config(enabled = IS_WINDOWS) {
            val staged = serverJar(File(tempDir, "installed.jar.1.new"))

            UpdateInstaller.keepStagedFresh(staged, intervalMillis = 60_000) { }.use {
                staged.delete().shouldBeFalse()
            }
            staged.delete().shouldBeTrue()
        }
    }

    test("runningJar is null when the code source is a classes directory") {
        UpdateInstaller.runningJar().shouldBeNull()
        UpdateInstaller::class.java.protectionDomain.codeSource.shouldNotBeNull()
    }

    test("runningJar names the JAR when the installer is loaded from one") {
        // Copy the installer's own class files into a temp JAR and load them child-first, so that
        // copy's code source is that JAR. Everything else still comes from the test classpath.
        val prefix = "com/jitunicornfx/defender/mcp/UpdateInstaller"
        val loader = UpdateInstaller::class.java.classLoader
        val jar = File(tempDir, "installed-copy.jar")
        val classesDir = File(UpdateInstaller::class.java.protectionDomain.codeSource.location.toURI())
        val classFiles = File(classesDir, "com/jitunicornfx/defender/mcp").listFiles()!!
            .filter { it.name.startsWith("UpdateInstaller") && it.name.endsWith(".class") }
        classFiles.shouldNotBe(emptyList<File>())
        ZipOutputStream(jar.outputStream().buffered()).use { zip ->
            classFiles.forEach { f ->
                zip.putNextEntry(ZipEntry("com/jitunicornfx/defender/mcp/${f.name}"))
                zip.write(f.readBytes())
                zip.closeEntry()
            }
        }
        val childFirst = object : java.net.URLClassLoader(arrayOf(jar.toURI().toURL()), loader) {
            override fun loadClass(name: String, resolve: Boolean): Class<*> = synchronized(getClassLoadingLock(name)) {
                if (!name.replace('.', '/').startsWith(prefix)) return super.loadClass(name, resolve)
                findLoadedClass(name) ?: findClass(name)
            }
        }
        childFirst.use {
            val copy = it.loadClass("com.jitunicornfx.defender.mcp.UpdateInstaller")
            copy.classLoader shouldBe it
            val instance = copy.getField("INSTANCE").get(null)
            val method = copy.declaredMethods.single { m -> m.name.startsWith("runningJar") }
            method.isAccessible = true
            val found = method.invoke(instance) as File?
            found.shouldNotBeNull()
            found.canonicalFile shouldBe jar.canonicalFile
        }
    }
})
