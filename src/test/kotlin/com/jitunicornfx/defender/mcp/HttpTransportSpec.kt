package com.jitunicornfx.defender.mcp

import com.jitunicornfx.defender.mcp.testutil.FakeDefender
import com.jitunicornfx.defender.mcp.testutil.InMemoryTransport
import com.jitunicornfx.defender.mcp.testutil.testConfig
import io.kotest.assertions.nondeterministic.eventually
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.collections.shouldContainExactly
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotContain
import io.kotest.matchers.string.shouldStartWith
import io.kotest.property.Arb
import io.kotest.property.arbitrary.element
import io.kotest.property.arbitrary.int
import io.kotest.property.arbitrary.string
import io.kotest.property.checkAll
import io.ktor.client.HttpClient
import io.ktor.client.engine.okhttp.OkHttp
import io.ktor.client.plugins.sse.SSE as ClientSSE
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.options
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.server.application.Application
import io.ktor.server.application.install
import io.ktor.server.cio.CIO
import io.ktor.server.engine.embeddedServer
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import io.ktor.server.sse.SSE
import io.ktor.server.testing.testApplication
import io.modelcontextprotocol.kotlin.sdk.client.Client
import io.modelcontextprotocol.kotlin.sdk.client.SseClientTransport
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.types.Implementation
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import java.net.ServerSocket
import java.net.Socket
import java.util.Collections
import kotlin.time.Duration.Companion.seconds

private const val GOOD_TOKEN = "0123456789abcdef0123456789abcdef-strong"

private fun freePort(): Int = ServerSocket(0).use { it.localPort }

/** The guard plus two trivial routes, so each test sees exactly what the guard lets through. */
private fun Application.guarded(security: HttpSecurity) {
    installTransportSecurity(security)
    routing {
        get("/x") { call.respondText("ok") }
        post("/x") { call.respondText("ok") }
    }
}

private fun loopbackSecurity(
    token: String? = null,
    origins: List<String> = emptyList(),
    maxBody: Long = HttpSecurity.DEFAULT_MAX_BODY_BYTES,
    maxFailures: Int = HttpSecurity.DEFAULT_MAX_AUTH_FAILURES,
) = HttpSecurity("127.0.0.1", 3074, token, origins, maxBodyBytes = maxBody, maxAuthFailures = maxFailures)

/** Send a raw HTTP request over a socket (lets a test omit Host or forge headers a client would fix up). */
private fun rawRequest(port: Int, request: String): String =
    Socket("127.0.0.1", port).use { s ->
        s.soTimeout = 10_000
        s.getOutputStream().apply {
            write(request.toByteArray(Charsets.ISO_8859_1))
            flush()
        }
        s.getInputStream().bufferedReader(Charsets.ISO_8859_1).readLine() ?: ""
    }

/** testApplication's client sends no Host header; a real client always does. */
private fun io.ktor.server.testing.ApplicationTestBuilder.http(): HttpClient = createClient {
    install(io.ktor.client.plugins.DefaultRequest) { header(HttpHeaders.Host, "127.0.0.1:3074") }
}

private fun newRuntime(config: Config = testConfig()) = DefenderRuntime(config, client = FakeDefender().client(config))

class HttpTransportSpec : FunSpec({

    context("helpers") {
        test("normalizeOrigin lowercases, strips default ports and trailing slash") {
            normalizeOrigin("HTTPS://App.Example.com:443/") shouldBe "https://app.example.com"
            normalizeOrigin("http://localhost:80") shouldBe "http://localhost"
            normalizeOrigin("http://localhost:8080") shouldBe "http://localhost:8080"
            normalizeOrigin("  https://a.b  ") shouldBe "https://a.b"
        }

        test("normalizeOrigin refuses wildcards, null, other schemes and anything beyond scheme://host[:port]") {
            listOf(
                "", "  ", "*", "null", "NULL", "ftp://a.b", "a.b", "https://", "https://a.b/path",
                "https://user@a.b", "https://a.b?x=1", "https://a.b#f", "javascript://x",
            ).forEach { normalizeOrigin(it).shouldBeNull() }
        }

        test("normalizeOrigin is idempotent and never yields a path, credentials or query") {
            checkAll(Arb.string(0..40)) { s ->
                val n = normalizeOrigin(s)
                if (n != null) {
                    normalizeOrigin(n) shouldBe n
                    val rest = n.substringAfter("://")
                    rest shouldNotContain "/"
                    rest shouldNotContain "@"
                    rest shouldNotContain "?"
                    rest shouldNotContain "#"
                    (n.startsWith("http://") || n.startsWith("https://")) shouldBe true
                }
            }
        }

        test("hostPart strips ports and keeps IPv6 brackets") {
            hostPart("localhost:3074") shouldBe "localhost"
            hostPart("localhost") shouldBe "localhost"
            hostPart("[::1]:3074") shouldBe "[::1]"
            hostPart("[::1]") shouldBe "[::1]"
            hostPart("127.0.0.1:1") shouldBe "127.0.0.1"
        }

        test("hostPart never returns a port for any host:port") {
            checkAll(Arb.element("a.example", "localhost", "10.0.0.1"), Arb.int(1..65535)) { h, p ->
                hostPart("$h:$p") shouldBe h
                hostPart("[$h]:$p") shouldBe "[$h]"
            }
        }

        test("bearerToken parses the Bearer scheme only") {
            bearerToken("Bearer abc") shouldBe "abc"
            bearerToken("bearer   abc") shouldBe "abc"
            bearerToken("  BEARER abc  ") shouldBe "abc"
            bearerToken("Bearer a b") shouldBe "a b"
            bearerToken("Basic abc").shouldBeNull()
            bearerToken("Bearer").shouldBeNull()
            bearerToken("Bearer ").shouldBeNull()
            bearerToken("").shouldBeNull()
            bearerToken("abc").shouldBeNull()
        }

        test("constantTimeEquals compares exactly") {
            constantTimeEquals("abc", "abc") shouldBe true
            constantTimeEquals("abc", "abd") shouldBe false
            constantTimeEquals("abc", "abcd") shouldBe false
            constantTimeEquals("", "") shouldBe true
            constantTimeEquals("é", "e") shouldBe false
            checkAll(Arb.string(0..30), Arb.string(0..30)) { a, b ->
                constantTimeEquals(a, b) shouldBe (a == b)
                constantTimeEquals(a, a) shouldBe true
            }
        }

        test("isLoopback recognises localhost and loopback literals only") {
            isLoopback("localhost") shouldBe true
            isLoopback(" LOCALHOST ") shouldBe true
            isLoopback("127.0.0.1") shouldBe true
            isLoopback("127.5.6.7") shouldBe true
            isLoopback("::1") shouldBe true
            isLoopback("[::1]") shouldBe true
            isLoopback("0.0.0.0") shouldBe false
            isLoopback("10.1.2.3") shouldBe false
            isLoopback("192.168.0.1") shouldBe false
            isLoopback("::") shouldBe false
            // Unresolvable names are not loopback (runCatching default).
            isLoopback("no-such-host.invalid") shouldBe false
        }

        test("HttpSecurity.toString never prints the token") {
            val s = loopbackSecurity(token = GOOD_TOKEN).toString()
            s shouldNotContain GOOD_TOKEN
            s shouldContain "token=***"
            loopbackSecurity().toString() shouldContain "token=unset"
            loopbackSecurity().toString() shouldStartWith "HttpSecurity(bindHost=127.0.0.1"
        }
    }

    context("AuthFailureLimiter") {
        test("blocks after maxFailures within the window and unblocks when it passes") {
            var now = 1_000L
            val l = AuthFailureLimiter(maxFailures = 3, windowMillis = 100, clock = { now })
            l.isBlocked("a") shouldBe false
            repeat(2) { l.recordFailure("a") }
            l.isBlocked("a") shouldBe false
            l.recordFailure("a")
            l.isBlocked("a") shouldBe true
            l.isBlocked("b") shouldBe false
            now += 99
            l.isBlocked("a") shouldBe true
            now += 1
            l.isBlocked("a") shouldBe false
            // The entry was dropped: a single new failure does not re-block.
            l.recordFailure("a")
            l.isBlocked("a") shouldBe false
        }

        test("a failure after the window restarts the count") {
            var now = 0L
            val l = AuthFailureLimiter(maxFailures = 2, windowMillis = 50, clock = { now })
            l.recordFailure("a")
            now = 60
            l.recordFailure("a") // window expired: count restarts at 1
            l.isBlocked("a") shouldBe false
            l.recordFailure("a")
            l.isBlocked("a") shouldBe true
        }

        test("recordSuccess resets the client") {
            val l = AuthFailureLimiter(maxFailures = 2, windowMillis = 1_000, clock = { 0L })
            l.recordFailure("a")
            l.recordSuccess("a")
            l.recordFailure("a")
            l.isBlocked("a") shouldBe false
            l.recordFailure("a")
            l.isBlocked("a") shouldBe true
            l.recordSuccess("a")
            l.isBlocked("a") shouldBe false
            l.recordSuccess("never-seen") // no-op
        }

        test("the table is capped, evicting the oldest client") {
            val l = AuthFailureLimiter(maxFailures = 1, windowMillis = 1_000, clock = { 0L }, maxTrackedClients = 2)
            l.recordFailure("a")
            l.recordFailure("b")
            l.isBlocked("a") shouldBe true
            l.recordFailure("c") // evicts "a"
            l.isBlocked("a") shouldBe false
            l.isBlocked("b") shouldBe true
            l.isBlocked("c") shouldBe true
            // A known client within its window does not evict anyone.
            l.recordFailure("c")
            l.isBlocked("b") shouldBe true
        }
    }

    context("installTransportSecurity") {
        test("a well-formed local request passes") {
            testApplication {
                application { guarded(loopbackSecurity()) }
                val r = http().get("/x")
                r.status shouldBe HttpStatusCode.OK
                r.bodyAsText() shouldBe "ok"
            }
        }

        test("a foreign Host on a loopback bind is refused with 421 (DNS rebinding)") {
            testApplication {
                application { guarded(loopbackSecurity()) }
                val r = client.get("/x") { header(HttpHeaders.Host, "evil.example:3074") }
                r.status.value shouldBe 421
                r.bodyAsText() shouldNotContain "ok"
                client.get("/x") { header(HttpHeaders.Host, "127.0.0.1:3074") }.status shouldBe HttpStatusCode.OK
                client.get("/x") { header(HttpHeaders.Host, "[::1]:3074") }.status shouldBe HttpStatusCode.OK
                client.get("/x") { header(HttpHeaders.Host, "LOCALHOST") }.status shouldBe HttpStatusCode.OK
            }
        }

        test("an allow-listed origin's host is an accepted Host") {
            testApplication {
                application { guarded(loopbackSecurity(origins = listOf("https://app.example.com", "*"))) }
                client.get("/x") { header(HttpHeaders.Host, "app.example.com") }.status shouldBe HttpStatusCode.OK
                client.get("/x") { header(HttpHeaders.Host, "other.example.com") }.status.value shouldBe 421
            }
        }

        test("the Host check is skipped on a non-loopback bind") {
            testApplication {
                application { guarded(HttpSecurity("10.1.2.3", 3074, GOOD_TOKEN, emptyList())) }
                val r = http().get("/x") {
                    header(HttpHeaders.Host, "mcp.corp.example")
                    header(HttpHeaders.Authorization, "Bearer $GOOD_TOKEN")
                }
                r.status shouldBe HttpStatusCode.OK
            }
        }

        test("a cross-origin request from an origin not allow-listed is refused with 403") {
            testApplication {
                application { guarded(loopbackSecurity(origins = listOf("https://app.example.com"))) }
                http().get("/x") { header(HttpHeaders.Origin, "https://evil.example") }.status shouldBe HttpStatusCode.Forbidden
                http().get("/x") { header(HttpHeaders.Origin, "null") }.status shouldBe HttpStatusCode.Forbidden
                http().get("/x") { header(HttpHeaders.Origin, "https://app.example.com.evil.example") }.status shouldBe HttpStatusCode.Forbidden
            }
        }

        test("an allow-listed origin passes (normalized) and gets CORS headers") {
            testApplication {
                application { guarded(loopbackSecurity(origins = listOf("https://App.Example.com:443/"))) }
                val r = http().get("/x") { header(HttpHeaders.Origin, "https://app.example.com") }
                r.status shouldBe HttpStatusCode.OK
                r.headers[HttpHeaders.AccessControlAllowOrigin] shouldBe "https://app.example.com"
            }
        }

        test("bearer token: missing or wrong gives 401 with WWW-Authenticate, right one passes") {
            testApplication {
                application { guarded(loopbackSecurity(token = GOOD_TOKEN)) }
                val missing = http().get("/x")
                missing.status shouldBe HttpStatusCode.Unauthorized
                missing.headers[HttpHeaders.WWWAuthenticate] shouldBe "Bearer realm=\"$SERVER_NAME\""
                missing.bodyAsText() shouldNotContain GOOD_TOKEN

                http().get("/x") { header(HttpHeaders.Authorization, "Bearer wrong") }.status shouldBe HttpStatusCode.Unauthorized
                http().get("/x") { header(HttpHeaders.Authorization, "Basic $GOOD_TOKEN") }.status shouldBe HttpStatusCode.Unauthorized
                http().get("/x") { header(HttpHeaders.Authorization, "Bearer ${GOOD_TOKEN}x") }.status shouldBe HttpStatusCode.Unauthorized
                http().get("/x") { header(HttpHeaders.Authorization, "Bearer $GOOD_TOKEN") }.status shouldBe HttpStatusCode.OK
            }
        }

        test("brute force: after N failures even the right token gets 429 with Retry-After") {
            testApplication {
                application { guarded(loopbackSecurity(token = GOOD_TOKEN, maxFailures = 3)) }
                repeat(3) {
                    http().get("/x") { header(HttpHeaders.Authorization, "Bearer guess$it") }.status shouldBe HttpStatusCode.Unauthorized
                }
                val blocked = http().get("/x") { header(HttpHeaders.Authorization, "Bearer $GOOD_TOKEN") }
                blocked.status shouldBe HttpStatusCode.TooManyRequests
                blocked.headers[HttpHeaders.RetryAfter] shouldBe "60"
            }
        }

        test("a successful authentication resets the failure count") {
            testApplication {
                application { guarded(loopbackSecurity(token = GOOD_TOKEN, maxFailures = 3)) }
                repeat(2) { http().get("/x") { header(HttpHeaders.Authorization, "Bearer bad") } }
                http().get("/x") { header(HttpHeaders.Authorization, "Bearer $GOOD_TOKEN") }.status shouldBe HttpStatusCode.OK
                repeat(2) {
                    http().get("/x") { header(HttpHeaders.Authorization, "Bearer bad") }.status shouldBe HttpStatusCode.Unauthorized
                }
                http().get("/x") { header(HttpHeaders.Authorization, "Bearer $GOOD_TOKEN") }.status shouldBe HttpStatusCode.OK
            }
        }

        test("an oversized body is refused with 413, a small one passes") {
            testApplication {
                application { guarded(loopbackSecurity(maxBody = 10)) }
                http().post("/x") { setBody("x".repeat(11)) }.status shouldBe HttpStatusCode.PayloadTooLarge
                http().post("/x") { setBody("x".repeat(10)) }.status shouldBe HttpStatusCode.OK
            }
        }

        test("CORS preflight from an allowed origin is answered without credentials") {
            testApplication {
                application { guarded(loopbackSecurity(token = GOOD_TOKEN, origins = listOf("https://app.example.com"))) }
                val r = http().options("/x") {
                    header(HttpHeaders.Origin, "https://app.example.com")
                    header(HttpHeaders.AccessControlRequestMethod, "POST")
                    header(HttpHeaders.AccessControlRequestHeaders, "authorization,mcp-session-id")
                }
                r.status shouldBe HttpStatusCode.OK
                r.headers[HttpHeaders.AccessControlAllowOrigin] shouldBe "https://app.example.com"
                r.headers[HttpHeaders.AccessControlAllowMethods].shouldNotBeNull() shouldContain "POST"
            }
        }

        test("CORS preflight from a foreign origin is refused, and OPTIONS without Origin still needs the token") {
            testApplication {
                application { guarded(loopbackSecurity(token = GOOD_TOKEN, origins = listOf("https://app.example.com"))) }
                http().options("/x") {
                    header(HttpHeaders.Origin, "https://evil.example")
                    header(HttpHeaders.AccessControlRequestMethod, "POST")
                }.status shouldBe HttpStatusCode.Forbidden
                http().options("/x").status shouldBe HttpStatusCode.Unauthorized
            }
        }

        test("over a real socket: a request with no Host header is refused with 421; a huge Content-Length with 413") {
            val port = freePort()
            val server = embeddedServer(CIO, host = "127.0.0.1", port = port) { guarded(loopbackSecurity(maxBody = 100)) }
            server.start(wait = false)
            try {
                rawRequest(port, "GET /x HTTP/1.0\r\n\r\n") shouldContain "421"
                rawRequest(port, "GET /x HTTP/1.1\r\nHost: 127.0.0.1:$port\r\nConnection: close\r\n\r\n") shouldContain "200"
                rawRequest(
                    port,
                    "POST /x HTTP/1.1\r\nHost: 127.0.0.1:$port\r\nContent-Length: 999999999\r\nConnection: close\r\n\r\n",
                ) shouldContain "413"
            } finally {
                server.stop(0, 1_000)
            }
        }
    }

    context("legacy SSE transport") {
        test("POST without sessionId is 400 and an unknown session is 404") {
            testApplication {
                install(SSE)
                routing { legacySseTransport("/sse") { error("must not build a server for a bad POST") } }
                val noId = client.post("/sse") { setBody("{}") }
                noId.status shouldBe HttpStatusCode.BadRequest
                noId.bodyAsText() shouldContain "sessionId"
                val unknown = client.post("/sse?sessionId=does-not-exist") {
                    contentType(ContentType.Application.Json)
                    setBody("{}")
                }
                unknown.status shouldBe HttpStatusCode.NotFound
            }
        }

        test("a real legacy client connects, lists tools, and its Server closes when the stream ends") {
            val port = freePort()
            val http = buildHttpRuntime(newRuntime(), "127.0.0.1", port)
            http.engine.start(wait = false)
            val httpClient = HttpClient(OkHttp) { install(ClientSSE) }
            try {
                val client = Client(Implementation("legacy-test", "1.0"))
                client.connect(SseClientTransport(httpClient, "http://127.0.0.1:$port$LEGACY_SSE_PATH"))
                client.listTools().tools.map { it.name } shouldContain "defender_server_info"
                http.sessions.liveCount shouldBe 1
                client.close()
                // CIO does not notice an idle stream's client leaving; stopping the engine cancels the
                // stream handler, whose finally block must close (and so release) the Server.
                http.engine.stop(0, 2_000)
                eventually(10.seconds) { http.sessions.liveCount shouldBe 0 }
            } finally {
                httpClient.close()
                http.engine.stop(0, 1_000)
                http.shutdown()
            }
        }

        test("a legacy stream ends when the session cap evicts its Server") {
            val port = freePort()
            val http = buildHttpRuntime(newRuntime(), "127.0.0.1", port, maxLiveSessions = 1)
            http.engine.start(wait = false)
            val httpClient = HttpClient(OkHttp) { install(ClientSSE) }
            try {
                val first = Client(Implementation("first", "1.0"))
                first.connect(SseClientTransport(httpClient, "http://127.0.0.1:$port$LEGACY_SSE_PATH"))
                val second = Client(Implementation("second", "1.0"))
                second.connect(SseClientTransport(httpClient, "http://127.0.0.1:$port$LEGACY_SSE_PATH"))
                second.listTools().tools.map { it.name } shouldContain "defender_server_info"
                eventually(10.seconds) { http.sessions.liveCount shouldBe 1 }
                // The evicted Server's stream ended, so the first client is disconnected.
                eventually(10.seconds) {
                    shouldThrow<IllegalStateException> { kotlinx.coroutines.withTimeout(5_000) { first.listTools() } }
                        .message shouldContain "Not connected"
                }
                second.close()
                first.close()
            } finally {
                httpClient.close()
                http.engine.stop(0, 1_000)
                http.shutdown()
            }
        }
    }

    context("ServerGovernor") {
        test("rejects a cap below one") {
            val scope = CoroutineScope(SupervisorJob())
            shouldThrow<IllegalArgumentException> { ServerGovernor(0, scope) }.message shouldContain "at least 1"
            scope.cancel()
        }

        test("admit caps live servers and closes the oldest") {
            val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
            val runtime = newRuntime()
            val governor = ServerGovernor(2, scope)
            val closed = Collections.synchronizedList(mutableListOf<String>())
            fun named(n: String): Server = buildServer(runtime).also { s -> s.onClose { closed += n } }
            val a = named("a")
            governor.admit(a) shouldBe a
            governor.admit(named("b"))
            governor.liveCount shouldBe 2
            closed.shouldBeEmpty()
            governor.admit(named("c"))
            governor.liveCount shouldBe 2
            eventually(5.seconds) { closed shouldContainExactly listOf("a") }
            governor.admit(named("d"))
            eventually(5.seconds) { closed shouldContainExactly listOf("a", "b") }
            governor.maxLive shouldBe 2
            scope.cancel()
        }

        test("a cap of one never evicts the newcomer") {
            val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
            val runtime = newRuntime()
            val governor = ServerGovernor(1, scope)
            val closed = Collections.synchronizedList(mutableListOf<String>())
            val a = buildServer(runtime).also { it.onClose { closed += "a" } }
            val b = buildServer(runtime).also { it.onClose { closed += "b" } }
            governor.admit(a)
            governor.admit(b)
            eventually(5.seconds) { closed shouldContainExactly listOf("a") }
            governor.liveCount shouldBe 1
            scope.cancel()
        }

        test("prefers evicting servers whose session never initialized, and releases a closed session") {
            val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
            val runtime = newRuntime()
            val governor = ServerGovernor(2, scope)
            val closed = Collections.synchronizedList(mutableListOf<String>())

            // "a" is oldest but initialized (a real client finished its handshake).
            val a = governor.admit(buildServer(runtime).also { it.onClose { closed += "a" } })
            val (clientT, serverT) = InMemoryTransport.createLinkedPair()
            val client = Client(Implementation("gov-test", "1.0"))
            coroutineScope {
                launch { client.connect(clientT) }
                launch { a.createSession(serverT) }
            }
            client.listTools().tools.shouldNotBe(emptyList<Any>())

            // "b" never initializes (a probe); "c" pushes past the cap.
            governor.admit(buildServer(runtime).also { it.onClose { closed += "b" } })
            governor.admit(buildServer(runtime).also { it.onClose { closed += "c" } })
            eventually(5.seconds) { closed shouldContainExactly listOf("b") }
            governor.liveCount shouldBe 2

            // Ending the initialized session releases "a" from the count without closing the Server.
            client.close()
            eventually(5.seconds) { governor.liveCount shouldBe 1 }
            closed shouldContainExactly listOf("b")
            scope.cancel()
        }

        test("a server closed from outside leaves the count, and marking an evicted server is ignored") {
            val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
            val runtime = newRuntime()
            val governor = ServerGovernor(3, scope)
            val s = governor.admit(buildServer(runtime))
            governor.liveCount shouldBe 1
            s.close()
            governor.liveCount shouldBe 0
            scope.cancel()
        }

        test("a second session on the same Server is not watched twice") {
            val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
            val runtime = newRuntime()
            val governor = ServerGovernor(2, scope)
            val s = governor.admit(buildServer(runtime))
            repeat(2) {
                val (clientT, serverT) = InMemoryTransport.createLinkedPair()
                val c = Client(Implementation("multi-$it", "1.0"))
                coroutineScope {
                    launch { c.connect(clientT) }
                    launch { s.createSession(serverT) }
                }
                c.listTools().tools.map { t -> t.name } shouldContain "defender_server_info"
            }
            governor.liveCount shouldBe 1
            scope.cancel()
        }

        test("a Server evicted before its handshake finishes is not marked initialized") {
            // A cancelled scope: the eviction close never runs, so the evicted Server can still initialize.
            val deadScope = CoroutineScope(SupervisorJob()).also { it.cancel() }
            val runtime = newRuntime()
            val governor = ServerGovernor(1, deadScope)
            val a = governor.admit(buildServer(runtime))
            val (clientT, serverT) = InMemoryTransport.createLinkedPair()
            a.createSession(serverT) // onConnect fires: the governor now watches a's session
            governor.admit(buildServer(runtime)) // evicts a (uninitialized)
            governor.liveCount shouldBe 1
            val c = Client(Implementation("late", "1.0"))
            c.connect(clientT) // a's session initializes after eviction
            c.listTools().tools.map { it.name } shouldContain "defender_server_info"
            governor.liveCount shouldBe 1
            // A third newcomer must evict the second (uninitialized) one, not resurrect a.
            governor.admit(buildServer(runtime))
            governor.liveCount shouldBe 1
        }
    }
})
