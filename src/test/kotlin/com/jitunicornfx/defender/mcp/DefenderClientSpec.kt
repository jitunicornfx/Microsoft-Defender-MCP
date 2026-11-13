package com.jitunicornfx.defender.mcp

import com.jitunicornfx.defender.mcp.testutil.Canned
import com.jitunicornfx.defender.mcp.testutil.FakeDefender
import com.jitunicornfx.defender.mcp.testutil.MACHINE_ID
import com.jitunicornfx.defender.mcp.testutil.TEST_SECRET
import com.jitunicornfx.defender.mcp.testutil.TEST_TENANT
import com.jitunicornfx.defender.mcp.testutil.testConfig
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.booleans.shouldBeFalse
import io.kotest.matchers.booleans.shouldBeTrue
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldContainExactly
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.ints.shouldBeLessThanOrEqual
import io.kotest.matchers.longs.shouldBeInRange
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldNotContain
import io.kotest.property.Arb
import io.kotest.property.arbitrary.element
import io.kotest.property.arbitrary.int
import io.kotest.property.arbitrary.list
import io.kotest.property.arbitrary.string
import io.kotest.property.checkAll
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.writeFully
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.currentTime
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.yield
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.util.Collections
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

private const val DEFENDER_SCOPE = "https://api.securitycenter.microsoft.com/.default"

private fun statuses(vararg codes: Int, headers: Map<String, String> = emptyMap()): (io.ktor.client.request.HttpRequestData) -> Canned {
    val n = AtomicInteger()
    return { Canned(status = HttpStatusCode.fromValue(codes[minOf(n.getAndIncrement(), codes.lastIndex)]), headers = headers) }
}

private fun FakeDefender.countingTokens(): FakeDefender = apply {
    val n = AtomicInteger()
    token = {
        Canned(body = """{"expires_in":3599,"access_token":"token-${n.incrementAndGet()}-abcdefghijklmnop"}""")
    }
}

private fun strictUtf8(bytes: ByteArray): String =
    Charsets.UTF_8.newDecoder()
        .onMalformedInput(CodingErrorAction.REPORT)
        .onUnmappableCharacter(CodingErrorAction.REPORT)
        .decode(ByteBuffer.wrap(bytes)).toString()

class DefenderClientSpec : FunSpec({

    context("request shape") {
        test("GET carries bearer token, Accept, query parameters and no body") {
            val fake = FakeDefender(api = { Canned(body = """{"value":[]}""") })
            val response = fake.client().get(
                "/api/machines",
                listOf("\$filter" to "healthStatus eq 'Active' and x=1&y", "\$top" to "5"),
            )
            response.ok.shouldBeTrue()
            response.status shouldBe 200
            response.text shouldBe """{"value":[]}"""
            response.contentType shouldBe "application/json"
            response.truncated.shouldBeFalse()
            val req = fake.last.request
            req.method shouldBe HttpMethod.Get
            req.url.host shouldBe "api.security.microsoft.com"
            req.url.protocol.name shouldBe "https"
            req.url.encodedPath shouldBe "/api/machines"
            req.url.parameters["\$filter"] shouldBe "healthStatus eq 'Active' and x=1&y"
            req.url.parameters["\$top"] shouldBe "5"
            req.url.parameters.names() shouldBe setOf("\$filter", "\$top")
            req.headers[HttpHeaders.Authorization] shouldBe "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOi.test.token"
            req.headers[HttpHeaders.Accept] shouldBe "application/json"
            fake.last.body.shouldBeNull()
            fake.tokenRequests shouldHaveSize 1
        }

        test("POST sends compact JSON with an application/json content type") {
            val fake = FakeDefender()
            val body = buildJsonObject {
                put("Comment", "isolate <b>now</b>")
                put("IsolationType", "Full")
            }
            fake.client().request(HttpMethod.Post, "/api/machines/$MACHINE_ID/isolate", body = body)
            val rec = fake.last
            rec.request.method shouldBe HttpMethod.Post
            rec.request.body.contentType?.withoutParameters() shouldBe ContentType.Application.Json
            rec.body shouldBe """{"Comment":"isolate <b>now</b>","IsolationType":"Full"}"""
            rec.request.headers[HttpHeaders.Authorization] shouldBe "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOi.test.token"
        }

        test("GRAPH upstream goes to the Graph host with a Graph-scoped token; scopes are cached separately") {
            val fake = FakeDefender().countingTokens()
            val client = fake.client()
            client.request(HttpMethod.Post, "/v1.0/security/runHuntingQuery", body = JsonPrimitive("q"), idempotent = true, upstream = Upstream.GRAPH)
            client.get("/api/alerts")
            client.request(HttpMethod.Post, "/v1.0/security/runHuntingQuery", body = JsonPrimitive("q"), upstream = Upstream.GRAPH)
            client.get("/api/alerts")
            val api = fake.apiRequests
            api.map { it.request.url.host } shouldContainExactly listOf(
                "graph.microsoft.com", "api.security.microsoft.com", "graph.microsoft.com", "api.security.microsoft.com",
            )
            api.map { it.request.headers[HttpHeaders.Authorization] } shouldContainExactly listOf(
                "Bearer token-1-abcdefghijklmnop", "Bearer token-2-abcdefghijklmnop",
                "Bearer token-1-abcdefghijklmnop", "Bearer token-2-abcdefghijklmnop",
            )
            fake.tokenRequests shouldHaveSize 2
            fake.tokenRequests[0].body!!.contains("graph.microsoft.com%2F.default").shouldBeTrue()
            fake.tokenRequests[1].body!!.contains("api.securitycenter.microsoft.com%2F.default").shouldBeTrue()
        }

        test("a government cloud pins API, Graph and login hosts together") {
            val fake = FakeDefender()
            val cloud = CloudEnvironment.GCC_HIGH
            val config = testConfig().copy(cloud = cloud)
            val client = fake.client(config)
            client.get("/api/machines")
            client.request(HttpMethod.Post, "/v1.0/security/runHuntingQuery", upstream = Upstream.GRAPH)
            fake.apiRequests.map { it.request.url.host } shouldContainExactly listOf("api-gov.securitycenter.microsoft.us", "graph.microsoft.us")
            fake.tokenRequests.map { it.request.url.toString() }.toSet() shouldBe
                setOf("https://login.microsoftonline.us/$TEST_TENANT/oauth2/v2.0/token")
        }

        test("a configured region's host is used") {
            val fake = FakeDefender()
            val config = testConfig().copy(region = DefenderRegion.US)
            fake.client(config).get("/api/machines")
            fake.last.request.url.host shouldBe "us.api.security.microsoft.com"
        }

        test("the client secret never appears on an API request") {
            val fake = FakeDefender()
            fake.client().get("/api/machines", listOf("q" to "x"))
            val req = fake.last
            req.url shouldNotContain TEST_SECRET
            req.request.headers.entries().forEach { (_, v) -> v.joinToString() shouldNotContain TEST_SECRET }
            // ...and is only sent to the Entra ID token endpoint.
            fake.tokenRequests.single().request.url.host shouldBe "login.microsoftonline.com"
        }
    }

    context("path validation") {
        test("relative and protocol-relative paths are refused before any request") {
            val fake = FakeDefender()
            val client = fake.client()
            listOf("api/machines", "", "//evil.example.com/api", "https://evil.example.com/x", "@evil.example.com").forEach { path ->
                shouldThrow<IllegalArgumentException> { client.get(path) }.message shouldBe "path must be absolute"
            }
            fake.recorded.shouldBeEmpty()
        }

        test("any path not starting with a single slash is refused (property)") {
            val fake = FakeDefender()
            val client = fake.client()
            checkAll(200, Arb.string(0..40)) { s ->
                val path = if (s.startsWith("/") && !s.startsWith("//")) "x$s" else s
                shouldThrow<IllegalArgumentException> { client.get(path) }
            }
            fake.recorded.shouldBeEmpty()
        }

        test("any path stays on the configured host") {
            val fake = FakeDefender()
            val client = fake.client()
            listOf("/@evil.example.com", "/.evil.example.com", "/api/../../x", "/%2F%2Fevil.example.com").forEach { path ->
                client.get(path)
                fake.last.request.url.host shouldBe "api.security.microsoft.com"
            }
        }
    }

    context("401 handling") {
        test("a 401 invalidates the token and retries exactly once with a fresh one") {
            val fake = FakeDefender(api = statuses(401, 200)).countingTokens()
            val response = fake.client().get("/api/machines")
            response.status shouldBe 200
            fake.apiRequests.map { it.request.headers[HttpHeaders.Authorization] } shouldContainExactly
                listOf("Bearer token-1-abcdefghijklmnop", "Bearer token-2-abcdefghijklmnop")
            fake.tokenRequests shouldHaveSize 2
        }

        test("a second 401 is returned, not retried forever") {
            val sleeps = mutableListOf<Long>()
            val fake = FakeDefender(api = statuses(401)).countingTokens()
            val response = fake.client(sleep = { sleeps += it }).get("/api/machines")
            response.status shouldBe 401
            response.ok.shouldBeFalse()
            fake.apiRequests shouldHaveSize 2
            fake.tokenRequests shouldHaveSize 2
            sleeps.shouldBeEmpty()
        }

        test("token failure surfaces as TokenAcquisitionException without the secret") {
            val fake = FakeDefender(token = { Canned(HttpStatusCode.Unauthorized, """{"error":"invalid_client","error_description":"bad $TEST_SECRET"}""") })
            val e = shouldThrow<TokenAcquisitionException> { fake.client().get("/api/machines") }
            e.message!! shouldNotContain TEST_SECRET
            fake.apiRequests.shouldBeEmpty()
        }
    }

    context("429 handling") {
        test("retries after the Retry-After seconds using the injected sleep") {
            val sleeps = mutableListOf<Long>()
            val fake = FakeDefender(api = statuses(429, 200, headers = mapOf(HttpHeaders.RetryAfter to "3")))
            val response = fake.client(sleep = { sleeps += it }).get("/api/machines")
            response.status shouldBe 200
            sleeps shouldContainExactly listOf(3_000L)
            fake.apiRequests shouldHaveSize 2
        }

        test("a Retry-After beyond the maximum is returned to the caller without waiting") {
            val sleeps = mutableListOf<Long>()
            val fake = FakeDefender(api = statuses(429, 200, headers = mapOf(HttpHeaders.RetryAfter to "31")))
            val response = fake.client(sleep = { sleeps += it }).get("/api/machines")
            response.status shouldBe 429
            sleeps.shouldBeEmpty()
            fake.apiRequests shouldHaveSize 1
        }

        test("exactly the maximum Retry-After is still honoured") {
            val sleeps = mutableListOf<Long>()
            val fake = FakeDefender(api = statuses(429, 200, headers = mapOf(HttpHeaders.RetryAfter to "30")))
            fake.client(sleep = { sleeps += it }).get("/api/machines").status shouldBe 200
            sleeps shouldContainExactly listOf(30_000L)
        }

        test("persistent 429s are returned once retries are exhausted") {
            val sleeps = mutableListOf<Long>()
            val fake = FakeDefender(api = statuses(429, headers = mapOf(HttpHeaders.RetryAfter to "1")))
            val response = fake.client(sleep = { sleeps += it }).request(HttpMethod.Post, "/api/machines/$MACHINE_ID/isolate")
            response.status shouldBe 429
            sleeps shouldContainExactly listOf(1_000L, 1_000L)
            fake.apiRequests shouldHaveSize 3
        }

        test("without Retry-After the wait backs off exponentially") {
            val sleeps = mutableListOf<Long>()
            val fake = FakeDefender(api = statuses(429))
            fake.client(sleep = { sleeps += it }).get("/api/machines").status shouldBe 429
            sleeps shouldContainExactly listOf(1_000L, 2_000L)
        }

        test("custom retry limits are respected") {
            val sleeps = mutableListOf<Long>()
            val fake = FakeDefender(api = statuses(429, headers = mapOf(HttpHeaders.RetryAfter to "2")))
            val client = DefenderClient(testConfig(), fake.engine, sleep = { sleeps += it }, maxRetryAfterMillis = 1_000, maxRetries = 5)
            client.get("/api/machines").status shouldBe 429
            sleeps.shouldBeEmpty()

            val sleeps2 = mutableListOf<Long>()
            val fake2 = FakeDefender(api = statuses(429))
            DefenderClient(testConfig(), fake2.engine, sleep = { sleeps2 += it }, maxRetries = 0).get("/api/machines").status shouldBe 429
            sleeps2.shouldBeEmpty()
            fake2.apiRequests shouldHaveSize 1
        }

        test("a 429 retry after a 401 refresh still works, and a later 401 is not refreshed again") {
            val fake = FakeDefender(api = statuses(401, 429, 401, headers = mapOf(HttpHeaders.RetryAfter to "0"))).countingTokens()
            val response = fake.client().get("/api/machines")
            response.status shouldBe 401
            fake.apiRequests shouldHaveSize 3
            fake.tokenRequests shouldHaveSize 2
        }
    }

    context("transient 5xx handling") {
        listOf(502, 503, 504).forEach { code ->
            test("GET is retried on $code with backoff and succeeds") {
                val sleeps = mutableListOf<Long>()
                val fake = FakeDefender(api = statuses(code, code, 200))
                fake.client(sleep = { sleeps += it }).get("/api/machines").status shouldBe 200
                sleeps shouldContainExactly listOf(1_000L, 2_000L)
                fake.apiRequests shouldHaveSize 3
            }

            test("a state-changing POST is never replayed on $code") {
                val sleeps = mutableListOf<Long>()
                val fake = FakeDefender(api = statuses(code, 200))
                val response = fake.client(sleep = { sleeps += it })
                    .request(HttpMethod.Post, "/api/machines/$MACHINE_ID/isolate", body = buildJsonObject { put("Comment", "x") })
                response.status shouldBe code
                sleeps.shouldBeEmpty()
                fake.apiRequests shouldHaveSize 1
            }
        }

        test("the idempotent hunting POST is retried") {
            val sleeps = mutableListOf<Long>()
            val fake = FakeDefender(api = statuses(503, 200))
            fake.client(sleep = { sleeps += it })
                .request(HttpMethod.Post, "/v1.0/security/runHuntingQuery", body = buildJsonObject { put("Query", "DeviceInfo") }, bucket = RateBucket.HUNTING, idempotent = true)
                .status shouldBe 200
            sleeps shouldContainExactly listOf(1_000L)
        }

        test("persistent 503 on GET is returned after the retry budget") {
            val fake = FakeDefender(api = statuses(503))
            fake.client().get("/api/machines").status shouldBe 503
            fake.apiRequests shouldHaveSize 3
        }

        test("500 and 4xx errors are returned immediately") {
            listOf(500, 400, 403, 404).forEach { code ->
                val fake = FakeDefender(api = statuses(code, 200))
                fake.client().get("/api/machines").status shouldBe code
                fake.apiRequests shouldHaveSize 1
            }
        }
    }

    context("redirects") {
        test("a 302 is returned, never followed, so the bearer token cannot be forwarded") {
            listOf(301, 302, 303, 307, 308).forEach { code ->
                val fake = FakeDefender(api = {
                    Canned(status = HttpStatusCode.fromValue(code), body = "", headers = mapOf(HttpHeaders.Location to "https://evil.example.com/steal"))
                })
                val response = fake.client().get("/api/machines")
                response.status shouldBe code
                response.ok.shouldBeFalse()
                fake.apiRequests shouldHaveSize 1
                fake.recorded.none { it.request.url.host == "evil.example.com" }.shouldBeTrue()
            }
        }

        test("the default OkHttp-backed client can be built and closed without any network use") {
            val client = DefenderClient(testConfig())
            client.tokens shouldBe client.tokens
            client.close()
        }
    }

    context("response size cap") {
        test("a body over maxResponseBytes is truncated and flagged") {
            val fake = FakeDefender(api = { Canned(body = "a".repeat(5_000)) })
            val config = testConfig().copy(maxResponseBytes = 1_024)
            val response = fake.client(config).get("/api/machines")
            response.truncated.shouldBeTrue()
            response.text.length shouldBe 1_024
            response.limitBytes shouldBe 1_024
            response.status shouldBe 200
        }

        test("a body of exactly the cap is not flagged") {
            val fake = FakeDefender(api = { Canned(body = "b".repeat(1_024)) })
            val response = fake.client(testConfig().copy(maxResponseBytes = 1_024)).get("/api/machines")
            response.truncated.shouldBeFalse()
            response.text.length shouldBe 1_024
        }

        test("truncation never leaves half a multi-byte character") {
            val fake = FakeDefender(api = { Canned(body = "€".repeat(1_000)) }) // 3 bytes each
            val response = fake.client(testConfig().copy(maxResponseBytes = 1_024)).get("/api/machines")
            response.truncated.shouldBeTrue()
            response.text shouldBe "€".repeat(341)
            response.text.contains('�').shouldBeFalse()
        }

        test("a missing content type is reported as null") {
            val engine = MockEngine { req ->
                if (req.url.host.startsWith("login.")) {
                    respond("""{"access_token":"abcdefghijklmnopqrstu"}""", HttpStatusCode.OK, headersOf(HttpHeaders.ContentType, "application/json"))
                } else {
                    respond("plain", HttpStatusCode.OK)
                }
            }
            val response = DefenderClient(testConfig(), engine).get("/api/x")
            response.contentType.shouldBeNull()
            response.text shouldBe "plain"
        }
    }

    context("ApiResponse") {
        test("ok covers exactly 2xx") {
            listOf(199 to false, 200 to true, 204 to true, 299 to true, 300 to false, 404 to false).forEach { (s, ok) ->
                DefenderClient.ApiResponse(s, null, "").ok shouldBe ok
            }
            DefenderClient.ApiResponse(200, null, "").truncated.shouldBeFalse()
            DefenderClient.ApiResponse(200, null, "").limitBytes shouldBe 0
        }
    }

    context("rate buckets") {
        fun virtual(): Pair<AtomicLong, MutableList<Long>> = AtomicLong(0) to Collections.synchronizedList(mutableListOf())

        test("PACKAGE_URI allows two calls a minute, independent of DEFAULT") {
            val (now, sleeps) = virtual()
            val fake = FakeDefender()
            val client = DefenderClient(testConfig(), fake.engine, clock = { now.get() }, sleep = { sleeps += it; now.addAndGet(it) })
            repeat(2) { client.get("/api/machines/$MACHINE_ID/x", bucket = RateBucket.PACKAGE_URI) }
            repeat(10) { client.get("/api/machines") }
            sleeps.shouldBeEmpty()
            client.get("/api/machines/$MACHINE_ID/x", bucket = RateBucket.PACKAGE_URI)
            sleeps shouldContainExactly listOf(60_000L)
        }

        test("HUNTING allows 45 calls a minute") {
            val (now, sleeps) = virtual()
            val fake = FakeDefender()
            val client = DefenderClient(testConfig(), fake.engine, clock = { now.get() }, sleep = { sleeps += it; now.addAndGet(it) })
            repeat(45) { client.request(HttpMethod.Post, "/v1.0/security/runHuntingQuery", bucket = RateBucket.HUNTING, idempotent = true) }
            sleeps.shouldBeEmpty()
            client.request(HttpMethod.Post, "/v1.0/security/runHuntingQuery", bucket = RateBucket.HUNTING, idempotent = true)
            sleeps shouldContainExactly listOf(60_000L)
        }

        test("DEFAULT allows 100 calls a minute") {
            val (now, sleeps) = virtual()
            val fake = FakeDefender()
            val client = DefenderClient(testConfig(), fake.engine, clock = { now.get() }, sleep = { sleeps += it; now.addAndGet(it) })
            repeat(100) { client.get("/api/machines") }
            sleeps.shouldBeEmpty()
            client.get("/api/machines")
            sleeps shouldContainExactly listOf(60_000L)
            fake.tokenRequests shouldHaveSize 1
        }
    }

    context("concurrency") {
        test("in-flight requests never exceed maxConcurrentRequests") {
            val inFlight = AtomicInteger()
            val peak = AtomicInteger()
            val engine = MockEngine { req ->
                if (req.url.host.startsWith("login.")) {
                    respond("""{"access_token":"abcdefghijklmnopqrstu"}""", HttpStatusCode.OK, headersOf(HttpHeaders.ContentType, "application/json"))
                } else {
                    val n = inFlight.incrementAndGet()
                    peak.accumulateAndGet(n) { a, b -> maxOf(a, b) }
                    delay(20)
                    inFlight.decrementAndGet()
                    respond("{}", HttpStatusCode.OK, headersOf(HttpHeaders.ContentType, "application/json"))
                }
            }
            val client = DefenderClient(testConfig().copy(maxConcurrentRequests = 2), engine)
            val results = coroutineScope {
                (1..12).map { async(Dispatchers.Default) { client.get("/api/machines").status } }.awaitAll()
            }
            results.toSet() shouldBe setOf(200)
            peak.get() shouldBeLessThanOrEqual 2
        }
    }

    context("default sleep") {
        test("retry waits use coroutine delay (virtual time under runTest)") {
            runTest {
                val fake = FakeDefender(api = statuses(503, 429, 200, headers = mapOf(HttpHeaders.RetryAfter to "4")))
                val client = DefenderClient(testConfig(), fake.engine)
                client.get("/api/machines").status shouldBe 200
                currentTime shouldBe 1_000 + 4_000
                fake.apiRequests shouldHaveSize 3
            }
        }
    }

    context("close") {
        test("close is safe to call repeatedly and works with use {}") {
            // Note: an externally supplied engine (MockEngine here) is not owned by the HttpClient, so
            // requests after close() are not guaranteed to fail; only the owned OkHttp engine is shut down.
            val fake = FakeDefender()
            fake.client().use { it.get("/api/machines").status shouldBe 200 }
            val client = fake.client()
            client.close()
            client.close()
            fake.apiRequests shouldHaveSize 1
        }
    }

    context("companion helpers") {
        test("retryAfterMillis parses seconds and falls back to backoff") {
            DefenderClient.retryAfterMillis("5", 0) shouldBe 5_000
            DefenderClient.retryAfterMillis(" 7 ", 3) shouldBe 7_000
            DefenderClient.retryAfterMillis("0", 0) shouldBe 0
            DefenderClient.retryAfterMillis(null, 0) shouldBe 1_000
            DefenderClient.retryAfterMillis(null, 1) shouldBe 2_000
            DefenderClient.retryAfterMillis("-1", 1) shouldBe 2_000
            DefenderClient.retryAfterMillis("abc", 2) shouldBe 4_000
            DefenderClient.retryAfterMillis("Wed, 21 Oct 2026 07:28:00 GMT", 0) shouldBe 1_000
            DefenderClient.retryAfterMillis("1.5", 0) shouldBe 1_000
        }

        test("backoffMillis doubles from one second and caps at 32 seconds") {
            listOf(-5 to 1_000L, 0 to 1_000L, 1 to 1_000L, 2 to 2_000L, 3 to 4_000L, 6 to 32_000L, 7 to 32_000L, 1_000 to 32_000L)
                .forEach { (attempt, expected) -> DefenderClient.backoffMillis(attempt) shouldBe expected }
        }

        test("backoffMillis is always a bounded power-of-two multiple of a second (property)") {
            checkAll(Arb.int()) { attempt ->
                val b = DefenderClient.backoffMillis(attempt)
                b shouldBeInRange 1_000L..32_000L
                (b / 1_000).countOneBits() shouldBe 1
            }
        }

        test("readCapped returns everything under the cap") {
            DefenderClient.readCapped(ByteReadChannel(ByteArray(0)), 10).let { (b, t) -> b.size shouldBe 0; t.shouldBeFalse() }
            DefenderClient.readCapped(ByteReadChannel("hello".toByteArray()), 10).let { (b, t) ->
                b.decodeToString() shouldBe "hello"; t.shouldBeFalse()
            }
            DefenderClient.readCapped(ByteReadChannel("0123456789".toByteArray()), 10).let { (b, t) ->
                b.decodeToString() shouldBe "0123456789"; t.shouldBeFalse()
            }
        }

        test("readCapped stops at the cap and flags more data") {
            DefenderClient.readCapped(ByteReadChannel("0123456789ABC".toByteArray()), 10).let { (b, t) ->
                b.decodeToString() shouldBe "0123456789"; t.shouldBeTrue()
            }
            val big = ByteArray(100_000) { 'x'.code.toByte() }
            DefenderClient.readCapped(ByteReadChannel(big), 40_000).let { (b, t) -> b.size shouldBe 40_000; t.shouldBeTrue() }
        }

        test("readCapped detects data arriving after exactly the cap was read") {
            runTest {
                val channel = ByteChannel()
                launch {
                    channel.writeFully("0123456789".toByteArray())
                    channel.flush()
                    yield()
                    yield()
                    channel.writeFully("more".toByteArray())
                    channel.flush()
                    channel.flushAndClose()
                }
                val (bytes, truncated) = DefenderClient.readCapped(channel, 10)
                bytes.decodeToString() shouldBe "0123456789"
                truncated.shouldBeTrue()
            }
        }

        test("readCapped with a stream that ends exactly at the cap after chunks is not flagged") {
            runTest {
                val channel = ByteChannel()
                launch {
                    channel.writeFully("01234".toByteArray())
                    channel.flush()
                    yield()
                    channel.writeFully("56789".toByteArray())
                    channel.flush()
                    yield()
                    channel.flushAndClose()
                }
                val (bytes, truncated) = DefenderClient.readCapped(channel, 10)
                bytes.decodeToString() shouldBe "0123456789"
                truncated.shouldBeFalse()
            }
        }

        test("trimIncompleteUtf8 keeps complete text and drops a split trailing character") {
            fun trim(vararg b: Int) = DefenderClient.trimIncompleteUtf8(ByteArray(b.size) { b[it].toByte() }).map { it.toInt() and 0xFF }
            trim() shouldBe emptyList()
            trim(0x41, 0x42) shouldBe listOf(0x41, 0x42)
            // Complete 2, 3 and 4 byte sequences are kept.
            trim(0x41, 0xC3, 0xA9) shouldBe listOf(0x41, 0xC3, 0xA9)
            trim(0xE2, 0x82, 0xAC) shouldBe listOf(0xE2, 0x82, 0xAC)
            trim(0xF0, 0x9F, 0x98, 0x80) shouldBe listOf(0xF0, 0x9F, 0x98, 0x80)
            // Split sequences are dropped back to the lead byte.
            trim(0x41, 0xC3) shouldBe listOf(0x41)
            trim(0x41, 0xE2, 0x82) shouldBe listOf(0x41)
            trim(0x41, 0xE2) shouldBe listOf(0x41)
            trim(0x41, 0xF0, 0x9F, 0x98) shouldBe listOf(0x41)
            trim(0xF0, 0x9F) shouldBe emptyList()
            // Invalid input is left alone rather than mangled further.
            trim(0x80, 0x80) shouldBe listOf(0x80, 0x80)
            trim(0x41, 0x80, 0x80, 0x80, 0x80, 0x80) shouldBe listOf(0x41, 0x80, 0x80, 0x80, 0x80, 0x80)
            trim(0x41, 0xFF, 0x80) shouldBe listOf(0x41, 0xFF, 0x80)
            trim(0x41, 0xF8) shouldBe listOf(0x41, 0xF8)
        }

        test("any UTF-8 text cut at any byte trims to a strictly valid prefix (property)") {
            val pieces = Arb.element("a", "Z", "é", "€", "中", "😀", "\n")
            checkAll(300, Arb.list(pieces, 0..40), Arb.int(0..1_000)) { parts, cutSeed ->
                val bytes = parts.joinToString("").toByteArray(Charsets.UTF_8)
                val cut = if (bytes.isEmpty()) 0 else cutSeed % (bytes.size + 1)
                val trimmed = DefenderClient.trimIncompleteUtf8(bytes.copyOf(cut))
                (trimmed.size <= cut).shouldBeTrue()
                (cut - trimmed.size <= 3).shouldBeTrue()
                trimmed.contentEquals(bytes.copyOf(trimmed.size)).shouldBeTrue()
                strictUtf8(trimmed).toByteArray(Charsets.UTF_8).contentEquals(trimmed).shouldBeTrue()
            }
        }
    }
})
