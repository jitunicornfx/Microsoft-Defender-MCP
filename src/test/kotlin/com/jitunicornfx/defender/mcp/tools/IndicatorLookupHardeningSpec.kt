package com.jitunicornfx.defender.mcp.tools

import com.jitunicornfx.defender.mcp.AccessLevel
import com.jitunicornfx.defender.mcp.ConfirmationMode
import com.jitunicornfx.defender.mcp.testutil.Canned
import com.jitunicornfx.defender.mcp.testutil.FakeDefender
import com.jitunicornfx.defender.mcp.testutil.ToolHarness
import com.jitunicornfx.defender.mcp.testutil.failed
import com.jitunicornfx.defender.mcp.testutil.testConfig
import com.jitunicornfx.defender.mcp.testutil.text
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.ktor.client.request.HttpRequestData
import io.ktor.http.HttpMethod
import java.time.Instant
import java.time.temporal.ChronoUnit

/**
 * Regression tests: the existing-indicator check must not trust the server-side filter. An ignored filter,
 * a case difference or an incomplete answer must never let a WRITE-level submit silently overwrite a Block.
 */
class IndicatorLookupHardeningSpec : FunSpec({
    val hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    val expires = Instant.now().plus(30, ChronoUnit.DAYS).toString()

    fun harness(lookup: (HttpRequestData) -> Canned): ToolHarness {
        val config = testConfig(access = AccessLevel.WRITE, confirmation = ConfirmationMode.NONE)
        return ToolHarness(
            config = config,
            fake = FakeDefender(api = { req -> if (req.method == HttpMethod.Get) lookup(req) else Canned(body = """{"id":"9"}""") }),
        )
    }

    suspend fun ToolHarness.audit() = call(
        CustomIndicatorTools.submitIndicator,
        "indicator_value" to hash, "indicator_type" to "FileSha256", "action" to "Audit",
        "title" to "t", "description" to "Alert 1234 follow-up", "expiration_time" to expires,
    )

    fun ToolHarness.posts() = fake.apiRequests.filter { it.request.method == HttpMethod.Post }

    test("an existing Block stored in uppercase is still found, so the downgrade is refused") {
        val h = harness { Canned(body = """{"value":[{"indicatorValue":"${hash.uppercase()}","indicatorType":"FileSha256","action":"Block"}]}""") }
        val r = h.audit()
        r.failed shouldBe true
        r.text() shouldContain "destructive access level"
        h.posts().shouldBeEmpty()
    }

    test("if the API ignores the filter, unrelated indicators are not mistaken for this value") {
        val h = harness {
            Canned(body = """{"value":[{"indicatorValue":"other.example","indicatorType":"DomainName","action":"Block"},{"indicatorValue":"${"a".repeat(64)}","indicatorType":"FileSha256","action":"Block"}]}""")
        }
        h.audit().failed shouldBe false
        h.posts().size shouldBe 1
    }

    test("an answer with more pages is incomplete and refused") {
        val h = harness { Canned(body = """{"value":[],"@odata.nextLink":"https://api.security.microsoft.com/api/indicators?${'$'}skip=100"}""") }
        val r = h.audit()
        r.failed shouldBe true
        r.text() shouldContain "could not be checked"
        h.posts().shouldBeEmpty()
    }

    test("a full page (100 records) is incomplete and refused, even without a nextLink") {
        val many = (1..CustomIndicatorTools.EXISTING_PAGE).joinToString(",") { """{"indicatorValue":"x$it.example","indicatorType":"DomainName","action":"Audit"}""" }
        val h = harness { Canned(body = """{"value":[$many]}""") }
        h.audit().failed shouldBe true
        h.posts().shouldBeEmpty()
    }
})
