package com.jitunicornfx.defender.mcp.tools

import com.jitunicornfx.defender.mcp.AccessLevel
import com.jitunicornfx.defender.mcp.ToolRegistry
import com.jitunicornfx.defender.mcp.Validators
import com.jitunicornfx.defender.mcp.testutil.Canned
import com.jitunicornfx.defender.mcp.testutil.FakeDefender
import com.jitunicornfx.defender.mcp.testutil.MACHINE_ID
import com.jitunicornfx.defender.mcp.testutil.ToolHarness
import com.jitunicornfx.defender.mcp.testutil.failed
import com.jitunicornfx.defender.mcp.testutil.testConfig
import com.jitunicornfx.defender.mcp.testutil.text
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldContainAll
import io.kotest.matchers.collections.shouldContainExactlyInAnyOrder
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.ints.shouldBeGreaterThanOrEqual
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotContain
import io.ktor.client.request.HttpRequestData
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import java.util.concurrent.atomic.AtomicInteger

private val SHA1 = "3395856ce81f2b7382dee72602f798b642f14140"
private val SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
private const val ALERT_ID = "da637472900382838869_1364969609"

private fun harness(
    access: AccessLevel = AccessLevel.READ_ONLY,
    api: (HttpRequestData) -> Canned = { Canned(body = """{"value":[]}""") },
) = ToolHarness(config = testConfig(access = access), fake = FakeDefender(api = api))

private fun ToolHarness.param(name: String): String? = fake.last.request.url.parameters[name]

private val TOKEN = Regex("page_token=\"([A-Za-z0-9_-]{32})\"")

class AlertFileToolsSpec : FunSpec({

    context("defender_list_alerts") {
        test("defaults: GET /api/alerts with \$top=50, no filter and no evidence expansion") {
            val h = harness()
            h.call(AlertFileTools.listAlerts).failed shouldBe false
            h.fake.last.request.method shouldBe HttpMethod.Get
            h.fake.last.path shouldBe "/api/alerts"
            h.param("\$top") shouldBe "50"
            h.param("\$filter").shouldBeNull()
            h.param("\$expand").shouldBeNull()
            h.param("\$skip").shouldBeNull()
        }

        test("every structured filter is ANDed in order, enums canonicalised and the time normalised to UTC") {
            val h = harness()
            h.call(
                AlertFileTools.listAlerts,
                "status" to "inprogress",
                "severity" to "HIGH",
                "category" to "CredentialAccess",
                "detection_source" to "WindowsDefenderAv",
                "created_after" to "2026-11-01T00:00:00+02:00",
                "top" to 5,
                "skip" to 10,
            ).failed shouldBe false
            h.param("\$filter") shouldBe "status eq 'InProgress' and severity eq 'High' and category eq 'CredentialAccess' and " +
                "detectionSource eq 'WindowsDefenderAv' and alertCreationTime ge 2026-10-31T22:00:00Z"
            h.param("\$top") shouldBe "5"
            h.param("\$skip") shouldBe "10"
        }

        test("a raw filter is validated against the alert fields and ANDed in parentheses") {
            val h = harness()
            h.call(AlertFileTools.listAlerts, "status" to "New", "filter" to "assignedTo eq 'secops@contoso.com'").failed shouldBe false
            h.param("\$filter") shouldBe "status eq 'New' and (assignedTo eq 'secops@contoso.com')"
        }

        test("include_evidence adds \$expand=evidence; false does not") {
            val h = harness()
            h.call(AlertFileTools.listAlerts, "include_evidence" to true).failed shouldBe false
            h.param("\$expand") shouldBe "evidence"
            h.call(AlertFileTools.listAlerts, "include_evidence" to false).failed shouldBe false
            h.param("\$expand").shouldBeNull()
        }

        test("invalid input is refused before any request") {
            listOf(
                arrayOf<Pair<String, Any?>>("status" to "Closed"),
                arrayOf<Pair<String, Any?>>("severity" to "Critical"),
                arrayOf<Pair<String, Any?>>("category" to "Execution' or 1 eq 1"),
                arrayOf<Pair<String, Any?>>("detection_source" to "Windows Defender"),
                arrayOf<Pair<String, Any?>>("created_after" to "yesterday"),
                arrayOf<Pair<String, Any?>>("filter" to "machineId eq 'x'"),
                arrayOf<Pair<String, Any?>>("top" to 0),
                arrayOf<Pair<String, Any?>>("unexpected" to "x"),
            ).forEach { args ->
                val h = harness()
                h.call(AlertFileTools.listAlerts, *args).failed shouldBe true
                h.fake.apiRequests.shouldBeEmpty()
            }
        }

        test("page_token continues verbatim from the nextLink, never re-adds \$expand, and is exclusive of every filter") {
            val next = "https://api.security.microsoft.com/api/alerts?\$expand=evidence&\$skiptoken=p2"
            val h = harness(api = { req ->
                if (req.url.parameters["\$skiptoken"] == "p2") Canned(body = """{"value":[{"id":"a2"}]}""")
                else Canned(body = """{"value":[{"id":"a1"}],"@odata.nextLink":"$next"}""")
            })
            val first = h.call(AlertFileTools.listAlerts, "include_evidence" to true, "severity" to "High").text()
            h.param("\$expand") shouldBe "evidence"
            first shouldNotContain "skiptoken"
            val token = TOKEN.find(first)!!.groupValues[1]

            listOf<Pair<String, Any?>>(
                "include_evidence" to true,
                "include_evidence" to false,
                "status" to "New",
                "top" to 10,
                "filter" to "status eq 'New'",
            ).forEach { extra ->
                val before = h.fake.apiRequests.size
                val r = h.call(AlertFileTools.listAlerts, "page_token" to token, extra)
                r.failed shouldBe true
                r.text() shouldContain "cannot be combined with ${extra.first}"
                h.fake.apiRequests.size shouldBe before
            }

            val second = h.call(AlertFileTools.listAlerts, "page_token" to token, "max_pages" to 1)
            second.failed shouldBe false
            second.text() shouldContain "a2"
            h.fake.last.url shouldBe next
            h.fake.last.request.url.parameters.getAll("\$expand") shouldBe listOf("evidence")
        }
    }

    context("defender_get_alert") {
        test("GETs /api/alerts/{id}") {
            val h = harness(api = { Canned(body = """{"id":"$ALERT_ID","title":"Suspicious PowerShell"}""") })
            val r = h.call(AlertFileTools.getAlert, "alert_id" to ALERT_ID)
            r.failed shouldBe false
            r.text() shouldContain "Suspicious PowerShell"
            h.fake.last.path shouldBe "/api/alerts/$ALERT_ID"
        }

        test("an id that could traverse the path is refused before any request") {
            listOf("../machines", "a/b", "a b", "x".repeat(129), "").forEach { bad ->
                val h = harness()
                h.call(AlertFileTools.getAlert, "alert_id" to bad).failed shouldBe true
                h.fake.apiRequests.shouldBeEmpty()
            }
        }
    }

    context("defender_get_alert_entities") {
        val sections = listOf("machine", "user", "files", "ips", "domains")

        test("fans out to the five sub-resources, labelled under the alert id") {
            val h = harness(api = { req ->
                when (req.url.encodedPath.substringAfterLast('/')) {
                    "machine" -> Canned(body = """{"id":"$MACHINE_ID","computerDnsName":"ws-042"}""")
                    "user" -> Canned(body = """{"id":"contoso\\jdoe","accountName":"jdoe"}""")
                    "files" -> Canned(body = """{"value":[{"sha1":"$SHA1"}]}""")
                    "ips" -> Canned(body = """{"value":[{"id":"203.0.113.7"}]}""")
                    else -> Canned(body = """{"value":[{"host":"evil.example"}]}""")
                }
            })
            val r = h.call(AlertFileTools.getAlertEntities, "alert_id" to ALERT_ID)
            r.failed shouldBe false
            h.fake.apiRequests.map { it.path } shouldContainExactlyInAnyOrder sections.map { "/api/alerts/$ALERT_ID/$it" }
            h.fake.apiRequests.all { it.request.method == HttpMethod.Get } shouldBe true
            val t = r.text()
            listOf("alertId", ALERT_ID, "ws-042", "jdoe", SHA1, "203.0.113.7", "evil.example").forEach { t shouldContain it }
        }

        test("requests are issued concurrently") {
            val inFlight = AtomicInteger()
            val peak = AtomicInteger()
            val h = harness(api = {
                val now = inFlight.incrementAndGet()
                peak.accumulateAndGet(now) { a, b -> maxOf(a, b) }
                Thread.sleep(150)
                inFlight.decrementAndGet()
                Canned(body = """{"value":[]}""")
            })
            h.call(AlertFileTools.getAlertEntities, "alert_id" to ALERT_ID).failed shouldBe false
            h.fake.apiRequests shouldHaveSize 5
            peak.get() shouldBeGreaterThanOrEqual 2
        }

        test("a failed section reports its own error without sinking the others") {
            val h = harness(api = { req ->
                when (req.url.encodedPath.substringAfterLast('/')) {
                    "user" -> Canned(HttpStatusCode.NotFound, "{}")
                    "ips" -> Canned(body = "not json")
                    "domains" -> Canned(HttpStatusCode.Forbidden, "{}")
                    else -> Canned(body = """{"value":[{"id":"kept-${req.url.encodedPath.substringAfterLast('/')}"}]}""")
                }
            })
            val r = h.call(AlertFileTools.getAlertEntities, "alert_id" to ALERT_ID)
            r.failed shouldBe false
            val t = r.text()
            t shouldContain "HTTP 404"
            t shouldContain "HTTP 403"
            t shouldContain "response was not JSON"
            t shouldContain "kept-machine"
            t shouldContain "kept-files"
        }

        test("max_items caps each list section; out-of-range values and bad ids are refused before any request") {
            val many = (1..6).joinToString(",") { """{"id":"f$it"}""" }
            val h = harness(api = { Canned(body = """{"value":[$many]}""") })
            val t = h.call(AlertFileTools.getAlertEntities, "alert_id" to ALERT_ID, "max_items" to 2).text()
            t shouldContain "Only the first 2 items"
            t shouldNotContain "\"f3\""

            listOf<Pair<String, Any?>>("max_items" to 0, "max_items" to TriageTools.MAX_ITEMS + 1).forEach { bad ->
                val b = harness()
                b.call(AlertFileTools.getAlertEntities, "alert_id" to ALERT_ID, bad).failed shouldBe true
                b.fake.apiRequests.shouldBeEmpty()
            }
            val b = harness()
            b.call(AlertFileTools.getAlertEntities, "alert_id" to "../x").failed shouldBe true
            b.fake.apiRequests.shouldBeEmpty()
        }
    }

    context("defender_get_file and defender_get_file_stats") {
        test("get_file accepts SHA-1 and SHA-256, lowercased into the path") {
            val h = harness(api = { Canned(body = """{"sha1":"$SHA1","signer":"Fabrikam"}""") })
            h.call(AlertFileTools.getFile, "file_hash" to SHA1.uppercase()).failed shouldBe false
            h.fake.last.path shouldBe "/api/files/$SHA1"
            h.call(AlertFileTools.getFile, "file_hash" to " $SHA256 ").failed shouldBe false
            h.fake.last.path shouldBe "/api/files/$SHA256"
        }

        test("other hashes and non-hex are refused before any request") {
            listOf(
                "d41d8cd98f00b204e9800998ecf8427e", // MD5
                SHA1 + "0", // 41 hex
                SHA256.dropLast(1), // 63 hex
                "g".repeat(40),
                "../" + SHA1.drop(3),
                "",
            ).forEach { bad ->
                listOf(AlertFileTools.getFile, AlertFileTools.getFileStats).forEach { spec ->
                    val h = harness()
                    val r = h.call(spec, "file_hash" to bad)
                    r.failed shouldBe true
                    h.fake.apiRequests.shouldBeEmpty()
                }
            }
        }

        test("Validators.fileHash names the field and lowercases") {
            Validators.fileHash(SHA256.uppercase()) shouldBe SHA256
            shouldThrow<IllegalArgumentException> { Validators.fileHash("abc", "hash") }.message shouldContain "hash must be a SHA-1"
        }

        test("get_file_stats GETs /stats, with lookBackHours only when given") {
            val h = harness(api = { Canned(body = """{"orgPrevalence":"3"}""") })
            h.call(AlertFileTools.getFileStats, "file_hash" to SHA1).failed shouldBe false
            h.fake.last.path shouldBe "/api/files/$SHA1/stats"
            h.param("lookBackHours").shouldBeNull()
            h.call(AlertFileTools.getFileStats, "file_hash" to SHA256, "look_back_hours" to 48).failed shouldBe false
            h.fake.last.path shouldBe "/api/files/$SHA256/stats"
            h.param("lookBackHours") shouldBe "48"
        }

        test("get_file_stats refuses an out-of-range lookback before any request") {
            listOf(0, -1, IndicatorTools.MAX_LOOKBACK_HOURS + 1).forEach { hours ->
                val h = harness()
                h.call(AlertFileTools.getFileStats, "file_hash" to SHA1, "look_back_hours" to hours).failed shouldBe true
                h.fake.apiRequests.shouldBeEmpty()
            }
        }
    }

    context("defender_get_device_av_health") {
        test("defaults to \$top=50 without a filter") {
            val h = harness()
            h.call(AlertFileTools.getDeviceAvHealth).failed shouldBe false
            h.fake.last.path shouldBe "/api/deviceavinfo"
            h.param("\$top") shouldBe "50"
            h.param("\$filter").shouldBeNull()
        }

        test("machine_id becomes a quoted, lowercased machineId filter; top is honoured") {
            val h = harness()
            h.call(AlertFileTools.getDeviceAvHealth, "machine_id" to MACHINE_ID.uppercase(), "top" to 10).failed shouldBe false
            h.param("\$filter") shouldBe "machineId eq '$MACHINE_ID'"
            h.param("\$top") shouldBe "10"
        }

        test("invalid machine_id or top is refused before any request") {
            listOf<Pair<String, Any?>>("machine_id" to "x' or 1 eq 1", "top" to 0, "top" to MAX_TOP + 1).forEach { bad ->
                val h = harness()
                h.call(AlertFileTools.getDeviceAvHealth, bad).failed shouldBe true
                h.fake.apiRequests.shouldBeEmpty()
            }
        }

        test("page_token continues from the verbatim nextLink without re-adding \$top or the filter") {
            val next = "https://api.security.microsoft.com/api/deviceavinfo?\$filter=machineId+eq+%27$MACHINE_ID%27&\$skiptoken=n2"
            val h = harness(api = { req ->
                if (req.url.parameters["\$skiptoken"] == "n2") Canned(body = """{"value":[{"id":"row-2"}]}""")
                else Canned(body = """{"value":[{"id":"row-1"}],"@odata.nextLink":"$next"}""")
            })
            val first = h.call(AlertFileTools.getDeviceAvHealth, "machine_id" to MACHINE_ID, "top" to 1).text()
            val token = TOKEN.find(first)!!.groupValues[1]
            val second = h.call(AlertFileTools.getDeviceAvHealth, "page_token" to token, "max_pages" to 1)
            second.failed shouldBe false
            second.text() shouldContain "row-2"
            h.param("\$skiptoken") shouldBe "n2"
            h.param("\$top").shouldBeNull()
            h.fake.last.request.url.parameters.getAll("\$filter") shouldBe listOf("machineId eq '$MACHINE_ID'")
        }

        // Regression: machine_id is a query filter, not part of the path, so the pager's listing binding cannot see it. A page_token
        // issued for device A, replayed with machine_id = device B, silently returns device A's records as if they were B's
        // (top is likewise silently ignored). Correct behaviour: refuse the mismatch (or any extra filter argument, as the
        // OData list tools do) before making a request.
        test("page_token with a different machine_id is refused rather than returning another device's records") {
                val other = "f".repeat(40)
                val next = "https://api.security.microsoft.com/api/deviceavinfo?\$skiptoken=n2"
                val h = harness(api = { req ->
                    if (req.url.parameters["\$skiptoken"] == "n2") Canned(body = """{"value":[{"machineId":"$MACHINE_ID"}]}""")
                    else Canned(body = """{"value":[{"machineId":"$MACHINE_ID"}],"@odata.nextLink":"$next"}""")
                })
                val token = TOKEN.find(h.call(AlertFileTools.getDeviceAvHealth, "machine_id" to MACHINE_ID).text())!!.groupValues[1]
                val before = h.fake.apiRequests.size
                val r = h.call(AlertFileTools.getDeviceAvHealth, "page_token" to token, "machine_id" to other)
                r.failed shouldBe true
                h.fake.apiRequests.size shouldBe before
            }
    }

    context("registration") {
        test("all six tools are read-only, need no approval, and are available at every access level") {
            AlertFileTools.all shouldHaveSize 6
            AlertFileTools.all.forEach {
                it.access shouldBe AccessLevel.READ_ONLY
                it.confirm shouldBe false
                it.destructive shouldBe false
            }
            AccessLevel.entries.forEach { level ->
                ToolRegistry.select(testConfig(access = level)).map { it.name } shouldContainAll AlertFileTools.all.map { it.name }
            }
        }
    }
})
