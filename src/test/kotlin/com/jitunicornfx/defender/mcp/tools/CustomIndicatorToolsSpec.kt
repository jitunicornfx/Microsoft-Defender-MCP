package com.jitunicornfx.defender.mcp.tools

import com.jitunicornfx.defender.mcp.AccessLevel
import com.jitunicornfx.defender.mcp.ActionBudget
import com.jitunicornfx.defender.mcp.ActionGate
import com.jitunicornfx.defender.mcp.ApprovalOutcome
import com.jitunicornfx.defender.mcp.Config
import com.jitunicornfx.defender.mcp.ConfirmationMode
import com.jitunicornfx.defender.mcp.ResponseRenderer
import com.jitunicornfx.defender.mcp.ToolContext
import com.jitunicornfx.defender.mcp.ToolRegistry
import com.jitunicornfx.defender.mcp.ToolSpec
import com.jitunicornfx.defender.mcp.invokeTool
import com.jitunicornfx.defender.mcp.testutil.Canned
import com.jitunicornfx.defender.mcp.testutil.FakeDefender
import com.jitunicornfx.defender.mcp.testutil.FixedApprover
import com.jitunicornfx.defender.mcp.testutil.ListAudit
import com.jitunicornfx.defender.mcp.testutil.Recorded
import com.jitunicornfx.defender.mcp.testutil.failed
import com.jitunicornfx.defender.mcp.testutil.jsonArgs
import com.jitunicornfx.defender.mcp.testutil.testConfig
import com.jitunicornfx.defender.mcp.testutil.text
import io.kotest.core.spec.style.FunSpec
import io.kotest.datatest.withData
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.collections.shouldContainExactly
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.collections.shouldNotContain
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotContain
import io.ktor.client.request.HttpRequestData
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.time.temporal.ChronoUnit

private const val SHA1 = "3395856ce81f2b7382dee72602f798b642f14140"
private const val SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
private const val MD5 = "d41d8cd98f00b204e9800998ecf8427e"
private const val EMPTY_LOOKUP = """{"value":[]}"""

private fun future(days: Long = 30): Instant = Instant.now().plus(Duration.ofDays(days)).truncatedTo(ChronoUnit.SECONDS)
private fun iso(i: Instant): String = DateTimeFormatter.ISO_INSTANT.format(i)

/** Routes indicator lookups (GET), creations (POST) and deletions (DELETE) separately. */
private class IocRig(
    access: AccessLevel = AccessLevel.DESTRUCTIVE,
    outcome: ApprovalOutcome = ApprovalOutcome.APPROVED,
    tenantAccess: AccessLevel? = null,
    confirmation: ConfirmationMode = ConfirmationMode.ELICIT,
) {
    var lookup: (HttpRequestData) -> Canned = { Canned(body = EMPTY_LOOKUP) }
    var post: (HttpRequestData) -> Canned = { Canned(body = """{"id":"5","indicatorValue":"x"}""") }
    var delete: (HttpRequestData) -> Canned = { Canned(HttpStatusCode.NoContent, "") }

    val config: Config = testConfig(access = access, confirmation = confirmation).copy(tenantAccessLevel = tenantAccess)
    val fake = FakeDefender(
        api = { req ->
            when (req.method) {
                HttpMethod.Post -> post(req)
                HttpMethod.Delete -> delete(req)
                else -> withRequestedValue(req, lookup(req))
            }
        },
    )

    /**
     * Fixtures list existing indicators without repeating their value. A real API returns it, and the server
     * now keeps only exact matches, so fill in the value the existence check asked for wherever it is missing.
     */
    private fun withRequestedValue(req: HttpRequestData, canned: Canned): Canned {
        val filter = req.url.parameters["\$filter"] ?: return canned
        val value = Regex("^indicatorValue eq '((?:[^']|'')*)'$").find(filter)?.groupValues?.get(1)?.replace("''", "'") ?: return canned
        val json = runCatching { kotlinx.serialization.json.Json.parseToJsonElement(canned.body) as? kotlinx.serialization.json.JsonObject }.getOrNull()
            ?: return canned
        val items = json["value"] as? kotlinx.serialization.json.JsonArray ?: return canned
        val filled = items.map { item ->
            val obj = item as? kotlinx.serialization.json.JsonObject ?: return@map item
            if (obj.containsKey("indicatorValue")) obj
            else kotlinx.serialization.json.JsonObject(obj + ("indicatorValue" to kotlinx.serialization.json.JsonPrimitive(value)))
        }
        val out = kotlinx.serialization.json.JsonObject(json + ("value" to kotlinx.serialization.json.JsonArray(filled)))
        return canned.copy(body = out.toString())
    }
    val approver = FixedApprover(outcome)
    val audit = ListAudit()
    val gate = ActionGate(config.confirmation, ActionBudget(config.maxActionsPerHour), audit)
    val context = ToolContext(config, fake.client(config), ResponseRenderer(config.maxResultChars), gate)

    suspend fun call(spec: ToolSpec, vararg args: Pair<String, Any?>) = invokeTool(spec, jsonArgs(*args), context, approver)

    suspend fun submit(
        value: String = SHA256,
        type: String = "FileSha256",
        action: String = "Audit",
        expiration: String = iso(future()),
        title: String = "Loader seen in INC-4411",
        description: String = "Alert da638: staged payload",
        extra: List<Pair<String, Any?>> = emptyList(),
    ) = call(
        CustomIndicatorTools.submitIndicator,
        "indicator_value" to value,
        "indicator_type" to type,
        "action" to action,
        "title" to title,
        "description" to description,
        "expiration_time" to expiration,
        *extra.toTypedArray(),
    )

    suspend fun delete(id: String = "42", comment: String = "False positive, ticket INC-9") =
        call(CustomIndicatorTools.deleteIndicator, "indicator_id" to id, "comment" to comment)

    val writes: List<Recorded> get() = fake.apiRequests.filter { it.request.method != HttpMethod.Get }
    val gets: List<Recorded> get() = fake.apiRequests.filter { it.request.method == HttpMethod.Get }
    val message: String get() = approver.lastMessage.shouldNotBeNull()

    /** Assert the call was refused before any write reached the API (and, by default, before any request at all). */
    fun assertNothingSent(anyRequest: Boolean = false) {
        writes.shouldBeEmpty()
        if (!anyRequest) fake.recorded.shouldBeEmpty()
    }
}

private fun Recorded.body(): JsonObject = bodyJson().jsonObject
private fun Recorded.param(name: String): String? = request.url.parameters[name]

class CustomIndicatorToolsSpec : FunSpec({

    context("tool definitions and registration") {
        test("three tools with the documented tiers and annotations") {
            CustomIndicatorTools.all.map { it.name } shouldContainExactly listOf(
                "defender_list_indicators", "defender_submit_indicator", "defender_delete_indicator",
            )
            with(CustomIndicatorTools.listIndicators) {
                access shouldBe AccessLevel.READ_ONLY
                confirm shouldBe false
                readOnly shouldBe true
                definition().annotations?.readOnlyHint shouldBe true
            }
            with(CustomIndicatorTools.submitIndicator) {
                access shouldBe AccessLevel.WRITE
                confirm shouldBe true
                readOnly shouldBe false
                definition().annotations?.destructiveHint shouldBe true
                definition().annotations?.idempotentHint shouldBe true
                definition().inputSchema.required!!.toSet() shouldBe setOf(
                    "indicator_value", "indicator_type", "action", "title", "description", "expiration_time",
                )
            }
            with(CustomIndicatorTools.deleteIndicator) {
                access shouldBe AccessLevel.DESTRUCTIVE
                confirm shouldBe true
                definition().annotations?.destructiveHint shouldBe true
                definition().inputSchema.properties!!["indicator_id"]!!.jsonObject["pattern"]!!.jsonPrimitive.content shouldBe "^[0-9]{1,20}$"
            }
        }

        test("the action enum offers no retired or unknown actions, and every type has a matrix entry") {
            val actions = CustomIndicatorTools.submitIndicator.definition().inputSchema.properties!!["action"]!!.jsonObject["enum"]!!.jsonArray
            actions.map { it.jsonPrimitive.content } shouldContainExactly CustomIndicatorTools.ACTIONS
            actions.map { it.jsonPrimitive.content } shouldNotContain "AlertAndBlock"
            CustomIndicatorTools.ACTIONS_BY_TYPE.keys shouldBe CustomIndicatorTools.TYPES.toSet()
            CustomIndicatorTools.DESTRUCTIVE_ACTIONS shouldBe setOf("Block", "BlockAndRemediate", "Allowed")
        }

        test("read-only exposes only the listing; write adds submit; destructive adds delete") {
            val ro = ToolRegistry.select(testConfig()).map { it.name }
            ro shouldContain "defender_list_indicators"
            ro shouldNotContain "defender_submit_indicator"
            ro shouldNotContain "defender_delete_indicator"
            val w = ToolRegistry.select(testConfig(access = AccessLevel.WRITE)).map { it.name }
            w shouldContain "defender_submit_indicator"
            w shouldNotContain "defender_delete_indicator"
            val d = ToolRegistry.select(testConfig(access = AccessLevel.DESTRUCTIVE)).map { it.name }
            d shouldContain "defender_submit_indicator"
            d shouldContain "defender_delete_indicator"
        }

        test("read-only servers refuse submit and delete without any request") {
            val r = IocRig(access = AccessLevel.READ_ONLY)
            r.submit().failed shouldBe true
            r.delete().failed shouldBe true
            r.approver.asked shouldBe 0
            r.assertNothingSent()
        }
    }

    context("defender_list_indicators") {
        test("no arguments: GET /api/indicators with the default page size and no filter") {
            val r = IocRig()
            r.call(CustomIndicatorTools.listIndicators).failed shouldBe false
            r.fake.last.request.method shouldBe HttpMethod.Get
            r.fake.last.path shouldBe "/api/indicators"
            r.fake.last.param("\$top") shouldBe "50"
            r.fake.last.param("\$filter").shouldBeNull()
            r.approver.asked shouldBe 0
        }

        test("structured filters are quoted and ANDed (case-insensitive enums canonicalised)") {
            val r = IocRig()
            r.call(
                CustomIndicatorTools.listIndicators,
                "indicator_value" to "  evil.example' or 1 eq 1 ",
                "indicator_type" to "domainname",
                "action" to "block",
                "filter" to "severity eq 'High'",
            ).failed shouldBe false
            r.fake.last.param("\$filter") shouldBe
                "indicatorValue eq 'evil.example'' or 1 eq 1' and indicatorType eq 'DomainName' and action eq 'Block' and (severity eq 'High')"
        }

        test("raw filters on fields outside the allow-list are refused without a request") {
            val r = IocRig()
            r.call(CustomIndicatorTools.listIndicators, "filter" to "secret eq 'x'").failed shouldBe true
            r.call(CustomIndicatorTools.listIndicators, "action" to "Nuke").failed shouldBe true
            r.fake.recorded.shouldBeEmpty()
        }
    }

    context("defender_submit_indicator: happy paths and exact request bodies") {
        test("Audit at the write level: looks up first, shows 'create', then POSTs the exact body with generateAlert forced on") {
            val r = IocRig(access = AccessLevel.WRITE)
            val exp = future(10)
            val res = r.submit(
                value = SHA256.uppercase(),
                expiration = iso(exp),
                extra = listOf(
                    "severity" to "high",
                    "rbac_group_names" to listOf("Finance", " Finance ", "SOC lab"),
                    "generate_alert" to false,
                    "recommended_actions" to "Isolate and reimage",
                ),
            )
            res.failed shouldBe false
            r.gets shouldHaveSize 1
            r.gets.single().path shouldBe "/api/indicators"
            r.gets.single().param("\$filter") shouldBe "indicatorValue eq '$SHA256'"
            r.gets.single().param("\$top") shouldBe CustomIndicatorTools.EXISTING_PAGE.toString()
            r.writes shouldHaveSize 1
            val post = r.writes.single()
            post.request.method shouldBe HttpMethod.Post
            post.path shouldBe "/api/indicators"
            val body = post.body()
            body.keys shouldBe setOf(
                "indicatorValue", "indicatorType", "action", "title", "description", "expirationTime", "severity",
                "recommendedActions", "rbacGroupNames", "generateAlert",
            )
            body["indicatorValue"]!!.jsonPrimitive.content shouldBe SHA256
            body["indicatorType"]!!.jsonPrimitive.content shouldBe "FileSha256"
            body["action"]!!.jsonPrimitive.content shouldBe "Audit"
            body["title"]!!.jsonPrimitive.content shouldBe "Loader seen in INC-4411"
            body["description"]!!.jsonPrimitive.content shouldBe "Alert da638: staged payload"
            body["expirationTime"]!!.jsonPrimitive.content shouldBe iso(exp)
            body["severity"]!!.jsonPrimitive.content shouldBe "High"
            body["recommendedActions"]!!.jsonPrimitive.content shouldBe "Isolate and reimage"
            body["rbacGroupNames"]!!.jsonArray.map { it.jsonPrimitive.content } shouldContainExactly listOf("Finance", "SOC lab")
            body["generateAlert"]!!.jsonPrimitive.boolean shouldBe true // forced for Audit
            r.approver.asked shouldBe 1
            r.message shouldContain "Action: AUDIT FileSha256 indicator for '$SHA256' (scope: Finance, SOC lab; expires ${iso(exp)})"
            r.message shouldContain "- Existing FileSha256 indicator: \"none: this creates a new indicator\""
            r.message shouldNotContain "OVERWRITE the existing"
            r.message shouldNotContain "URL host"
            r.message shouldNotContain "OVERWRITTEN"
            r.message shouldNotContain "subdomain"
            r.audit.lines.single() shouldContain "defender_submit_indicator"
        }

        test("Warn without device groups: scope is ALL devices, optional fields are omitted, generateAlert defaults to false") {
            val r = IocRig(access = AccessLevel.WRITE)
            r.submit(value = "https://evil.example/drop.php?a=1", type = "Url", action = "Warn").failed shouldBe false
            r.message shouldContain "scope: ALL devices in the tenant"
            r.message shouldContain "- Scope (supplied by the AI): \"ALL devices in the tenant\""
            val body = r.writes.single().body()
            body.keys shouldNotContain "rbacGroupNames"
            body.keys shouldNotContain "severity"
            body.keys shouldNotContain "recommendedActions"
            body["generateAlert"]!!.jsonPrimitive.boolean shouldBe false
            body["indicatorValue"]!!.jsonPrimitive.content shouldBe "https://evil.example/drop.php?a=1"
            r.message shouldContain "- URL host: \"evil.example\""
        }

        test("Warn with generate_alert=true sends true") {
            val r = IocRig(access = AccessLevel.WRITE)
            r.submit(value = MD5, type = "FileMd5", action = "Warn", extra = listOf("generate_alert" to true)).failed shouldBe false
            r.writes.single().body()["generateAlert"]!!.jsonPrimitive.boolean shouldBe true
        }

        test("an expiration with an offset is sent as the equivalent UTC ISO instant") {
            val r = IocRig(access = AccessLevel.WRITE)
            val exp = future(5)
            val withOffset = exp.atOffset(ZoneOffset.ofHours(2)).format(DateTimeFormatter.ISO_OFFSET_DATE_TIME)
            r.submit(expiration = withOffset).failed shouldBe false
            r.writes.single().body()["expirationTime"]!!.jsonPrimitive.content shouldBe iso(exp)
        }

        test("an expiration exactly 365 days ahead (as sent) is accepted") {
            val r = IocRig(access = AccessLevel.WRITE)
            r.submit(expiration = iso(Instant.now().plus(Duration.ofDays(365)).truncatedTo(ChronoUnit.SECONDS))).failed shouldBe false
            r.writes shouldHaveSize 1
        }

        withData(
            nameFn = { "destructive tier allows ${it.first} ${it.second}" },
            Triple("Block", "IpAddress", "203.0.113.7"),
            Triple("Block", "DomainName", "evil.example"),
            Triple("BlockAndRemediate", "FileSha1", SHA1),
            Triple("BlockAndRemediate", "CertificateThumbprint", SHA1.uppercase()),
            Triple("Allowed", "FileSha256", SHA256),
            Triple("Allowed", "Url", "http://intranet.contoso.example/tool"),
        ) { (action, type, value) ->
            val r = IocRig(access = AccessLevel.DESTRUCTIVE)
            r.submit(value = value, type = type, action = action).failed shouldBe false
            val body = r.writes.single().body()
            body["action"]!!.jsonPrimitive.content shouldBe action
            body["indicatorType"]!!.jsonPrimitive.content shouldBe type
            r.message shouldContain "${action.uppercase()} $type indicator"
        }

        test("a full 8-segment IPv6 address is accepted and lowercased") {
            val r = IocRig()
            r.submit(value = "2001:DB8:0:0:0:0:0:1", type = "IpAddress", action = "Audit").failed shouldBe false
            r.writes.single().body()["indicatorValue"]!!.jsonPrimitive.content shouldBe "2001:db8:0:0:0:0:0:1"
        }

        test("a DomainName indicator is normalised and the approver is told it matches every subdomain") {
            val r = IocRig()
            r.submit(value = " Evil.Example. ", type = "DomainName", action = "Audit").failed shouldBe false
            r.writes.single().body()["indicatorValue"]!!.jsonPrimitive.content shouldBe "evil.example"
            r.message shouldContain "also matches every subdomain"
        }

        test("unattended confirmation mode still looks up first and posts once") {
            val r = IocRig(confirmation = ConfirmationMode.NONE)
            r.submit().failed shouldBe false
            r.approver.asked shouldBe 0
            r.gets shouldHaveSize 1
            r.writes shouldHaveSize 1
            r.audit.lines.single() shouldContain "approved_unattended"
        }

        test("an API error on the POST is rendered as an error") {
            val r = IocRig()
            r.post = { Canned(HttpStatusCode.BadRequest, """{"error":{"code":"InvalidRequestBody"}}""") }
            r.submit().failed shouldBe true
            r.writes shouldHaveSize 1
        }
    }

    context("defender_submit_indicator: create vs overwrite facts") {
        test("existing indicators are shown as OVERWRITTEN facts, at most three") {
            val r = IocRig()
            r.lookup = {
                Canned(
                    body = """{"value":[
                    {"indicatorType":"FileSha256","action":"Block","title":"Old block","expirationTime":"2027-01-01T00:00:00Z"},
                    {"indicatorType":"FileSha256","action":"Allowed","title":"Vendor tool"},
                    {"indicatorType":"FileSha256","action":"Audit","title":"  "},
                    {"indicatorType":"FileSha256","action":"Warn","title":"Fourth one"},
                    "not-an-object"
                ]}""",
                )
            }
            r.submit().failed shouldBe false
            r.message shouldContain "Action: OVERWRITE the existing Block indicator with: AUDIT FileSha256 indicator for '$SHA256'"
            r.message shouldContain "- Existing indicator that will be OVERWRITTEN: \"FileSha256 | Block | Old block | expires 2027-01-01T00:00:00Z\""
            r.message shouldContain "- Existing indicator that will be OVERWRITTEN: \"FileSha256 | Allowed | Vendor tool\""
            r.message shouldContain "- Existing indicator that will be OVERWRITTEN: \"FileSha256 | Audit\""
            r.message shouldNotContain "Fourth one"
            r.message shouldNotContain "none: this creates"
            r.message shouldNotContain "Other indicator for this value"
            r.writes shouldHaveSize 1
        }

        test("indicators of another type are shown as unchanged, and the summary does not say OVERWRITE") {
            val r = IocRig(access = AccessLevel.WRITE)
            r.lookup = {
                Canned(
                    body = """{"value":[
                    {"indicatorType":"Url","action":"Block","title":"Same value, other type"},
                    {"indicatorType":"FileSha1","action":"Allowed","title":"Another"}
                ]}""",
                )
            }
            // An existing Block of ANOTHER type is not overwritten, so the write level may still add an Audit.
            r.submit(value = "evil.example", type = "DomainName", action = "Audit").failed shouldBe false
            r.message shouldContain "Action: AUDIT DomainName indicator for 'evil.example'"
            r.message shouldNotContain "OVERWRITE"
            r.message shouldContain "- Existing DomainName indicator: \"none: this creates a new indicator\""
            r.message shouldContain "- Other indicator for this value (unchanged): \"Url | Block | Same value, other type\""
            r.message shouldContain "- Other indicator for this value (unchanged): \"FileSha1 | Allowed | Another\""
            r.writes shouldHaveSize 1
        }

        test("type matching for overwrite is case-insensitive") {
            val r = IocRig()
            r.lookup = { Canned(body = """{"value":[{"indicatorType":"filesha256","action":"Warn","title":"lower"}]}""") }
            r.submit().failed shouldBe false
            r.message shouldContain "OVERWRITE the existing Warn indicator with: AUDIT FileSha256"
            r.message shouldContain "- Existing indicator that will be OVERWRITTEN: \"filesha256 | Warn | lower\""
        }

        test("an existing Audit or Warn of the same type may be overwritten at the write level, and the summary says OVERWRITE") {
            for (old in listOf("Audit", "Warn")) {
                val r = IocRig(access = AccessLevel.WRITE)
                r.lookup = { Canned(body = """{"value":[{"indicatorType":"FileSha256","action":"$old","title":"t"}]}""") }
                r.submit(action = "Warn").failed shouldBe false
                r.message shouldContain "Action: OVERWRITE the existing $old indicator with: WARN FileSha256"
                r.writes shouldHaveSize 1
            }
        }

        // Regression: replacing a Block/BlockAndRemediate/Allowed indicator with a short-lived Audit or Warn lifts its
        // enforcement, so it is a destructive change even though the new action is write-tier.
        withData(
            nameFn = { "regression: write level refuses to overwrite an existing ${it.first} with ${it.second}" },
            "Block" to "Audit",
            "Block" to "Warn",
            "BlockAndRemediate" to "Audit",
            "Allowed" to "Warn",
            "block" to "Audit",
            "ALLOWED" to "Audit",
        ) { (old, new) ->
            val r = IocRig(access = AccessLevel.WRITE)
            r.lookup = { Canned(body = """{"value":[{"indicatorType":"FileSha256","action":"$old","title":"Enforced"}]}""") }
            val res = r.submit(action = new)
            res.failed shouldBe true
            res.text() shouldContain "an existing $old indicator for this value would be overwritten"
            res.text() shouldContain "destructive access level"
            res.text() shouldContain "Nothing was changed"
            r.approver.asked shouldBe 0
            r.gets shouldHaveSize 1
            r.writes.shouldBeEmpty()
        }

        test("regression: a tenant narrowed to write cannot downgrade a Block on a destructive server") {
            val r = IocRig(access = AccessLevel.DESTRUCTIVE, tenantAccess = AccessLevel.WRITE)
            r.lookup = { Canned(body = """{"value":[{"indicatorType":"FileSha256","action":"Block","title":"Enforced"}]}""") }
            val res = r.submit(action = "Audit")
            res.failed shouldBe true
            res.text() shouldContain "would be overwritten"
            r.approver.asked shouldBe 0
            r.writes.shouldBeEmpty()
        }

        withData(
            nameFn = { "regression: destructive level may overwrite an existing ${it.first} with ${it.second} after approval" },
            "Block" to "Audit",
            "BlockAndRemediate" to "Warn",
            "Allowed" to "Audit",
        ) { (old, new) ->
            val r = IocRig(access = AccessLevel.DESTRUCTIVE)
            r.lookup = { Canned(body = """{"value":[{"indicatorType":"FileSha256","action":"$old","title":"Enforced"}]}""") }
            r.submit(action = new).failed shouldBe false
            r.approver.asked shouldBe 1
            r.message shouldContain "Action: OVERWRITE the existing $old indicator with: ${new.uppercase()} FileSha256 indicator for '$SHA256'"
            r.message shouldContain "- Existing indicator that will be OVERWRITTEN: \"FileSha256 | $old | Enforced\""
            r.writes.single().body()["action"]!!.jsonPrimitive.content shouldBe new
        }

        test("declining after seeing the overwrite sends no write") {
            val r = IocRig(outcome = ApprovalOutcome.DECLINED)
            r.lookup = { Canned(body = """{"value":[{"indicatorType":"FileSha256","action":"Block","title":"t"}]}""") }
            val res = r.submit()
            res.failed shouldBe true
            res.text() shouldContain "declined"
            r.approver.asked shouldBe 1
            r.gets shouldHaveSize 1
            r.writes.shouldBeEmpty()
            r.audit.lines.single() shouldContain "declined"
        }
    }

    context("defender_submit_indicator: the existing-indicator lookup fails closed") {
        withData(
            nameFn = { it.first },
            "HTTP 500" to Canned(HttpStatusCode.InternalServerError, """{"error":{"code":"InternalError"}}"""),
            "HTTP 403" to Canned(HttpStatusCode.Forbidden, """{"error":{"code":"Forbidden"}}"""),
            "not JSON" to Canned(body = "<html>oops</html>", contentType = "text/html"),
            "a JSON array" to Canned(body = "[1,2,3]"),
        ) { (_, canned) ->
            val r = IocRig()
            r.lookup = { canned }
            val res = r.submit()
            res.failed shouldBe true
            res.text() shouldContain "existing indicators could not be checked"
            r.approver.asked shouldBe 0
            r.assertNothingSent(anyRequest = true)
        }

        // Regression: a 200 response without a "value" array used to count as "no existing indicator" (the lookup
        // failed OPEN and the approver was told "this creates a new indicator" although nothing was checked).
        test("regression: a lookup body without a value array is a failed lookup, not 'none'") {
            for (body in listOf("{}", """{"value":"x"}""", """{"value":null}""", """{"value":{}}""", """{"@odata.context":"x"}""")) {
                val r = IocRig()
                r.lookup = { Canned(body = body) }
                val res = r.submit()
                res.failed shouldBe true
                res.text() shouldContain "existing indicators could not be checked"
                r.approver.asked shouldBe 0
                r.assertNothingSent(anyRequest = true)
            }
        }
    }

    context("defender_submit_indicator: refusals send nothing") {
        withData(
            nameFn = { "${it.first} on ${it.second} is not in the action matrix" },
            "Audit" to "CertificateThumbprint",
            "Warn" to "CertificateThumbprint",
            "Block" to "CertificateThumbprint",
            "BlockAndRemediate" to "IpAddress",
            "BlockAndRemediate" to "DomainName",
            "BlockAndRemediate" to "Url",
        ) { (action, type) ->
            val r = IocRig()
            val value = when (type) {
                "CertificateThumbprint" -> SHA1
                "IpAddress" -> "203.0.113.7"
                "DomainName" -> "evil.example"
                else -> "https://evil.example/x"
            }
            val res = r.submit(value = value, type = type, action = action)
            res.failed shouldBe true
            res.text() shouldContain "not supported for $type"
            r.assertNothingSent()
        }

        withData(
            nameFn = { "${it.first}: '${it.second.take(40)}'" },
            "FileSha1" to SHA1.dropLast(1),
            "FileSha1" to SHA256,
            "FileSha1" to SHA1.dropLast(1) + "g",
            "FileSha256" to SHA1,
            "FileSha256" to SHA256 + "0",
            "FileMd5" to SHA1,
            "FileMd5" to MD5.dropLast(2),
            "FileMd5" to "*",
            "CertificateThumbprint" to SHA256,
            "CertificateThumbprint" to SHA1.replaceFirst('3', ':'),
            "IpAddress" to "2001:db8::1",
            "IpAddress" to "::1",
            "IpAddress" to "2001:db8:0:0:0:0:1",
            "IpAddress" to "10.0.0.0/8",
            "IpAddress" to "10.0.0.1-10.0.0.9",
            "IpAddress" to "10.0.0.*",
            "IpAddress" to "evil.example",
            "IpAddress" to "999.1.1.1",
            "DomainName" to "*.evil.example",
            "DomainName" to "evil*.example",
            "DomainName" to "com",
            "DomainName" to "203.0.113.7",
            "DomainName" to "evil.example/path",
            "DomainName" to "localhost",
            "Url" to "ftp://evil.example/x",
            "Url" to "javascript:alert(1)",
            "Url" to "file:///C:/Windows/x",
            "Url" to "evil.example/path",
            "Url" to "/relative/path",
            "Url" to "http://",
            "Url" to "https://*.evil.example/x",
            "Url" to "https://evil.example/a b",
            "Url" to "https://evil.example/\u0007",
            "Url" to "https://evil.example/\u200B",
            "Url" to "https://evil.example/" + "a".repeat(2_048),
            "Url" to "https://microsoft.com@evil.example/x",
            "Url" to "https://user:pass@evil.example/",
            "Url" to "http://a@b@evil.example/",
            "Url" to "https://evil.example/x#frag",
            "Url" to "https://evil.example/#",
            "Url" to "https://evil.example/x?y=1#microsoft.com",
        ) { (type, value) ->
            val r = IocRig()
            val action = if (type == "CertificateThumbprint") "Allowed" else "Audit"
            val res = r.submit(value = value, type = type, action = action)
            res.failed shouldBe true
            res.text() shouldContain "indicator_value"
            r.approver.asked shouldBe 0
            r.assertNothingSent()
        }

        test("regression: URL user info and fragments are refused with a reason; '@' in the path or query is not user info") {
            for (v in listOf("https://microsoft.com@evil.example/x", "https://user:pass@evil.example/", "https://login.microsoftonline.com@203.0.113.7/")) {
                val e = runCatching { CustomIndicatorTools.validateValue("Url", v) }.exceptionOrNull()
                (e is IllegalArgumentException) shouldBe true
                e!!.message!! shouldContain "user info"
            }
            for (v in listOf("https://evil.example/x#frag", "https://evil.example/#")) {
                val e = runCatching { CustomIndicatorTools.validateValue("Url", v) }.exceptionOrNull()
                (e is IllegalArgumentException) shouldBe true
                e!!.message!! shouldContain "fragment"
            }
            CustomIndicatorTools.validateValue("Url", "https://evil.example/u/@alice?to=a@b.example") shouldBe
                "https://evil.example/u/@alice?to=a@b.example"
        }

        test("the URL host fact shows the real host the approver is blocking") {
            val r = IocRig()
            r.submit(value = "https://cdn.evil.example:8443/p/microsoft.com/x", type = "Url", action = "Block").failed shouldBe false
            r.message shouldContain "- URL host: \"cdn.evil.example\""
        }

        test("validateValue rejects an unknown type") {
            val e = runCatching { CustomIndicatorTools.validateValue("Registry", "x") }.exceptionOrNull()
            (e is IllegalArgumentException) shouldBe true
            e!!.message!! shouldContain "indicator_type must be one of"
        }

        withData(
            nameFn = { it.first },
            "in the past" to iso(Instant.now().minus(Duration.ofMinutes(5))),
            "more than 365 days ahead" to iso(Instant.now().plus(Duration.ofDays(366))),
            "far future" to "2999-01-01T00:00:00Z",
            "not a timestamp" to "next tuesday",
            "no offset" to "2027-01-01T00:00:00",
        ) { (_, exp) ->
            val r = IocRig()
            val res = r.submit(expiration = exp)
            res.failed shouldBe true
            res.text() shouldContain "expiration_time"
            r.assertNothingSent()
        }

        withData(
            nameFn = { "write level refuses $it" },
            CustomIndicatorTools.DESTRUCTIVE_ACTIONS.toList(),
        ) { action ->
            val r = IocRig(access = AccessLevel.WRITE)
            val res = r.submit(value = SHA1, type = "FileSha1", action = action)
            res.failed shouldBe true
            res.text() shouldContain "needs the destructive access level"
            res.text() shouldContain "has write"
            r.approver.asked shouldBe 0
            r.assertNothingSent()
        }

        test("a tenant narrowed to write refuses Block even on a destructive server") {
            val r = IocRig(access = AccessLevel.DESTRUCTIVE, tenantAccess = AccessLevel.WRITE)
            val res = r.submit(value = SHA1, type = "FileSha1", action = "Block")
            res.failed shouldBe true
            res.text() shouldContain "has write"
            r.assertNothingSent()
            // ...while Audit still works for that tenant.
            r.submit(value = SHA1, type = "FileSha1", action = "Audit").failed shouldBe false
        }

        test("title, description and recommended actions are validated") {
            val r = IocRig()
            r.submit(title = "t".repeat(CustomIndicatorTools.MAX_TITLE + 1)).text() shouldContain "title must be at most"
            r.submit(title = "\u200B\u200B ").text() shouldContain "title is required"
            r.submit(description = "   ").text() shouldContain "description is required"
            r.submit(extra = listOf("severity" to "Critical")).text() shouldContain "severity must be one of"
            r.submit(extra = listOf("rbac_group_names" to listOf("bad\u0000group"))).text() shouldContain "rbac_group_names"
            r.submit(extra = listOf("recommended_actions" to "  ")).failed shouldBe false // blank -> omitted
            r.writes.single().body().keys shouldNotContain "recommendedActions"
            r.submit(extra = listOf("unknown" to "x")).text() shouldContain "Unknown argument"
        }
    }

    context("defender_submit_indicator: critical domains") {
        withData(
            nameFn = { "refuses $it" },
            CustomIndicatorTools.CRITICAL_DOMAINS.toList() + listOf("MICROSOFT.COM.", " Windows.Net "),
        ) { domain ->
            for (action in listOf("Audit", "Warn", "Block")) {
                val r = IocRig()
                val res = r.submit(value = domain, type = "DomainName", action = action)
                res.failed shouldBe true
                res.text() shouldContain "Windows, Defender or Microsoft 365 depend on"
                r.approver.asked shouldBe 0
                r.assertNothingSent()
            }
        }

        test("parents of critical domains are critical; subdomains and look-alikes are not") {
            CustomIndicatorTools.isCriticalDomain("com") shouldBe true
            CustomIndicatorTools.isCriticalDomain("net") shouldBe true
            CustomIndicatorTools.isCriticalDomain("microsoft.com") shouldBe true
            CustomIndicatorTools.isCriticalDomain("core.windows.net") shouldBe false
            CustomIndicatorTools.isCriticalDomain("evil.blob.core.windows.net") shouldBe false
            CustomIndicatorTools.isCriticalDomain("notmicrosoft.com") shouldBe false
            CustomIndicatorTools.isCriticalDomain("microsoft.com.evil.example") shouldBe false
            CustomIndicatorTools.isCriticalDomain("org") shouldBe false
        }

        test("a TLD (the ultimate parent) cannot even be submitted: a domain needs two labels") {
            for (tld in listOf("com", "net", ".com")) {
                val r = IocRig()
                r.submit(value = tld, type = "DomainName", action = "Block").failed shouldBe true
                r.assertNothingSent()
            }
        }

        test("a subdomain of a critical domain can be blocked (attacker-hosted storage)") {
            val r = IocRig()
            r.submit(value = "evil.blob.core.windows.net", type = "DomainName", action = "Block").failed shouldBe false
            r.writes.single().body()["indicatorValue"]!!.jsonPrimitive.content shouldBe "evil.blob.core.windows.net"
            r.message shouldContain "BLOCK DomainName indicator for 'evil.blob.core.windows.net'"
        }

        test("Allowed on a critical domain is not refused by the critical-domain rule") {
            val r = IocRig()
            r.submit(value = "microsoft.com", type = "DomainName", action = "Allowed").failed shouldBe false
            r.writes shouldHaveSize 1
        }

        test("a URL on a critical domain is allowed (it is narrow)") {
            val r = IocRig()
            r.submit(value = "https://microsoft.com/evil-redirect", type = "Url", action = "Block").failed shouldBe false
            r.writes shouldHaveSize 1
        }
    }

    context("defender_delete_indicator") {
        val found = """{"value":[{"id":"42","indicatorValue":"evil.example","indicatorType":"DomainName","action":"Block",
            "title":"C2 domain","createdBy":"analyst@contoso.com"}]}"""

        test("looks the indicator up, shows its facts, then DELETEs /api/indicators/{id}") {
            val r = IocRig()
            r.lookup = { Canned(body = found) }
            r.delete(id = " 42 ").failed shouldBe false
            r.gets.single().path shouldBe "/api/indicators"
            r.gets.single().param("\$filter").shouldBeNull()
            r.gets.single().param("\$top") shouldBe "10000"
            r.gets.single().param("\$skip") shouldBe "0"
            r.writes.single().request.method shouldBe HttpMethod.Delete
            r.writes.single().path shouldBe "/api/indicators/42"
            r.writes.single().body.shouldBeNull()
            r.message shouldContain "Action: DELETE indicator 42, lifting its rule tenant-wide"
            r.message shouldContain "- Comment (supplied by the AI): \"False positive, ticket INC-9\""
            r.message shouldContain "Target as reported by Defender:"
            r.message shouldContain "- Value: \"evil.example\""
            r.message shouldContain "- Type: \"DomainName\""
            r.message shouldContain "- Action: \"Block\""
            r.message shouldContain "- Title: \"C2 domain\""
            r.message shouldContain "- Created by: \"analyst@contoso.com\""
        }

        test("an indicator with no descriptive fields still needs approval, with no facts") {
            val r = IocRig()
            r.lookup = { Canned(body = """{"value":[{"id":"7"}]}""") }
            r.delete(id = "7").failed shouldBe false
            r.message shouldNotContain "Target as reported by Defender"
            r.writes.single().path shouldBe "/api/indicators/7"
        }

        withData(
            nameFn = { it.first },
            "unknown ID (empty value)" to Canned(body = EMPTY_LOOKUP),
            "HTTP 404" to Canned(HttpStatusCode.NotFound, """{"error":{"code":"NotFound"}}"""),
            "HTTP 500" to Canned(HttpStatusCode.InternalServerError, "{}"),
            "not JSON" to Canned(body = "garbage"),
            "no value array" to Canned(body = "{}"),
            "value is not an object" to Canned(body = """{"value":["42"]}"""),
            "value is null" to Canned(body = """{"value":null}"""),
            "a JSON array" to Canned(body = """[{"id":"42"}]"""),
            "only other indicators (filter ignored)" to Canned(body = """{"value":[{"id":"41","action":"Block"},{"id":"420"},{"id":"4"}]}"""),
            "id differs only by a leading zero" to Canned(body = """{"value":[{"id":"042"}]}"""),
            "id with whitespace" to Canned(body = """{"value":[{"id":" 42"}]}"""),
        ) { (_, canned) ->
            val r = IocRig()
            r.lookup = { canned }
            val res = r.delete()
            res.failed shouldBe true
            res.text() shouldContain "could not be found (or looked up)"
            r.approver.asked shouldBe 0
            r.gets.isNotEmpty() shouldBe true
            r.assertNothingSent(anyRequest = true)
        }

        // Regression: delete used to look the record up with "$filter=id eq N" ($top=1) and show the first result; an
        // API that ignored the (undocumented) filter would show the approver one indicator and delete another.
        test("regression: when the API ignores the filter, the record with the exact id is shown and deleted") {
            val r = IocRig()
            r.lookup = {
                Canned(
                    body = """{"value":[
                    {"id":"41","indicatorValue":"decoy.example","indicatorType":"DomainName","action":"Allowed","title":"Decoy"},
                    {"id":"420","indicatorValue":"other.example","indicatorType":"DomainName","action":"Block","title":"Other"},
                    {"id":42,"indicatorValue":"evil.example","indicatorType":"DomainName","action":"Block","title":"C2 domain"},
                    {"id":"42","indicatorValue":"second.example","title":"Duplicate"}
                ]}""",
                )
            }
            r.delete(id = "42").failed shouldBe false
            r.message shouldContain "- Value: \"evil.example\""
            r.message shouldContain "- Title: \"C2 domain\""
            r.message shouldNotContain "decoy.example"
            r.message shouldNotContain "other.example"
            r.message shouldNotContain "Decoy"
            r.writes.single().path shouldBe "/api/indicators/42"
        }

        test("the lookup pages through the list with \$top=10000 and \$skip, and finds a record on the second page") {
            val fullPage = (1..CustomIndicatorTools.SCAN_PAGE).joinToString(",", "{\"value\":[", "]}") { """{"id":"${it + 100_000}"}""" }
            val r = IocRig()
            r.lookup = { req ->
                when (req.url.parameters["\$skip"]) {
                    "0" -> Canned(body = fullPage)
                    "10000" -> Canned(body = """{"value":[{"id":"42","indicatorValue":"evil.example","title":"Page two"}]}""")
                    else -> Canned(HttpStatusCode.BadRequest, "{}")
                }
            }
            r.delete(id = "42").failed shouldBe false
            r.gets.map { it.param("\$skip") } shouldContainExactly listOf("0", "10000")
            r.gets.forEach {
                it.param("\$top") shouldBe "10000"
                it.param("\$filter").shouldBeNull()
            }
            r.message shouldContain "- Title: \"Page two\""
            r.writes.single().path shouldBe "/api/indicators/42"
        }

        test("a short first page without the id stops the scan and refuses") {
            val r = IocRig()
            r.lookup = { Canned(body = """{"value":[{"id":"1"}]}""") }
            r.delete(id = "42").failed shouldBe true
            r.gets shouldHaveSize 1
            r.writes.shouldBeEmpty()
        }

        withData(
            nameFn = { "two full pages, second page ${it.first}: refused" },
            "without the id" to Canned(body = (1..CustomIndicatorTools.SCAN_PAGE).joinToString(",", "{\"value\":[", "]}") { """{"id":"${it + 200_000}"}""" }),
            "failing" to Canned(HttpStatusCode.InternalServerError, "{}"),
            "unreadable" to Canned(body = "garbage"),
        ) { (_, second) ->
            val fullPage = (1..CustomIndicatorTools.SCAN_PAGE).joinToString(",", "{\"value\":[", "]}") { """{"id":"${it + 100_000}"}""" }
            val r = IocRig()
            r.lookup = { req -> if (req.url.parameters["\$skip"] == "0") Canned(body = fullPage) else second }
            val res = r.delete(id = "42")
            res.failed shouldBe true
            res.text() shouldContain "could not be found (or looked up)"
            r.approver.asked shouldBe 0
            r.writes.shouldBeEmpty()
            // Only the SCAN_PAGES pages are read (the tenant cap is 15,000 indicators); retries may repeat a page.
            r.gets.map { it.param("\$skip") }.toSet() shouldBe setOf("0", "10000")
        }

        test("declined: no DELETE") {
            val r = IocRig(outcome = ApprovalOutcome.DECLINED)
            r.lookup = { Canned(body = found) }
            r.delete().failed shouldBe true
            r.approver.asked shouldBe 1
            r.assertNothingSent(anyRequest = true)
        }

        test("non-numeric or hostile IDs are refused before any request") {
            for (bad in listOf("abc", "42/../1", "42 or 1 eq 1", "-1", "1".repeat(21), "4 2", "")) {
                val r = IocRig()
                r.delete(id = bad).failed shouldBe true
                r.assertNothingSent()
            }
        }

        test("a blank comment is refused before any request") {
            val r = IocRig()
            r.delete(comment = " \u200B ").failed shouldBe true
            r.assertNothingSent()
        }

        test("the write level cannot delete") {
            val r = IocRig(access = AccessLevel.WRITE)
            r.lookup = { Canned(body = found) }
            r.delete().text() shouldContain "not permitted"
            r.assertNothingSent()
        }
    }
})
