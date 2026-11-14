package com.jitunicornfx.defender.mcp.tools

import com.jitunicornfx.defender.mcp.AccessLevel
import com.jitunicornfx.defender.mcp.ActionBudget
import com.jitunicornfx.defender.mcp.ActionGate
import com.jitunicornfx.defender.mcp.ApprovalOutcome
import com.jitunicornfx.defender.mcp.CloudEnvironment
import com.jitunicornfx.defender.mcp.Config
import com.jitunicornfx.defender.mcp.ConfirmationMode
import com.jitunicornfx.defender.mcp.DefenderRuntime
import com.jitunicornfx.defender.mcp.EntraCredentials
import com.jitunicornfx.defender.mcp.ResponseRenderer
import com.jitunicornfx.defender.mcp.TenantProfile
import com.jitunicornfx.defender.mcp.ToolContext
import com.jitunicornfx.defender.mcp.ToolRegistry
import com.jitunicornfx.defender.mcp.ToolSpec
import com.jitunicornfx.defender.mcp.invokeTool
import com.jitunicornfx.defender.mcp.testutil.ACTION_ID
import com.jitunicornfx.defender.mcp.testutil.Canned
import com.jitunicornfx.defender.mcp.testutil.FakeDefender
import com.jitunicornfx.defender.mcp.testutil.FixedApprover
import com.jitunicornfx.defender.mcp.testutil.ListAudit
import com.jitunicornfx.defender.mcp.testutil.MACHINE_ID
import com.jitunicornfx.defender.mcp.testutil.Recorded
import com.jitunicornfx.defender.mcp.testutil.failed
import com.jitunicornfx.defender.mcp.testutil.jsonArgs
import com.jitunicornfx.defender.mcp.testutil.mcpHarness
import com.jitunicornfx.defender.mcp.testutil.testConfig
import com.jitunicornfx.defender.mcp.testutil.text
import io.kotest.core.spec.style.FunSpec
import io.kotest.datatest.withData
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.collections.shouldContainAll
import io.kotest.matchers.collections.shouldContainExactly
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.collections.shouldNotContain
import io.kotest.matchers.ints.shouldBeLessThan
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotContain
import io.ktor.client.request.HttpRequestData
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.ElicitResult
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.put

private val ZW = Char(0x200B).toString()
private val LS = Char(0x2028).toString()
private val SHA1 = "3395856ce81f2b7382dee72602f798b642f14140"
private const val GOOD_COMMENT = "Alert da638 - ransomware staging, ticket INC-4411"

private const val MACHINE_JSON = """{"id":"$MACHINE_ID","computerDnsName":"ws-042.contoso.local","osPlatform":"Windows11",
    "version":"23H2","healthStatus":"Active","deviceValue":"High","rbacGroupName":"Finance workstations",
    "lastSeen":"2026-11-12T10:00:00Z","machineTags":["finance","VIP"]}"""

private const val ACTION_JSON = """{"id":"$ACTION_ID","type":"Isolate","status":"Pending","computerDnsName":"ws-042.contoso.local",
    "requestor":"analyst@contoso.com"}"""

private const val POST_JSON = """{"id":"$ACTION_ID","type":"Isolate","status":"Pending"}"""

/**
 * A rig with its own [ActionGate] (so the containment budget is configurable) and a fake Defender that
 * routes device, file and machine-action lookups separately from the POSTed actions.
 */
private class Rig(
    access: AccessLevel = AccessLevel.DESTRUCTIVE,
    confirmation: ConfirmationMode = ConfirmationMode.ELICIT,
    outcome: ApprovalOutcome = ApprovalOutcome.APPROVED,
    maxActions: Int = Config.DEFAULT_MAX_ACTIONS_PER_HOUR,
    maxContainments: Int = Config.DEFAULT_MAX_CONTAINMENTS_PER_HOUR,
    protectedTags: Set<String> = emptySet(),
) {
    var machine: () -> Canned = { Canned(body = MACHINE_JSON) }
    var file: () -> Canned = { Canned(HttpStatusCode.NotFound, """{"error":{"code":"NotFound"}}""") }
    var action: () -> Canned = { Canned(body = ACTION_JSON) }
    var post: (HttpRequestData) -> Canned = { Canned(body = POST_JSON) }

    val config: Config = testConfig(access = access, confirmation = confirmation, maxActionsPerHour = maxActions)
        .copy(maxContainmentsPerHour = maxContainments, protectedTags = protectedTags)
    val fake = FakeDefender(api = { req -> route(req) })
    val approver = FixedApprover(outcome)
    val audit = ListAudit()
    val gate = ActionGate(
        config.confirmation,
        ActionBudget(config.maxActionsPerHour),
        audit,
        containmentBudget = ActionBudget(config.maxContainmentsPerHour),
    )
    val context = ToolContext(config, fake.client(config), ResponseRenderer(config.maxResultChars), gate)

    private fun route(req: HttpRequestData): Canned {
        if (req.method == HttpMethod.Post) return post(req)
        val path = req.url.encodedPath
        return when {
            path.startsWith("/api/machines/") -> machine()
            path.startsWith("/api/files/") -> file()
            path.startsWith("/api/machineactions/") -> action()
            else -> Canned(HttpStatusCode.NotFound)
        }
    }

    suspend fun call(spec: ToolSpec, vararg args: Pair<String, Any?>) = invokeTool(spec, jsonArgs(*args), context, approver)

    val posts: List<Recorded> get() = fake.apiRequests.filter { it.request.method == HttpMethod.Post }
    val gets: List<Recorded> get() = fake.apiRequests.filter { it.request.method == HttpMethod.Get }
    val message: String get() = approver.lastMessage.shouldNotBeNull()

    suspend fun isolate(comment: String = GOOD_COMMENT, type: String = "Full", id: String = MACHINE_ID) =
        call(ResponseTools.isolateMachine, "machine_id" to id, "comment" to comment, "isolation_type" to type)

    suspend fun restrict(comment: String = GOOD_COMMENT, id: String = MACHINE_ID) =
        call(ResponseTools.restrictAppExecution, "machine_id" to id, "comment" to comment)

    suspend fun quarantine(comment: String = GOOD_COMMENT, sha1: String = SHA1, id: String = MACHINE_ID) =
        call(ResponseTools.stopAndQuarantineFile, "machine_id" to id, "comment" to comment, "sha1" to sha1)

    suspend fun unisolate(comment: String = "Cleared after triage", id: String = MACHINE_ID) =
        call(ResponseTools.unisolateMachine, "machine_id" to id, "comment" to comment)

    suspend fun unrestrict(comment: String = "Cleared after triage", id: String = MACHINE_ID) =
        call(ResponseTools.unrestrictAppExecution, "machine_id" to id, "comment" to comment)

    suspend fun scan(comment: String = "Sweep", type: String = "Quick", id: String = MACHINE_ID) =
        call(ResponseTools.runAntivirusScan, "machine_id" to id, "comment" to comment, "scan_type" to type)

    suspend fun cancel(comment: String = "Wrong device", id: String = ACTION_ID) =
        call(ResponseTools.cancelMachineAction, "action_id" to id, "comment" to comment)
}

private class Case(val name: String, val block: suspend (Rig) -> CallToolResult)

private fun Recorded.body(): JsonObject = bodyJson().jsonObject

private fun obj(vararg pairs: Pair<String, String>) = JsonObject(pairs.associate { (k, v) -> k to JsonPrimitive(v) })

private val CONTAINMENT_TOOLS = listOf("isolate", "restrict", "quarantine")

private suspend fun Rig.contain(which: String, comment: String = GOOD_COMMENT) = when (which) {
    "isolate" -> isolate(comment)
    "restrict" -> restrict(comment)
    else -> quarantine(comment)
}

class ResponseToolsSpec : FunSpec({

    context("exact API paths, PascalCase bodies and successful rendering") {
        test("isolate POSTs Comment and IsolationType (canonical case) to /isolate, lowercasing the device ID") {
            val r = Rig()
            val res = r.isolate(type = "selective", id = MACHINE_ID.uppercase())
            res.failed shouldBe false
            res.text() shouldContain ACTION_ID
            r.gets.map { it.path } shouldContainExactly listOf("/api/machines/$MACHINE_ID")
            r.posts shouldHaveSize 1
            r.posts.single().path shouldBe "/api/machines/$MACHINE_ID/isolate"
            r.posts.single().body() shouldBe obj("Comment" to GOOD_COMMENT, "IsolationType" to "Selective")
            r.approver.asked shouldBe 1
            r.gate.containmentUsed shouldBe 1
            r.gate.budgetUsed shouldBe 1
        }

        test("UnManagedDevice isolation type is accepted verbatim") {
            val r = Rig()
            r.isolate(type = "UnManagedDevice").failed shouldBe false
            r.posts.single().body()["IsolationType"] shouldBe JsonPrimitive("UnManagedDevice")
        }

        test("restrict POSTs Comment to /restrictCodeExecution") {
            val r = Rig()
            r.restrict().failed shouldBe false
            r.posts.single().path shouldBe "/api/machines/$MACHINE_ID/restrictCodeExecution"
            r.posts.single().body() shouldBe obj("Comment" to GOOD_COMMENT)
        }

        test("unisolate POSTs Comment to /unisolate") {
            val r = Rig()
            r.unisolate().failed shouldBe false
            r.posts.single().path shouldBe "/api/machines/$MACHINE_ID/unisolate"
            r.posts.single().body() shouldBe obj("Comment" to "Cleared after triage")
        }

        test("unrestrict POSTs Comment to /unrestrictCodeExecution") {
            val r = Rig()
            r.unrestrict().failed shouldBe false
            r.posts.single().path shouldBe "/api/machines/$MACHINE_ID/unrestrictCodeExecution"
            r.posts.single().body() shouldBe obj("Comment" to "Cleared after triage")
        }

        test("AV scan POSTs Comment and ScanType to /runAntiVirusScan") {
            val r = Rig()
            r.scan(type = "full").failed shouldBe false
            r.posts.single().path shouldBe "/api/machines/$MACHINE_ID/runAntiVirusScan"
            r.posts.single().body() shouldBe obj("Comment" to "Sweep", "ScanType" to "Full")
            r.message shouldContain "Run a Full antivirus scan on device $MACHINE_ID"
        }

        test("quarantine POSTs Comment and a lowercased Sha1 to /StopAndQuarantineFile (documented casing)") {
            val r = Rig()
            r.quarantine(sha1 = SHA1.uppercase()).failed shouldBe false
            r.gets.map { it.path } shouldContainExactly listOf("/api/machines/$MACHINE_ID", "/api/files/$SHA1")
            r.posts.single().path shouldBe "/api/machines/$MACHINE_ID/StopAndQuarantineFile"
            r.posts.single().body() shouldBe obj("Comment" to GOOD_COMMENT, "Sha1" to SHA1)
            r.message shouldContain "STOP and QUARANTINE file $SHA1 on device $MACHINE_ID"
        }

        test("cancel looks the action up, then POSTs Comment to /api/machineactions/{id}/cancel") {
            val r = Rig()
            r.cancel(id = ACTION_ID.uppercase()).failed shouldBe false
            r.gets.map { it.path } shouldContainExactly listOf("/api/machineactions/$ACTION_ID")
            r.posts.single().path shouldBe "/api/machineactions/$ACTION_ID/cancel"
            r.posts.single().body() shouldBe obj("Comment" to "Wrong device")
        }

        test("an API error on the action itself is surfaced as a failure") {
            val r = Rig()
            r.post = { Canned(HttpStatusCode.Conflict, """{"error":{"code":"ActiveRequestAlreadyExists"}}""") }
            val res = r.isolate()
            res.failed shouldBe true
            r.posts shouldHaveSize 1
        }

        test("tool metadata: containment tools are DESTRUCTIVE and flagged destructive; the rest are WRITE; all need approval") {
            listOf(ResponseTools.isolateMachine, ResponseTools.restrictAppExecution, ResponseTools.stopAndQuarantineFile).forEach {
                it.access shouldBe AccessLevel.DESTRUCTIVE
                it.destructive shouldBe true
                it.confirm shouldBe true
            }
            listOf(
                ResponseTools.unisolateMachine, ResponseTools.unrestrictAppExecution,
                ResponseTools.runAntivirusScan, ResponseTools.cancelMachineAction,
            ).forEach {
                it.access shouldBe AccessLevel.WRITE
                it.destructive shouldBe false
                it.confirm shouldBe true
            }
            ResponseTools.all shouldHaveSize 7
        }
    }

    context("input validation refuses before any request") {
        withData(
            nameFn = { it.name },
            Case("isolate: bad machine id") { r -> r.isolate(id = "not-a-machine") },
            Case("isolate: unknown isolation type") { r -> r.isolate(type = "Partial") },
            Case("scan: unknown scan type") { r -> r.scan(type = "Deep") },
            Case("quarantine: MD5 instead of SHA-1") { r -> r.quarantine(sha1 = "d41d8cd98f00b204e9800998ecf8427e") },
            Case("quarantine: SHA-256 instead of SHA-1") { r -> r.quarantine(sha1 = "a".repeat(64)) },
            Case("cancel: not a GUID") { r -> r.cancel(id = "../../machines/x") },
            Case("unisolate: blank comment") { r -> r.unisolate(comment = "   ") },
            Case("unisolate: invisible-only comment") { r -> r.unisolate(comment = "${ZW}${ZW}${ZW}") },
            Case("cancel: over-long comment") { r -> r.cancel(comment = "x".repeat(1001)) },
        ) { case ->
            val r = Rig()
            val res = case.block(r)
            res.failed shouldBe true
            r.fake.apiRequests.shouldBeEmpty()
            r.approver.asked shouldBe 0
            r.gate.budgetUsed shouldBe 0
        }
    }

    context("containment comment must be substantive (at least 10 characters after cleaning)") {
        withData(CONTAINMENT_TOOLS) { which ->
            listOf("too short", "    abc      ", "abc${ZW}${ZW}${ZW}${ZW}${ZW}${ZW}${ZW}${ZW}", "\tabcdefgh\n").forEach { c ->
                val r = Rig()
                val res = r.contain(which, c)
                res.failed shouldBe true
                res.text() shouldContain "at least ${ResponseTools.MIN_CONTAINMENT_COMMENT} characters"
                r.fake.apiRequests.shouldBeEmpty()
                r.approver.asked shouldBe 0
                r.gate.containmentUsed shouldBe 0
            }
            // Exactly the minimum is enough.
            val ok = Rig()
            ok.contain(which, "INC-123456").failed shouldBe false
            ok.posts shouldHaveSize 1
        }

        test("recovery actions, scan and cancel accept a short comment") {
            val r = Rig()
            r.unisolate(comment = "ok").failed shouldBe false
            r.unrestrict(comment = "ok").failed shouldBe false
            r.scan(comment = "ok").failed shouldBe false
            r.cancel(comment = "ok").failed shouldBe false
            r.posts shouldHaveSize 4
        }

        test("the schema documents the minimum on containment tools only") {
            fun commentDesc(spec: ToolSpec) =
                spec.inputSchema.properties!!["comment"]!!.jsonObject["description"].toString()
            commentDesc(ResponseTools.isolateMachine) shouldContain "at least 10 characters"
            commentDesc(ResponseTools.unisolateMachine) shouldNotContain "at least"
        }
    }

    context("protected tags") {
        withData(CONTAINMENT_TOOLS) { which ->
            val r = Rig(protectedTags = setOf("tier0"))
            r.machine = { Canned(body = """{"computerDnsName":"dc01","machineTags":["Finance"," TIER0 "]}""") }
            val res = r.contain(which)
            res.failed shouldBe true
            res.text() shouldContain Config.ENV_PROTECTED_TAGS
            res.text() shouldContain "Nothing was changed"
            r.posts.shouldBeEmpty()
            r.gets.map { it.path } shouldContainExactly listOf("/api/machines/$MACHINE_ID") // no file lookup either
            r.approver.asked shouldBe 0
            r.gate.containmentUsed shouldBe 0
            r.gate.budgetUsed shouldBe 0
        }

        test("protected tags parsed from the environment match case-insensitively end to end") {
            val env = mapOf(
                Config.ENV_TENANT_ID to "11111111-2222-3333-4444-555555555555",
                Config.ENV_CLIENT_ID to "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                Config.ENV_CLIENT_SECRET to "secret",
                Config.ENV_PROTECTED_TAGS to "Crown-Jewels, Tier0",
            )
            val r = Rig(protectedTags = Config.fromEnv(env).protectedTags)
            r.machine = { Canned(body = """{"machineTags":["crown-JEWELS"]}""") }
            r.isolate().failed shouldBe true
            r.posts.shouldBeEmpty()
        }

        test("malformed machineTags entries never hide a protected tag, and a non-array value does not break the lookup") {
            val hit = Rig(protectedTags = setOf("tier0"))
            hit.machine = { Canned(body = """{"machineTags":[null,{"x":1},["nested"],"Tier0"]}""") }
            hit.isolate().failed shouldBe true
            hit.posts.shouldBeEmpty()

            val notArray = Rig()
            notArray.machine = { Canned(body = """{"computerDnsName":"ws-9","machineTags":"finance"}""") }
            notArray.unisolate().failed shouldBe false
            notArray.message shouldContain "- Device name: \"ws-9\""
            notArray.message shouldNotContain "Tags:"
        }

        test("a device without a protected tag is contained; tag similarity is not a match") {
            val r = Rig(protectedTags = setOf("tier0"))
            r.machine = { Canned(body = """{"machineTags":["tier0-adjacent","tier"]}""") }
            r.isolate().failed shouldBe false
            r.posts shouldHaveSize 1
        }

        test("recovery actions and the scan still work on a protected device") {
            val r = Rig(protectedTags = setOf("tier0"))
            r.machine = { Canned(body = """{"machineTags":["Tier0"]}""") }
            r.unisolate().failed shouldBe false
            r.unrestrict().failed shouldBe false
            r.scan().failed shouldBe false
            r.posts.map { it.path.substringAfterLast('/') } shouldContainExactly
                listOf("unisolate", "unrestrictCodeExecution", "runAntiVirusScan")
        }
    }

    context("containment fails closed when the device cannot be looked up") {
        withData(CONTAINMENT_TOOLS) { which ->
            listOf(HttpStatusCode.NotFound, HttpStatusCode.Forbidden).forEach { status ->
                val r = Rig()
                r.machine = { Canned(status, """{"error":{"code":"x","message":"nope"}}""") }
                val res = r.contain(which)
                res.failed shouldBe true
                res.text() shouldContain "could not be looked up before a containment action (HTTP ${status.value})"
                res.text() shouldContain "Nothing was changed"
                r.posts.shouldBeEmpty()
                r.gets.map { it.path } shouldContainExactly listOf("/api/machines/$MACHINE_ID")
                r.approver.asked shouldBe 0
                r.gate.containmentUsed shouldBe 0
            }
        }

        test("a 200 whose body is not a JSON object is also refused") {
            listOf("not json at all", "[]", "\"string\"").forEach { body ->
                val r = Rig()
                r.machine = { Canned(body = body) }
                val res = r.isolate()
                res.failed shouldBe true
                res.text() shouldContain "device record could not be read"
                r.posts.shouldBeEmpty()
                r.approver.asked shouldBe 0
            }
        }
    }

    context("recovery actions proceed when the device lookup fails") {
        withData(
            nameFn = { it.name },
            Case("unisolate") { r -> r.unisolate() },
            Case("unrestrict") { r -> r.unrestrict() },
            Case("scan") { r -> r.scan() },
        ) { case ->
            listOf(Canned(HttpStatusCode.NotFound, "{}"), Canned(HttpStatusCode.Forbidden, "{}"), Canned(body = "garbage")).forEach { c ->
                val r = Rig()
                r.machine = { c }
                case.block(r).failed shouldBe false
                r.posts shouldHaveSize 1
                r.message shouldContain "Target as reported by Defender:"
                r.message shouldContain "- Device: \"(could not be looked up)\""
            }
        }

        test("cancel proceeds when the machine action cannot be looked up") {
            listOf(Canned(HttpStatusCode.NotFound, "{}"), Canned(body = "[1,2]"), Canned(body = "garbage")).forEach { c ->
                val r = Rig()
                r.action = { c }
                r.cancel().failed shouldBe false
                r.posts.single().path shouldBe "/api/machineactions/$ACTION_ID/cancel"
                r.message shouldContain "- Action: \"(could not be looked up)\""
            }
        }
    }

    context("approval prompt: Defender-reported facts, separate from AI-supplied details") {
        test("isolate shows every device fact, labelled as reported by Defender, after the AI-supplied details") {
            val r = Rig()
            r.isolate().failed shouldBe false
            val m = r.message
            m shouldContain "Action: ISOLATE device $MACHINE_ID from the network (Full isolation)"
            m shouldContain "- Device ID (supplied by the AI): \"$MACHINE_ID\""
            m shouldContain "- Isolation type (supplied by the AI): \"Full\""
            m shouldContain "- Comment (supplied by the AI): \"$GOOD_COMMENT\""
            val facts = m.substringAfter("Target as reported by Defender:\n")
            listOf(
                "- Device name: \"ws-042.contoso.local\"",
                "- OS: \"Windows11 23H2\"",
                "- Sensor health: \"Active\"",
                "- Device value: \"High\"",
                "- Device group: \"Finance workstations\"",
                "- Last seen: \"2026-11-12T10:00:00Z\"",
                "- Tags: \"finance, VIP\"",
            ).forEach { facts shouldContain it }
            m.indexOf("(supplied by the AI)") shouldBeLessThan m.indexOf("Target as reported by Defender:")
            m shouldNotContain "Device name (supplied by the AI)"
        }

        test("OS without a version, and blank or missing fields are omitted") {
            val r = Rig()
            r.machine = { Canned(body = """{"osPlatform":"Linux","computerDnsName":"  ","healthStatus":null,"machineTags":[]}""") }
            r.restrict().failed shouldBe false
            r.message shouldContain "- OS: \"Linux\""
            r.message shouldNotContain "Device name:"
            r.message shouldNotContain "Sensor health:"
            r.message shouldNotContain "Tags:"
        }

        test("a device record with no displayable fields yields no facts section, but containment still proceeds") {
            val r = Rig()
            r.machine = { Canned(body = "{}") }
            r.isolate().failed shouldBe false
            r.message shouldNotContain "Target as reported by Defender"
        }

        test("attacker-settable facts are scrubbed: no invisible characters, no line breaks, no closing quotes") {
            val r = Rig()
            r.machine = {
                Canned(body = """{"computerDnsName":"evil${ZW}-host\nAction: approved by admin\"","machineTags":["a${LS}b"]}""")
            }
            r.isolate().failed shouldBe false
            val m = r.message
            m shouldNotContain "${ZW}"
            m shouldNotContain "${LS}"
            m shouldContain "- Device name: \"evil-host Action: approved by admin'\""
            m.lines().none { it.startsWith("Action: approved") } shouldBe true
            m shouldContain "- Tags: \"a b\""
        }

        test("a long tag list is clipped to 200 characters") {
            val r = Rig()
            val tags = (1..40).joinToString(",") { "\"tag-number-$it\"" }
            r.machine = { Canned(body = """{"machineTags":[$tags]}""") }
            r.isolate().failed shouldBe false
            val line = r.message.lines().single { it.startsWith("- Tags: ") }
            line.removePrefix("- Tags: \"").removeSuffix("\"").length shouldBe 200
        }

        test("quarantine shows device and file facts together") {
            val r = Rig()
            r.file = {
                Canned(
                    body = """{"sha1":"$SHA1","fileProductName":"Updater","filePublisher":"Fabrikam","signer":"Fabrikam Ltd",
                        "isValidCertificate":true,"globalPrevalence":1234,"determinationType":"Malware",
                        "determinationValue":"Trojan:Win32/Wacatac"}""",
                )
            }
            r.quarantine().failed shouldBe false
            val m = r.message
            m shouldContain "- Device name: \"ws-042.contoso.local\""
            m shouldContain "- Product: \"Updater\""
            m shouldContain "- Publisher: \"Fabrikam\""
            m shouldContain "- Signer: \"Fabrikam Ltd (valid certificate)\""
            m shouldContain "- Global prevalence: \"1234\""
            m shouldContain "- Determination: \"Malware: Trojan:Win32/Wacatac\""
            m shouldContain "- SHA-1 (supplied by the AI): \"$SHA1\""
        }

        test("cancel shows the action as Defender reports it") {
            val r = Rig()
            r.cancel().failed shouldBe false
            r.message shouldContain "- Action type: \"Isolate\""
            r.message shouldContain "- Status: \"Pending\""
            r.message shouldContain "- Device name: \"ws-042.contoso.local\""
            r.message shouldContain "- Requested by: \"analyst@contoso.com\""
        }

        test("a machine action record with no displayable fields yields no facts section") {
            val r = Rig()
            r.action = { Canned(body = "{}") }
            r.cancel().failed shouldBe false
            r.message shouldNotContain "Target as reported by Defender"
        }
    }

    context("quarantine file lookup") {
        test("a file Defender has never seen is shown as such and may be quarantined") {
            val r = Rig()
            r.quarantine().failed shouldBe false
            r.message shouldContain "- File: \"not in Defender's file catalogue\""
            r.posts shouldHaveSize 1
        }

        test("any other lookup failure refuses without approval or action") {
            listOf(
                Canned(HttpStatusCode.Forbidden, "{}"),
                Canned(HttpStatusCode.BadRequest, "{}"),
                Canned(body = "not json"),
                Canned(body = "[]"),
            ).forEach { c ->
                val r = Rig()
                r.file = { c }
                val res = r.quarantine()
                res.failed shouldBe true
                res.text() shouldContain "file could not be looked up before quarantine (HTTP ${c.status.value})"
                r.posts.shouldBeEmpty()
                r.approver.asked shouldBe 0
                r.gate.containmentUsed shouldBe 0
            }
        }

        test("a validly Microsoft-signed file is refused, whatever the case of the signer or the JSON type of the flag") {
            listOf(
                """{"signer":"Microsoft Windows","isValidCertificate":true}""",
                """{"signer":"MICROSOFT CORPORATION","isValidCertificate":"true"}""",
            ).forEach { body ->
                val r = Rig()
                r.file = { Canned(body = body) }
                val res = r.quarantine()
                res.failed shouldBe true
                res.text() shouldContain "valid Microsoft signature"
                r.posts.shouldBeEmpty()
                r.approver.asked shouldBe 0
                r.gate.containmentUsed shouldBe 0
            }
        }

        test("a Microsoft signer with an invalid certificate is not trusted and can be quarantined") {
            val r = Rig()
            r.file = { Canned(body = """{"signer":"Microsoft Corporation","isValidCertificate":false,"determinationType":"Clean"}""") }
            r.quarantine().failed shouldBe false
            r.message shouldContain "- Signer: \"Microsoft Corporation (certificate not valid)\""
            r.message shouldContain "- Determination: \"Clean\""
            r.posts shouldHaveSize 1
        }

        test("a missing, null or non-boolean certificate flag is never read as valid") {
            listOf(
                """{"signer":"Microsoft Corporation"}""",
                """{"signer":"Microsoft Corporation","isValidCertificate":null}""",
                """{"signer":"Microsoft Corporation","isValidCertificate":{"value":true}}""",
            ).forEach { body ->
                val r = Rig()
                r.file = { Canned(body = body) }
                r.quarantine().failed shouldBe false
                r.message shouldContain "- Signer: \"Microsoft Corporation (certificate not valid)\""
            }
        }

        test("a valid certificate without a signer is not treated as Microsoft-signed") {
            val r = Rig()
            r.file = { Canned(body = """{"isValidCertificate":true}""") }
            r.quarantine().failed shouldBe false
            r.posts shouldHaveSize 1
        }

        test("a device that cannot be looked up is refused before the file is looked up") {
            val r = Rig()
            r.machine = { Canned(HttpStatusCode.NotFound, "{}") }
            r.quarantine().failed shouldBe true
            r.gets.none { it.path.startsWith("/api/files/") } shouldBe true
        }
    }

    context("human approval") {
        withData(ApprovalOutcome.DECLINED, ApprovalOutcome.UNSUPPORTED, ApprovalOutcome.FAILED) { outcome ->
            val r = Rig(outcome = outcome)
            listOf(
                r.isolate(), r.restrict(), r.quarantine(), r.unisolate(), r.unrestrict(), r.scan(), r.cancel(),
            ).forEach { it.failed shouldBe true }
            r.approver.asked shouldBe 7
            r.posts.shouldBeEmpty()
            r.gate.budgetUsed shouldBe 0
            r.gate.containmentUsed shouldBe 0
        }

        test("UNSUPPORTED explains that the client cannot ask the human") {
            Rig(outcome = ApprovalOutcome.UNSUPPORTED).isolate().text() shouldContain "does not support elicitation"
        }

        test("under confirmation NONE containment proceeds unattended but still draws on the containment budget") {
            val r = Rig(confirmation = ConfirmationMode.NONE, maxContainments = 1)
            r.isolate().failed shouldBe false
            r.approver.asked shouldBe 0
            r.gate.containmentUsed shouldBe 1
            r.restrict().failed shouldBe true
            r.posts shouldHaveSize 1
            r.audit.lines.any { "approved_unattended" in it } shouldBe true
        }

        test("approval goes through real MCP elicitation and the client sees the Defender facts") {
            var seen: String? = null
            val fake = FakeDefender(api = { req ->
                if (req.method == HttpMethod.Get) Canned(body = MACHINE_JSON) else Canned(body = POST_JSON)
            })
            val h = mcpHarness(config = testConfig(access = AccessLevel.DESTRUCTIVE), fake = fake, elicitation = { req ->
                seen = req.params.message
                ElicitResult(ElicitResult.Action.Accept, buildJsonObject { put("approve", JsonPrimitive(true)) })
            })
            val res = h.call(
                "defender_isolate_machine",
                mapOf("machine_id" to MACHINE_ID, "comment" to GOOD_COMMENT, "isolation_type" to "Full"),
            )
            res.failed shouldBe false
            seen.shouldNotBeNull() shouldContain "Target as reported by Defender:"
            seen shouldContain "- Device name: \"ws-042.contoso.local\""
            fake.apiRequests.last().path shouldBe "/api/machines/$MACHINE_ID/isolate"
            h.runtime.gate.containmentUsed shouldBe 1
        }
    }

    context("containment budget") {
        test("is shared across isolate, restrict and quarantine, and refuses the next one without asking or acting") {
            val r = Rig(maxContainments = 2)
            r.isolate().failed shouldBe false
            r.restrict().failed shouldBe false
            val third = r.quarantine()
            third.failed shouldBe true
            third.text() shouldContain "containment budget of 2"
            third.text() shouldContain Config.ENV_MAX_CONTAINMENTS_PER_HOUR
            r.approver.asked shouldBe 2
            r.posts.map { it.path.substringAfterLast('/') } shouldContainExactly listOf("isolate", "restrictCodeExecution")
            r.gate.containmentUsed shouldBe 2
            r.gate.budgetUsed shouldBe 2 // the general permit was handed back
            r.audit.lines.any { "refused_containment_budget" in it } shouldBe true
        }

        test("any containment tool can exhaust it for the others") {
            CONTAINMENT_TOOLS.forEach { first ->
                val r = Rig(maxContainments = 1)
                r.contain(first).failed shouldBe false
                (CONTAINMENT_TOOLS - first).forEach { other ->
                    r.contain(other).text() shouldContain "containment budget of 1"
                }
                r.posts shouldHaveSize 1
            }
        }

        test("is released when the human declines") {
            val r = Rig(maxContainments = 1, outcome = ApprovalOutcome.DECLINED)
            r.isolate().failed shouldBe true
            r.gate.containmentUsed shouldBe 0
            r.approver.outcome = ApprovalOutcome.APPROVED
            r.restrict().failed shouldBe false
            r.gate.containmentUsed shouldBe 1
            r.posts shouldHaveSize 1
        }

        test("is not consumed by unisolate, unrestrict, scan or cancel, which keep working once it is exhausted") {
            val r = Rig(maxContainments = 1)
            r.unisolate().failed shouldBe false
            r.unrestrict().failed shouldBe false
            r.scan().failed shouldBe false
            r.cancel().failed shouldBe false
            r.gate.containmentUsed shouldBe 0
            r.gate.budgetUsed shouldBe 4
            r.isolate().failed shouldBe false
            r.gate.containmentUsed shouldBe 1
            r.unisolate().failed shouldBe false
            r.scan().failed shouldBe false
            r.cancel().failed shouldBe false
            r.unrestrict().failed shouldBe false
            r.posts shouldHaveSize 9
        }

        test("a zero containment budget disables containment entirely") {
            val r = Rig(maxContainments = 0)
            CONTAINMENT_TOOLS.forEach { r.contain(it).text() shouldContain "containment budget of 0" }
            r.posts.shouldBeEmpty()
            r.approver.asked shouldBe 0
            r.unisolate().failed shouldBe false
        }

        test("the general action budget is checked first and an exhausted one does not consume containment") {
            val r = Rig(maxActions = 1)
            r.scan().failed shouldBe false
            val res = r.isolate()
            res.failed shouldBe true
            res.text() shouldContain "state-change budget of 1"
            r.gate.containmentUsed shouldBe 0
            r.posts shouldHaveSize 1
        }

        test("the default runtime gate applies the configured containment budget") {
            val config = testConfig(access = AccessLevel.DESTRUCTIVE).copy(maxContainmentsPerHour = 1)
            val fake = FakeDefender(api = { req ->
                if (req.method == HttpMethod.Get) Canned(body = MACHINE_JSON) else Canned(body = POST_JSON)
            })
            DefenderRuntime(config, client = fake.client(config)).use { rt ->
                rt.gate.containmentLimit shouldBe 1
                val approver = FixedApprover()
                val spec = rt.tools.first { it.name == "defender_restrict_app_execution" }
                val args = jsonArgs("machine_id" to MACHINE_ID, "comment" to GOOD_COMMENT)
                invokeTool(spec, args, rt.context, approver).failed shouldBe false
                invokeTool(spec, args, rt.context, approver).text() shouldContain "containment budget of 1"
            }
        }
    }

    context("access levels") {
        val containment = listOf("defender_isolate_machine", "defender_restrict_app_execution", "defender_stop_and_quarantine_file")
        val write = listOf(
            "defender_unisolate_machine", "defender_unrestrict_app_execution", "defender_run_av_scan", "defender_cancel_machine_action",
        )

        test("destructive tools are absent at WRITE; write tools are absent at READ_ONLY; DESTRUCTIVE has all") {
            val ro = ToolRegistry.select(testConfig(access = AccessLevel.READ_ONLY)).map { it.name }
            val w = ToolRegistry.select(testConfig(access = AccessLevel.WRITE)).map { it.name }
            val d = ToolRegistry.select(testConfig(access = AccessLevel.DESTRUCTIVE)).map { it.name }
            (containment + write).forEach { ro shouldNotContain it }
            containment.forEach { w shouldNotContain it }
            w shouldContainAll write
            d shouldContainAll containment + write
        }

        test("globs cannot raise a WRITE server to containment") {
            val names = ToolRegistry.select(testConfig(access = AccessLevel.WRITE).copy(toolGlobs = listOf("defender_*isolate*", "*quarantine*")))
                .map { it.name }
            names shouldContainExactly listOf("defender_unisolate_machine")
        }

        test("invoking a destructive tool on a WRITE tenant is refused before any request") {
            val r = Rig(access = AccessLevel.WRITE)
            val res = r.isolate()
            res.failed shouldBe true
            res.text() shouldContain "not permitted"
            r.fake.apiRequests.shouldBeEmpty()
            r.approver.asked shouldBe 0
            r.unisolate().failed shouldBe false
        }

        test("invoking a write tool on a READ_ONLY tenant is refused before any request") {
            val r = Rig(access = AccessLevel.READ_ONLY)
            r.scan().failed shouldBe true
            r.cancel().failed shouldBe true
            r.fake.apiRequests.shouldBeEmpty()
        }
    }

    context("multi-tenant") {
        test("the approval prompt names the tenant, and the action goes to that tenant's API host") {
            val config = Config(
                credentials = EntraCredentials("aaaaaaaa-1111-2222-3333-444444444444", "aaaaaaaa-5555-6666-7777-888888888888", "secret-A"),
                accessLevel = AccessLevel.DESTRUCTIVE,
                tenantName = "contoso",
                additionalTenants = listOf(
                    TenantProfile(
                        "fabrikam-gov",
                        EntraCredentials("bbbbbbbb-1111-2222-3333-444444444444", "bbbbbbbb-5555-6666-7777-888888888888", "secret-B"),
                        CloudEnvironment.GCC,
                    ),
                ),
                updateCheckDisabled = true,
                autoUpdateDisabled = true,
            )
            val fake = FakeDefender(api = { req ->
                if (req.method == HttpMethod.Get) Canned(body = MACHINE_JSON) else Canned(body = POST_JSON)
            })
            val approver = FixedApprover()
            val gate = ActionGate(config.confirmation, ActionBudget(config.maxActionsPerHour), ListAudit())
            DefenderRuntime(config, gate = gate, clientFactory = { fake.client(it) }).use { rt ->
                val spec = rt.tools.first { it.name == "defender_isolate_machine" }
                val res = invokeTool(
                    spec,
                    jsonArgs("machine_id" to MACHINE_ID, "comment" to GOOD_COMMENT, "isolation_type" to "Full", "tenant" to "fabrikam-gov"),
                    rt.context,
                    approver,
                )
                res.failed shouldBe false
                res.text() shouldContain "Tenant: fabrikam-gov"
                val m = approver.lastMessage.shouldNotBeNull()
                m shouldContain "(Full isolation) in tenant 'fabrikam-gov'"
                m shouldContain "- Tenant (supplied by the AI): \"fabrikam-gov\""
                m shouldContain "Target as reported by Defender:"
                fake.apiRequests.map { it.request.url.host }.toSet() shouldBe setOf(CloudEnvironment.GCC.apiBaseUrl.removePrefix("https://"))
                fake.apiRequests.last().path shouldBe "/api/machines/$MACHINE_ID/isolate"
                gate.containmentUsed shouldBe 1

                // Without a tenant there is no default, so nothing is looked up or changed.
                val missing = invokeTool(spec, jsonArgs("machine_id" to MACHINE_ID, "comment" to GOOD_COMMENT, "isolation_type" to "Full"), rt.context, approver)
                missing.failed shouldBe true
                fake.apiRequests shouldHaveSize 2
            }
        }
    }
})
