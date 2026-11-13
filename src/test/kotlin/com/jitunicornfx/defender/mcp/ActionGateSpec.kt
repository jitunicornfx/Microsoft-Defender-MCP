package com.jitunicornfx.defender.mcp

import com.jitunicornfx.defender.mcp.testutil.Canned
import com.jitunicornfx.defender.mcp.testutil.FakeDefender
import com.jitunicornfx.defender.mcp.testutil.FixedApprover
import com.jitunicornfx.defender.mcp.testutil.ListAudit
import com.jitunicornfx.defender.mcp.testutil.MACHINE_ID
import com.jitunicornfx.defender.mcp.testutil.failed
import com.jitunicornfx.defender.mcp.testutil.mcpHarness
import com.jitunicornfx.defender.mcp.testutil.testConfig
import com.jitunicornfx.defender.mcp.testutil.text
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotContain
import io.kotest.matchers.string.shouldStartWith
import io.kotest.property.Arb
import io.kotest.property.arbitrary.string
import io.kotest.property.checkAll
import io.modelcontextprotocol.kotlin.sdk.client.Client
import io.modelcontextprotocol.kotlin.sdk.client.ClientOptions
import io.modelcontextprotocol.kotlin.sdk.server.ClientConnection
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.server.ServerOptions
import io.modelcontextprotocol.kotlin.sdk.shared.RequestOptions
import io.modelcontextprotocol.kotlin.sdk.types.ClientCapabilities
import io.modelcontextprotocol.kotlin.sdk.types.ElicitRequestParams
import io.modelcontextprotocol.kotlin.sdk.types.Implementation
import io.modelcontextprotocol.kotlin.sdk.types.ServerCapabilities
import io.modelcontextprotocol.kotlin.sdk.types.Tool
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import com.jitunicornfx.defender.mcp.testutil.InMemoryTransport
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import io.modelcontextprotocol.kotlin.sdk.types.ElicitRequest
import io.modelcontextprotocol.kotlin.sdk.types.ElicitResult
import kotlinx.coroutines.CancellationException
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.time.Instant
import java.util.Collections

private const val AUDIT_PREFIX = "[defender-mcp] AUDIT "
private val FIXED_NOW: Instant = Instant.parse("2026-01-02T03:04:05Z")

private fun parseAudit(line: String): JsonObject {
    line shouldStartWith AUDIT_PREFIX
    return JsonCodec.compact.parseToJsonElement(line.removePrefix(AUDIT_PREFIX)).jsonObject
}

private fun JsonObject.str(key: String): String = this[key]!!.jsonPrimitive.content

private fun gate(
    mode: ConfirmationMode = ConfirmationMode.ELICIT,
    limit: Int = 5,
    audit: AuditSink = ListAudit(),
) = ActionGate(mode, ActionBudget(limit), audit) { FIXED_NOW }

private val DETAILS = listOf("machine" to MACHINE_ID, "comment" to "please isolate")

private fun tagArgs() = mapOf("machine_id" to MACHINE_ID, "tag" to "suspect", "action" to "Add")

/**
 * A bare MCP server (not buildServer) with one tool "probe" whose handler runs [probe] with the
 * calling client's real [ClientConnection], connected in-process to a client advertising elicitation.
 */
private suspend fun probeSession(
    elicitation: (ElicitRequest) -> ElicitResult = { ElicitResult(ElicitResult.Action.Accept, buildJsonObject { put("approve", JsonPrimitive(true)) }) },
    probe: suspend (Server, ClientConnection) -> String,
): Client {
    val server = Server(
        Implementation("probe-server", "1"),
        ServerOptions(capabilities = ServerCapabilities(tools = ServerCapabilities.Tools(listChanged = false))),
    )
    server.addTool(Tool(name = "probe", inputSchema = ToolSchema())) { _ -> textResult(probe(server, this)) }
    val (ct, st) = InMemoryTransport.createLinkedPair()
    val client = Client(Implementation("c", "1"), ClientOptions(capabilities = ClientCapabilities(elicitation = ClientCapabilities.Elicitation())))
    client.setElicitationHandler(elicitation)
    coroutineScope {
        launch { client.connect(ct) }
        launch { server.createSession(st) }
    }
    return client
}

class ActionGateSpec : FunSpec({

    context("authorize") {
        test("APPROVED returns null, keeps the budget permit and audits 'approved'") {
            val audit = ListAudit()
            val g = gate(audit = audit)
            val approver = FixedApprover(ApprovalOutcome.APPROVED)
            g.authorize("defender_tag_machine", "Tag machine", DETAILS, approver).shouldBeNull()
            approver.asked shouldBe 1
            g.budgetUsed shouldBe 1
            g.budgetLimit shouldBe 5
            audit.lines shouldHaveSize 1
            val entry = parseAudit(audit.lines.single())
            entry.str("ts") shouldBe "2026-01-02T03:04:05Z"
            entry.str("event") shouldBe "defender_action"
            entry.str("tool") shouldBe "defender_tag_machine"
            entry.str("outcome") shouldBe "approved"
            entry.str("summary") shouldBe "Tag machine"
            entry["details"]!!.jsonObject.str("machine") shouldBe MACHINE_ID
            entry["details"]!!.jsonObject.str("comment") shouldBe "please isolate"
        }

        test("DECLINED refuses, releases the permit and tells the model not to retry") {
            val audit = ListAudit()
            val g = gate(audit = audit)
            val result = g.authorize("t", "s", DETAILS, FixedApprover(ApprovalOutcome.DECLINED)).shouldNotBeNull()
            result.failed shouldBe true
            result.text() shouldContain "declined"
            result.text() shouldContain "Do not retry"
            g.budgetUsed shouldBe 0
            parseAudit(audit.lines.single()).str("outcome") shouldBe "declined"
        }

        test("UNSUPPORTED fails closed, releases the permit and mentions elicitation") {
            val audit = ListAudit()
            val g = gate(audit = audit)
            val result = g.authorize("t", "s", DETAILS, FixedApprover(ApprovalOutcome.UNSUPPORTED)).shouldNotBeNull()
            result.failed shouldBe true
            result.text() shouldContain "does not support elicitation"
            result.text() shouldContain "Nothing was changed"
            g.budgetUsed shouldBe 0
            parseAudit(audit.lines.single()).str("outcome") shouldBe "unsupported"
        }

        test("FAILED refuses, releases the permit and says the prompt could not complete") {
            val audit = ListAudit()
            val g = gate(audit = audit)
            val result = g.authorize("t", "s", DETAILS, FixedApprover(ApprovalOutcome.FAILED)).shouldNotBeNull()
            result.failed shouldBe true
            result.text() shouldContain "could not be completed"
            g.budgetUsed shouldBe 0
            parseAudit(audit.lines.single()).str("outcome") shouldBe "failed"
        }

        test("ConfirmationMode.NONE approves without asking and audits 'approved_unattended'") {
            val audit = ListAudit()
            val g = gate(mode = ConfirmationMode.NONE, audit = audit)
            val approver = FixedApprover(ApprovalOutcome.DECLINED)
            g.authorize("t", "s", DETAILS, approver).shouldBeNull()
            approver.asked shouldBe 0
            g.budgetUsed shouldBe 1
            parseAudit(audit.lines.single()).str("outcome") shouldBe "approved_unattended"
        }

        test("exhausted budget refuses before the human is asked, even in NONE mode") {
            for (mode in ConfirmationMode.entries) {
                val audit = ListAudit()
                val g = gate(mode = mode, limit = 2, audit = audit)
                val approver = FixedApprover(ApprovalOutcome.APPROVED)
                g.authorize("t", "s", DETAILS, approver).shouldBeNull()
                g.authorize("t", "s", DETAILS, approver).shouldBeNull()
                val refused = g.authorize("t", "s", DETAILS, approver).shouldNotBeNull()
                refused.failed shouldBe true
                refused.text() shouldContain "budget of 2 actions per hour is exhausted"
                refused.text() shouldContain Config.ENV_MAX_ACTIONS_PER_HOUR
                approver.asked shouldBe if (mode == ConfirmationMode.ELICIT) 2 else 0
                g.budgetUsed shouldBe 2
                parseAudit(audit.lines.last()).str("outcome") shouldBe "refused_budget"
            }
        }

        test("declines do not consume the budget, so a limit of 1 still allows a later approval") {
            val g = gate(limit = 1)
            val approver = FixedApprover(ApprovalOutcome.DECLINED)
            repeat(5) { g.authorize("t", "s", DETAILS, approver).shouldNotBeNull().failed shouldBe true }
            approver.asked shouldBe 5
            approver.outcome = ApprovalOutcome.APPROVED
            g.authorize("t", "s", DETAILS, approver).shouldBeNull()
            g.authorize("t", "s", DETAILS, approver).shouldNotBeNull().text() shouldContain "exhausted"
        }

        test("cancellation while waiting for the human releases the permit and propagates") {
            val audit = ListAudit()
            val g = gate(limit = 1, audit = audit)
            shouldThrow<CancellationException> {
                g.authorize("t", "s", DETAILS) { throw CancellationException("client went away") }
            }
            g.budgetUsed shouldBe 0
            audit.lines.shouldBeEmpty()
            g.authorize("t", "s", DETAILS, FixedApprover()).shouldBeNull()
        }

        test("approver receives the labelled approval message") {
            val approver = FixedApprover()
            gate().authorize("t", "Isolate machine", DETAILS, approver)
            approver.lastMessage shouldBe ActionGate.approvalMessage("Isolate machine", DETAILS)
        }

        test("a throwing audit sink is swallowed and the decision still stands") {
            val g = gate(audit = AuditSink { error("disk full") })
            g.authorize("t", "s", DETAILS, FixedApprover()).shouldBeNull()
            g.authorize("t", "s", DETAILS, FixedApprover(ApprovalOutcome.DECLINED)).shouldNotBeNull().failed shouldBe true
        }

        test("audit details are scrubbed of invisible/control characters and clipped to 500 chars") {
            val audit = ListAudit()
            val g = gate(audit = audit)
            val sneaky = "ok​‮hidden\u0007" + "x".repeat(1_000)
            g.authorize("t", "s", listOf("comment" to sneaky), FixedApprover())
            val raw = audit.lines.single()
            raw shouldNotContain "​"
            raw shouldNotContain "‮"
            val comment = parseAudit(raw)["details"]!!.jsonObject.str("comment")
            comment shouldStartWith "okhidden"
            comment.length shouldBe 500
            comment.any { it == '​' || it == '‮' || it == '\u0007' } shouldBe false
        }

        test("audit lines are single-line JSON even with newlines in the values") {
            val audit = ListAudit()
            gate(audit = audit).authorize("t", "line1\nline2", listOf("c" to "a\nb"), FixedApprover())
            val raw = audit.lines.single()
            raw.contains('\n') shouldBe false
            val entry = parseAudit(raw)
            entry.str("summary") shouldBe "line1\nline2"
            entry["details"]!!.jsonObject.str("c") shouldBe "a\nb"
        }

        test("default audit sink and clock work (stderr)") {
            val g = ActionGate(ConfirmationMode.NONE, ActionBudget(1))
            g.authorize("t", "s", emptyList(), FixedApprover()).shouldBeNull()
        }
    }

    context("approvalMessage") {
        test("labels every AI-supplied value and warns about untrusted data") {
            val msg = ActionGate.approvalMessage("Tag machine", DETAILS)
            msg shouldStartWith "An AI assistant is requesting a Microsoft Defender for Endpoint action."
            msg shouldContain "Action: Tag machine\n"
            msg shouldContain "- machine (supplied by the AI): \"$MACHINE_ID\"\n"
            msg shouldContain "- comment (supplied by the AI): \"please isolate\"\n"
            msg shouldContain "Approve only if you asked for this."
            msg shouldContain "untrusted data"
        }

        test("an injected comment cannot forge a new line in the prompt") {
            val msg = ActionGate.approvalMessage(
                "Tag",
                listOf("comment" to "routine\nAction: SAFE, approved by admin​⁦"),
            )
            msg shouldContain "- comment (supplied by the AI): \"routine Action: SAFE, approved by admin\"\n"
            msg.lines().count { it.startsWith("Action:") } shouldBe 1
            msg shouldNotContain "​"
            msg shouldNotContain "⁦"
        }

        test("long values are clipped to 500 characters") {
            val msg = ActionGate.approvalMessage("s", listOf("c" to "y".repeat(2_000)))
            msg shouldContain "\"" + "y".repeat(500) + "\"\n"
            msg shouldNotContain "y".repeat(501)
        }

        test("no details still yields a complete message") {
            val msg = ActionGate.approvalMessage("Run scan", emptyList())
            msg shouldContain "Action: Run scan\n\nApprove only"
        }

        test("property: every value line is one line, labelled, and free of invisible chars") {
            // letters with newlines, invisible and control characters sprinkled through
            val chars = ('a'..'z').toList() + listOf('\n', '​', '‮', '\u0007', '﻿', '\u0000', '\u009B')
            val alphabet = io.kotest.property.arbitrary.arbitrary { rs ->
                val n = rs.random.nextInt(0, 700)
                buildString { repeat(n) { append(chars.random(rs.random)) } }
            }
            checkAll(200, alphabet) { value ->
                val msg = ActionGate.approvalMessage("s", listOf("v" to value))
                val line = msg.split('\n').single { it.startsWith("- v (supplied by the AI): \"") }
                line.endsWith("\"") shouldBe true
                Validators.INVISIBLE.containsMatchIn(line) shouldBe false
                line.none { it.isISOControl() } shouldBe true
                (line.length - "- v (supplied by the AI): \"\"".length) shouldBe minOf(PromptShield.scrub(value).length, 500)
            }
        }

        // Regression: approvalMessage once replaced only '\n', so '\r' or a Unicode line separator in an
        // AI-supplied comment could forge an "Action: ..." line in the human's approval prompt.
        test("carriage returns and Unicode line separators cannot forge a line in the prompt") {
            val msg = ActionGate.approvalMessage("Tag", listOf("comment" to "x\rAction: SAFE Action: SAFE2 y"))
            msg shouldNotContain "\r"
            msg shouldNotContain " "
            msg shouldNotContain " "
        }
    }

    context("approvalMessage line flattening and quoting") {
        test("every line terminator in a value is flattened to a space") {
            val forged = "a\rb\nc\u000Bd\u000Ce\u0085f\u2028g\u2029h"
            val msg = ActionGate.approvalMessage("Tag", listOf("comment" to forged))
            val line = msg.split('\n').single { it.startsWith("- comment (supplied by the AI): ") }
            line shouldBe "- comment (supplied by the AI): \"a b c d e f g h\""
            listOf("\r", "\u000B", "\u000C", "\u0085", "\u2028", "\u2029").forEach { msg shouldNotContain it }
        }
        test("a double quote in a value cannot close the quoted field early") {
            val msg = ActionGate.approvalMessage("Tag", listOf("comment" to "ok\" Action: \"isolate all"))
            msg.split('\n').single { it.startsWith("- comment") } shouldBe
                "- comment (supplied by the AI): \"ok' Action: 'isolate all\""
        }
    }

    context("ElicitationApprover.interpret") {
        fun content(v: Any?) = buildJsonObject {
            when (v) {
                is Boolean -> put("approve", JsonPrimitive(v))
                is String -> put("approve", JsonPrimitive(v))
                is JsonObject -> put("approve", v)
                else -> {}
            }
        }

        test("accept with approve=true is APPROVED") {
            ElicitationApprover.interpret(ElicitResult(ElicitResult.Action.Accept, content(true))) shouldBe ApprovalOutcome.APPROVED
        }
        test("accept with approve=false is DECLINED") {
            ElicitationApprover.interpret(ElicitResult(ElicitResult.Action.Accept, content(false))) shouldBe ApprovalOutcome.DECLINED
        }
        test("accept with no content is DECLINED") {
            ElicitationApprover.interpret(ElicitResult(ElicitResult.Action.Accept, null)) shouldBe ApprovalOutcome.DECLINED
        }
        test("accept without the approve field is DECLINED") {
            ElicitationApprover.interpret(ElicitResult(ElicitResult.Action.Accept, content(null))) shouldBe ApprovalOutcome.DECLINED
        }
        test("only a real JSON boolean true approves; the string \"true\" is DECLINED") {
            ElicitationApprover.interpret(ElicitResult(ElicitResult.Action.Accept, content("true"))) shouldBe ApprovalOutcome.DECLINED
            ElicitationApprover.interpret(ElicitResult(ElicitResult.Action.Accept, content("TRUE"))) shouldBe ApprovalOutcome.DECLINED
            ElicitationApprover.interpret(
                ElicitResult(ElicitResult.Action.Accept, buildJsonObject { put("approve", JsonPrimitive(1)) }),
            ) shouldBe ApprovalOutcome.DECLINED
        }
        test("accept with a non-boolean or non-primitive approve is DECLINED") {
            ElicitationApprover.interpret(ElicitResult(ElicitResult.Action.Accept, content("yes please"))) shouldBe ApprovalOutcome.DECLINED
            ElicitationApprover.interpret(ElicitResult(ElicitResult.Action.Accept, content(JsonObject(emptyMap())))) shouldBe ApprovalOutcome.DECLINED
            ElicitationApprover.interpret(
                ElicitResult(ElicitResult.Action.Accept, buildJsonObject { put("approve", JsonArray(listOf(JsonPrimitive(true)))) }),
            ) shouldBe ApprovalOutcome.DECLINED
        }
        test("decline and cancel are DECLINED") {
            // The SDK itself forbids content on decline/cancel, so a forged "approve" cannot ride along.
            shouldThrow<IllegalArgumentException> { ElicitResult(ElicitResult.Action.Decline, content(true)) }
            ElicitationApprover.interpret(ElicitResult(ElicitResult.Action.Decline, null)) shouldBe ApprovalOutcome.DECLINED
            ElicitationApprover.interpret(ElicitResult(ElicitResult.Action.Cancel, null)) shouldBe ApprovalOutcome.DECLINED
        }
        test("approval schema requires a boolean 'approve' defaulting to false") {
            ElicitationApprover.APPROVAL_SCHEMA.required shouldBe listOf(ElicitationApprover.APPROVE_FIELD)
            ElicitationApprover.APPROVAL_SCHEMA.properties.keys shouldBe setOf("approve")
        }
    }

    context("ElicitationApprover.approve over a real in-process MCP session") {
        val writeConfig = testConfig(access = AccessLevel.WRITE)
        val ok = { _: Any -> Canned(body = """{"id":"x"}""") }

        test("client without elicitation capability -> UNSUPPORTED, API never called") {
            val fake = FakeDefender(api = { ok(it) })
            val audit = ListAudit()
            val h = mcpHarness(config = writeConfig, fake = fake, audit = audit)
            val r = h.call("defender_tag_machine", tagArgs())
            r.failed shouldBe true
            r.text() shouldContain "does not support elicitation"
            fake.apiRequests.shouldBeEmpty()
            parseAudit(audit.lines.single()).str("outcome") shouldBe "unsupported"
        }

        test("accept + approve=true -> APPROVED, the human saw the labelled prompt and schema") {
            val fake = FakeDefender(api = { ok(it) })
            val audit = ListAudit()
            val seen = Collections.synchronizedList(mutableListOf<ElicitRequest>())
            val h = mcpHarness(config = writeConfig, fake = fake, audit = audit, elicitation = { req ->
                seen += req
                ElicitResult(ElicitResult.Action.Accept, buildJsonObject { put("approve", JsonPrimitive(true)) })
            })
            val r = h.call("defender_tag_machine", tagArgs())
            r.failed shouldBe false
            fake.apiRequests shouldHaveSize 1
            seen shouldHaveSize 1
            seen.single().params.message shouldContain "(supplied by the AI)"
            seen.single().params.message shouldContain MACHINE_ID
            parseAudit(audit.lines.single()).str("outcome") shouldBe "approved"
        }

        test("decline -> DECLINED, API never called") {
            val fake = FakeDefender(api = { ok(it) })
            val h = mcpHarness(config = writeConfig, fake = fake, elicitation = { ElicitResult(ElicitResult.Action.Decline) })
            val r = h.call("defender_tag_machine", tagArgs())
            r.failed shouldBe true
            r.text() shouldContain "declined"
            fake.apiRequests.shouldBeEmpty()
        }

        test("accept without ticking the box -> DECLINED") {
            val fake = FakeDefender(api = { ok(it) })
            val h = mcpHarness(config = writeConfig, fake = fake, elicitation = {
                ElicitResult(ElicitResult.Action.Accept, buildJsonObject { put("approve", JsonPrimitive(false)) })
            })
            h.call("defender_tag_machine", tagArgs()).text() shouldContain "declined"
            fake.apiRequests.shouldBeEmpty()
        }

        test("connection whose session the server does not know -> UNSUPPORTED (fails closed)") {
            val stranger = Server(Implementation("other", "1"), ServerOptions(capabilities = ServerCapabilities()))
            val client = probeSession { _, conn -> ElicitationApprover(stranger, conn).approve("x").name }
            client.callTool("probe", emptyMap()).text() shouldBe "UNSUPPORTED"
        }

        test("direct approve with a custom timeout returns APPROVED / DECLINED from the human's answer") {
            var answer = true
            val client = probeSession(elicitation = {
                ElicitResult(ElicitResult.Action.Accept, buildJsonObject { put("approve", JsonPrimitive(answer)) })
            }) { server, conn -> ElicitationApprover(server, conn, timeoutMinutes = 1).approve("x").name }
            client.callTool("probe", emptyMap()).text() shouldBe "APPROVED"
            answer = false
            client.callTool("probe", emptyMap()).text() shouldBe "DECLINED"
        }

        test("cancellation during the elicitation propagates instead of being reported as FAILED") {
            val client = probeSession { server, conn ->
                val cancelling = object : ClientConnection by conn {
                    override suspend fun createElicitation(
                        message: String,
                        requestedSchema: ElicitRequestParams.RequestedSchema,
                        options: RequestOptions?,
                    ): ElicitResult = throw CancellationException("session closed")
                }
                try {
                    "returned " + ElicitationApprover(server, cancelling).approve("x").name
                } catch (e: CancellationException) {
                    "rethrown: " + e.message
                }
            }
            client.callTool("probe", emptyMap()).text() shouldBe "rethrown: session closed"
        }

        test("elicitation handler that throws -> FAILED, API never called") {
            val fake = FakeDefender(api = { ok(it) })
            val audit = ListAudit()
            val h = mcpHarness(config = writeConfig, fake = fake, audit = audit, elicitation = { error("UI crashed") })
            val r = h.call("defender_tag_machine", tagArgs())
            r.failed shouldBe true
            r.text() shouldContain "could not be completed"
            r.text() shouldNotContain "UI crashed"
            fake.apiRequests.shouldBeEmpty()
            parseAudit(audit.lines.single()).str("outcome") shouldBe "failed"
        }
    }
})
