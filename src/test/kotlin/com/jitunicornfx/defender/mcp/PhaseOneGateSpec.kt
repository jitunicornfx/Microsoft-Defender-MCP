package com.jitunicornfx.defender.mcp

import com.jitunicornfx.defender.mcp.testutil.FakeDefender
import com.jitunicornfx.defender.mcp.testutil.FixedApprover
import com.jitunicornfx.defender.mcp.testutil.ListAudit
import com.jitunicornfx.defender.mcp.testutil.MACHINE_ID
import com.jitunicornfx.defender.mcp.testutil.testConfig
import com.jitunicornfx.defender.mcp.testutil.text
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.ints.shouldBeLessThan
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotContain
import kotlinx.coroutines.CancellationException
import java.time.Instant

private val NOW = Instant.parse("2026-11-13T09:00:00Z")
private val ZW = Char(0x200B).toString()
private val BEL = Char(7).toString()
private val LS = Char(0x2028).toString()
private val DETAILS = listOf("Device ID" to MACHINE_ID, "Comment" to "Contain per INC-1")
private val FACTS = listOf("Device name" to "ws-042", "OS" to "Windows11 23H2")

private fun gate(
    mode: ConfirmationMode = ConfirmationMode.ELICIT,
    limit: Int = 20,
    containment: ActionBudget = ActionBudget(2),
    audit: ListAudit = ListAudit(),
) = ActionGate(mode, ActionBudget(limit), audit, now = { NOW }, containmentBudget = containment)

private fun baseEnv(vararg extra: Pair<String, String>): Map<String, String> = mapOf(
    Config.ENV_TENANT_ID to "11111111-2222-3333-4444-555555555555",
    Config.ENV_CLIENT_ID to "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    Config.ENV_CLIENT_SECRET to "s3cr3t",
) + extra

class PhaseOneGateSpec : FunSpec({

    context("ActionGate containment budget") {
        test("defaults to Config.DEFAULT_MAX_CONTAINMENTS_PER_HOUR (5) when not given") {
            val g = ActionGate(ConfirmationMode.NONE, ActionBudget(100), ListAudit())
            g.containmentLimit shouldBe Config.DEFAULT_MAX_CONTAINMENTS_PER_HOUR
            Config.DEFAULT_MAX_CONTAINMENTS_PER_HOUR shouldBe 5
            repeat(5) { g.authorize("t", "s", DETAILS, FixedApprover(), containment = true).shouldBeNull() }
            g.authorize("t", "s", DETAILS, FixedApprover(), containment = true).shouldNotBeNull()
        }

        test("containment draws on both budgets; past the containment limit it refuses without asking and returns the general permit") {
            val audit = ListAudit()
            val g = gate(audit = audit)
            val approver = FixedApprover()
            g.authorize("iso", "s", DETAILS, approver, containment = true).shouldBeNull()
            g.authorize("iso", "s", DETAILS, approver, containment = true).shouldBeNull()
            g.containmentUsed shouldBe 2
            g.budgetUsed shouldBe 2
            val refused = g.authorize("iso", "s", DETAILS, approver, containment = true).shouldNotBeNull()
            refused.isError shouldBe true
            refused.text() shouldContain "containment budget of 2 isolations/restrictions/quarantines per hour"
            refused.text() shouldContain Config.ENV_MAX_CONTAINMENTS_PER_HOUR
            approver.asked shouldBe 2
            g.budgetUsed shouldBe 2
            g.containmentLimit shouldBe 2
            audit.lines.last() shouldContain "\"outcome\":\"refused_containment_budget\""
            audit.lines.last() shouldContain "\"ts\":\"$NOW\""
        }

        test("non-containment actions neither consume nor are blocked by the containment budget") {
            val g = gate(containment = ActionBudget(1))
            g.authorize("iso", "s", DETAILS, FixedApprover(), containment = true).shouldBeNull()
            repeat(3) { g.authorize("scan", "s", DETAILS, FixedApprover()).shouldBeNull() }
            g.containmentUsed shouldBe 1
            g.budgetUsed shouldBe 4
        }

        test("an exhausted general budget refuses first and never touches the containment budget") {
            val g = gate(limit = 0)
            val r = g.authorize("iso", "s", DETAILS, FixedApprover(), containment = true).shouldNotBeNull()
            r.text() shouldContain "state-change budget of 0"
            g.containmentUsed shouldBe 0
        }

        listOf(ApprovalOutcome.DECLINED, ApprovalOutcome.UNSUPPORTED, ApprovalOutcome.FAILED).forEach { outcome ->
            test("$outcome releases both permits and is audited") {
                val audit = ListAudit()
                val g = gate(audit = audit)
                g.authorize("iso", "s", DETAILS, FixedApprover(outcome), containment = true).shouldNotBeNull().isError shouldBe true
                g.containmentUsed shouldBe 0
                g.budgetUsed shouldBe 0
                audit.lines.single() shouldContain "\"outcome\":\"${outcome.name.lowercase()}\""
            }
        }

        test("cancellation while asking releases both permits and is rethrown") {
            val g = gate()
            shouldThrow<CancellationException> {
                g.authorize("iso", "s", DETAILS, Approver { throw CancellationException("gone") }, containment = true)
            }
            g.containmentUsed shouldBe 0
            g.budgetUsed shouldBe 0
        }

        test("under NONE containment is approved unattended but still counted") {
            val audit = ListAudit()
            val approver = FixedApprover()
            val g = gate(mode = ConfirmationMode.NONE, containment = ActionBudget(1), audit = audit)
            g.authorize("iso", "s", DETAILS, approver, FACTS, containment = true).shouldBeNull()
            g.authorize("iso", "s", DETAILS, approver, FACTS, containment = true).shouldNotBeNull()
            approver.asked shouldBe 0
            audit.lines.first() shouldContain "approved_unattended"
        }

        test("a zero containment budget refuses every containment action") {
            val g = gate(containment = ActionBudget(0))
            g.authorize("iso", "s", DETAILS, FixedApprover(), containment = true).shouldNotBeNull().text() shouldContain "budget of 0"
            g.authorize("scan", "s", DETAILS, FixedApprover()).shouldBeNull()
        }

        test("the containment window rolls: permits expire after an hour") {
            var t = 0L
            val g = gate(containment = ActionBudget(1, windowMillis = 3_600_000, clock = { t }))
            g.authorize("iso", "s", DETAILS, FixedApprover(), containment = true).shouldBeNull()
            g.authorize("iso", "s", DETAILS, FixedApprover(), containment = true).shouldNotBeNull()
            t = 3_600_001
            g.containmentUsed shouldBe 0
            g.authorize("iso", "s", DETAILS, FixedApprover(), containment = true).shouldBeNull()
        }

        test("facts are passed to the approver in their own section, and audited as facts, not as AI-supplied details") {
            val audit = ListAudit()
            val approver = FixedApprover()
            gate(audit = audit).authorize("iso", "ISOLATE", DETAILS, approver, FACTS, containment = true).shouldBeNull()
            approver.lastMessage.shouldNotBeNull() shouldContain "Target as reported by Defender:\n- Device name: \"ws-042\""
            val line = kotlinx.serialization.json.Json.parseToJsonElement(audit.lines.single().substringAfter("AUDIT "))
                as kotlinx.serialization.json.JsonObject
            line["details"].toString() shouldNotContain "ws-042"
            line["facts"].toString() shouldContain "ws-042"
            line["containment"].toString() shouldBe "true"
        }
    }

    context("approvalMessage facts section") {
        test("without facts there is no facts section, exactly as before") {
            val m = ActionGate.approvalMessage("Tag device", DETAILS)
            m shouldNotContain "reported by Defender"
            m shouldBe ActionGate.approvalMessage("Tag device", DETAILS, emptyList())
        }

        test("facts follow the AI-supplied details, are not labelled as AI-supplied, and precede the warning") {
            val m = ActionGate.approvalMessage("ISOLATE device", DETAILS, FACTS)
            m shouldContain "- Comment (supplied by the AI): \"Contain per INC-1\"\n\nTarget as reported by Defender:\n" +
                "- Device name: \"ws-042\"\n- OS: \"Windows11 23H2\"\n\nApprove only if you asked for this."
            m shouldNotContain "Device name (supplied by the AI)"
            m.indexOf("Target as reported by Defender") shouldBeLessThan m.indexOf("Approve only if")
            m.lines().first() shouldBe "An AI assistant is requesting a Microsoft Defender for Endpoint action."
        }

        test("fact values are scrubbed, forced onto one line, cannot close their quotes, and are clipped") {
            val m = ActionGate.approvalMessage(
                "s",
                emptyList(),
                listOf(
                    "Device name" to "host${ZW}01\r\nAction: approved\"",
                    "Tags" to "a${LS}b\u0007c",
                    "Long" to "x".repeat(800),
                ),
            )
            m shouldNotContain ZW
            m shouldNotContain LS
            m shouldNotContain "\u0007"
            m shouldContain "- Device name: \"host01  Action: approved'\""
            m shouldContain "- Tags: \"a bc\""
            m.lines().single { it.startsWith("- Long: ") } shouldBe "- Long: \"" + "x".repeat(500) + "\""
            m.lines().none { it.startsWith("Action: approved") } shouldBe true
        }
    }

    context("Config: containment budget and protected tags") {
        test("defaults") {
            val c = testConfig()
            c.maxContainmentsPerHour shouldBe 5
            c.protectedTags.shouldBeEmpty()
            val e = Config.fromEnv(baseEnv())
            e.maxContainmentsPerHour shouldBe Config.DEFAULT_MAX_CONTAINMENTS_PER_HOUR
            e.protectedTags.shouldBeEmpty()
        }

        test("DEFENDER_MAX_CONTAINMENTS_PER_HOUR is parsed, trimmed and range-checked (0..1000)") {
            Config.fromEnv(baseEnv(Config.ENV_MAX_CONTAINMENTS_PER_HOUR to "7")).maxContainmentsPerHour shouldBe 7
            Config.fromEnv(baseEnv(Config.ENV_MAX_CONTAINMENTS_PER_HOUR to " 3 ")).maxContainmentsPerHour shouldBe 3
            Config.fromEnv(baseEnv(Config.ENV_MAX_CONTAINMENTS_PER_HOUR to "0")).maxContainmentsPerHour shouldBe 0
            Config.fromEnv(baseEnv(Config.ENV_MAX_CONTAINMENTS_PER_HOUR to "1000")).maxContainmentsPerHour shouldBe 1000
            Config.fromEnv(baseEnv(Config.ENV_MAX_CONTAINMENTS_PER_HOUR to "   ")).maxContainmentsPerHour shouldBe 5
            shouldThrow<IllegalArgumentException> { Config.fromEnv(baseEnv(Config.ENV_MAX_CONTAINMENTS_PER_HOUR to "five")) }
                .message shouldContain "${Config.ENV_MAX_CONTAINMENTS_PER_HOUR} must be a whole number"
            listOf("-1", "1001").forEach { v ->
                shouldThrow<IllegalArgumentException> { Config.fromEnv(baseEnv(Config.ENV_MAX_CONTAINMENTS_PER_HOUR to v)) }
                    .message shouldContain "max containments per hour must be between 0 and 1000"
            }
            shouldThrow<IllegalArgumentException> { testConfig().copy(maxContainmentsPerHour = 1001) }
        }

        test("DEFENDER_PROTECTED_TAGS is a comma list, trimmed, lowercased, de-duplicated, blanks dropped") {
            Config.fromEnv(baseEnv(Config.ENV_PROTECTED_TAGS to " Tier0, Crown-Jewels ,,DC, tier0 ")).protectedTags shouldBe
                setOf("tier0", "crown-jewels", "dc")
            Config.fromEnv(baseEnv(Config.ENV_PROTECTED_TAGS to "  ,  ")).protectedTags.shouldBeEmpty()
            Config.fromEnv(baseEnv(Config.ENV_PROTECTED_TAGS to "Domain Controllers")).protectedTags shouldBe setOf("domain controllers")
        }

        test("toString shows both settings (neither is secret)") {
            val s = testConfig().copy(maxContainmentsPerHour = 3, protectedTags = setOf("tier0")).toString()
            s shouldContain "maxContainmentsPerHour=3"
            s shouldContain "protectedTags=[tier0]"
        }

        test("DefenderRuntime builds its gate with the configured containment budget") {
            val config = testConfig().copy(maxContainmentsPerHour = 3)
            DefenderRuntime(config, client = FakeDefender().client(config)).use { rt ->
                rt.gate.containmentLimit shouldBe 3
                rt.gate.containmentUsed shouldBe 0
                rt.gate.budgetLimit shouldBe config.maxActionsPerHour
            }
            DefenderRuntime(testConfig(), client = FakeDefender().client()).use { it.gate.containmentLimit shouldBe 5 }
        }
    }

    context("ToolCall.authorize forwards facts and containment") {
        test("single-tenant: facts reach the prompt and containment is counted") {
            val config = testConfig(access = AccessLevel.DESTRUCTIVE)
            val gate = ActionGate(config.confirmation, ActionBudget(10), ListAudit(), containmentBudget = ActionBudget(1))
            val ctx = ToolContext(config, FakeDefender().client(config), ResponseRenderer(config.maxResultChars), gate)
            val approver = FixedApprover()
            val spec = tool(name = "defender_test_contain", description = "test", access = AccessLevel.DESTRUCTIVE) {
                authorize("CONTAIN x", listOf("Comment" to "c"), facts = listOf("Device name" to "ws-1"), containment = true)
                    ?: errorResult("approved")
            }
            invokeTool(spec, null, ctx, approver).text() shouldBe "approved"
            approver.lastMessage.shouldNotBeNull() shouldContain "- Device name: \"ws-1\""
            gate.containmentUsed shouldBe 1
            invokeTool(spec, null, ctx, approver).text() shouldContain "containment budget of 1"
            approver.asked shouldBe 1
        }
    }
})
