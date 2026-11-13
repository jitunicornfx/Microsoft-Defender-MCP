package com.jitunicornfx.defender.mcp

import io.modelcontextprotocol.kotlin.sdk.server.ClientConnection
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.shared.RequestOptions
import io.modelcontextprotocol.kotlin.sdk.types.BooleanSchema
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.ElicitRequestParams
import io.modelcontextprotocol.kotlin.sdk.types.ElicitResult
import kotlinx.coroutines.CancellationException
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.time.Instant
import kotlin.time.Duration.Companion.minutes

/** What the human said when asked to approve an action. */
enum class ApprovalOutcome { APPROVED, DECLINED, UNSUPPORTED, FAILED }

/** Asks a human to approve an action. Implemented over MCP elicitation; a seam for tests. */
fun interface Approver {
    suspend fun approve(message: String): ApprovalOutcome
}

/**
 * [Approver] backed by MCP form elicitation on the calling client's session. A client that did not
 * advertise the elicitation capability yields [ApprovalOutcome.UNSUPPORTED], which the gate treats
 * as a refusal: the decision must come from a human, never from the model.
 */
class ElicitationApprover(
    private val server: Server,
    private val connection: ClientConnection,
    private val timeoutMinutes: Int = 10,
) : Approver {
    override suspend fun approve(message: String): ApprovalOutcome {
        val capabilities = server.sessions[connection.sessionId]?.clientCapabilities
        if (capabilities?.elicitation == null) return ApprovalOutcome.UNSUPPORTED
        val result = try {
            connection.createElicitation(message, APPROVAL_SCHEMA, RequestOptions(timeout = timeoutMinutes.minutes))
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
            return ApprovalOutcome.FAILED
        }
        return interpret(result)
    }

    companion object {
        const val APPROVE_FIELD = "approve"

        val APPROVAL_SCHEMA = ElicitRequestParams.RequestedSchema(
            properties = mapOf(
                APPROVE_FIELD to BooleanSchema(
                    title = "Approve this Defender action",
                    description = "Tick to allow the action described above. Leave unticked or decline to refuse.",
                    default = false,
                ),
            ),
            required = listOf(APPROVE_FIELD),
        )

        /** Approved only on an explicit accept carrying `approve: true`. */
        fun interpret(result: ElicitResult): ApprovalOutcome =
            if (result.action == ElicitResult.Action.Accept &&
                (result.content?.get(APPROVE_FIELD) as? JsonPrimitive)?.let { !it.isString && it.booleanOrNull == true } == true
            ) {
                ApprovalOutcome.APPROVED
            } else {
                ApprovalOutcome.DECLINED
            }
    }
}

/** Append-only audit trail of state-changing and secret-revealing calls. */
fun interface AuditSink {
    fun record(line: String)
}

/**
 * The single checkpoint every state-changing (or secret-revealing) tool passes before it touches
 * the API. Three independent controls, any of which can stop a prompt-injected agent:
 *
 *  1. **Action budget** — at most N such calls per rolling hour; past it, calls are refused.
 *  2. **Human approval** — under [ConfirmationMode.ELICIT] the human must explicitly approve each
 *     call through their MCP client. A client that cannot ask the human fails closed.
 *  3. **Audit** — every decision, approved or not, is written to the audit sink (stderr by default)
 *     as one JSON line.
 */
class ActionGate(
    private val mode: ConfirmationMode,
    private val budget: ActionBudget,
    private val audit: AuditSink = AuditSink { System.err.println(it) },
    private val now: () -> Instant = Instant::now,
) {
    val budgetUsed: Int get() = budget.used()
    val budgetLimit: Int get() = budget.limit

    suspend fun authorize(
        tool: String,
        summary: String,
        details: List<Pair<String, String>>,
        approver: Approver,
    ): CallToolResult? {
        val permit = budget.tryAcquire()
        if (permit == null) {
            record(tool, "refused_budget", summary, details)
            return errorResult(
                "Refused: the state-change budget of ${budget.limit} actions per hour is exhausted. This brake exists " +
                    "to stop runaway or manipulated automation. Ask the human operator to review recent actions; the " +
                    "limit is set by ${Config.ENV_MAX_ACTIONS_PER_HOUR}.",
            )
        }
        if (mode == ConfirmationMode.NONE) {
            record(tool, "approved_unattended", summary, details)
            return null
        }
        val outcome = try {
            approver.approve(approvalMessage(summary, details))
        } catch (e: CancellationException) {
            budget.release(permit)
            throw e
        }
        if (outcome == ApprovalOutcome.APPROVED) {
            record(tool, "approved", summary, details)
            return null
        }
        budget.release(permit)
        record(tool, outcome.name.lowercase(), summary, details)
        return errorResult(
            when (outcome) {
                ApprovalOutcome.DECLINED ->
                    "The human operator declined this action, so nothing was changed. Do not retry it unless the operator asks."
                ApprovalOutcome.UNSUPPORTED ->
                    "Refused: this action needs explicit human approval, and the connected MCP client does not support " +
                        "elicitation (approval prompts). Nothing was changed. Use a client with elicitation support, or have " +
                        "the operator perform the action in the Microsoft Defender portal."
                else ->
                    "Refused: the approval prompt could not be completed (timed out or failed), so nothing was changed."
            },
        )
    }

    private fun record(tool: String, outcome: String, summary: String, details: List<Pair<String, String>>) {
        val line = buildJsonObject {
            put("ts", now().toString())
            put("event", "defender_action")
            put("tool", tool)
            put("outcome", outcome)
            put("summary", summary)
            put("details", buildJsonObject { details.forEach { (k, v) -> put(k, PromptShield.scrub(v).take(MAX_DETAIL)) } })
        }
        runCatching { audit.record("[defender-mcp] AUDIT " + JsonCodec.compact.encodeToString(kotlinx.serialization.json.JsonObject.serializer(), line)) }
    }

    companion object {
        private const val MAX_DETAIL = 500
        private val LINE_BREAKS = Regex("[\\r\\n\\u000B\\u000C\\u0085\\u2028\\u2029]")

        /** A value forced onto one line, with quotes replaced so it cannot close its own quotation. */
        internal fun oneLine(value: String): String =
            PromptShield.scrub(LINE_BREAKS.replace(value, " ")).replace('"', '\'').take(MAX_DETAIL)

        /**
         * The prompt shown to the human. Values come from the model (validated, but a comment is free
         * text), so they are scrubbed of invisible characters, clipped, quoted, and explicitly labelled
         * as AI-supplied so a persuasive comment ("routine, safe to approve") reads as what it is.
         */
        internal fun approvalMessage(summary: String, details: List<Pair<String, String>>): String = buildString {
            append("An AI assistant is requesting a Microsoft Defender for Endpoint action.\n\n")
            append("Action: ").append(summary).append("\n")
            details.forEach { (label, value) ->
                append("- ").append(label).append(" (supplied by the AI): \"")
                append(oneLine(value)).append("\"\n")
            }
            append("\nApprove only if you asked for this. Text above that came from the AI may have been influenced by ")
            append("untrusted data such as alert contents or command lines.")
        }
    }
}
