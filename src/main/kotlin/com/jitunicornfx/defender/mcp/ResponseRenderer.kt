package com.jitunicornfx.defender.mcp

import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull

/**
 * Turns Defender API responses into model-safe tool results.
 *
 * Every byte of API-originated text is cleaned and fenced by [PromptShield]; everything outside the
 * fence (status lines, hints, paging and truncation notices) is server-authored and contains no
 * remote text. OData noise (`@odata.context`) is dropped and `@odata.nextLink` is never shown: a URL
 * from a response is something the model might be talked into fetching or relaying. Collections are
 * paged by [Pager], which keeps the link server-side and hands out an opaque `page_token` instead.
 */
class ResponseRenderer(val maxChars: Int) {

    /** Optional knobs for one rendering. */
    data class Options(
        /** Keep at most this many records of the result list (client-side row cap). */
        val maxRecords: Int? = null,
        /**
         * What to tell the model when the list was trimmed. Collections that page do so through
         * [Pager] and its page_token; plain renders can only advise narrowing the request.
         */
        val hint: String? = null,
    )

    fun render(response: DefenderClient.ApiResponse, options: Options = Options()): CallToolResult {
        if (!response.ok) return renderError(response)
        if (response.text.isBlank()) {
            return CallToolResult(content = listOf(TextContent("Success (HTTP ${response.status}, empty response body).")))
        }
        val parsed = runCatching { JsonCodec.compact.parseToJsonElement(response.text) }.getOrNull()
        val text = if (parsed == null) {
            renderText(response.text, response.truncated, response.limitBytes)
        } else {
            renderJson(parsed, options, response.truncated, response.limitBytes)
        }
        return CallToolResult(content = listOf(TextContent(text)))
    }

    /**
     * Render a page-assembled record list as `{"value": [...]}`, trimmed to the budget. [notice] gets
     * the number of records kept and returns the server-authored continuation text (or null); it is
     * appended outside the fence.
     */
    fun renderCollection(records: List<JsonElement>, notice: (kept: Int) -> String?): CallToolResult {
        fun assemble(keep: Int): JsonElement = JsonObject(mapOf("value" to JsonArray(records.take(keep))))
        var shield = PromptShield.sanitize(assemble(records.size))
        var body = JsonCodec.pretty.encodeToString(JsonElement.serializer(), shield.element)
        var kept = records.size
        if (body.length > maxChars && records.isNotEmpty()) {
            var lo = 0
            var hi = records.size
            while (lo < hi) {
                val mid = (lo + hi + 1) / 2
                val candidate = JsonCodec.pretty.encodeToString(JsonElement.serializer(), PromptShield.sanitize(assemble(mid)).element)
                if (candidate.length <= maxChars) lo = mid else hi = mid - 1
            }
            // Always make progress: one record larger than the budget is shown cut, so paging never stalls.
            kept = maxOf(lo, 1)
            shield = PromptShield.sanitize(assemble(kept))
            body = JsonCodec.pretty.encodeToString(JsonElement.serializer(), shield.element)
        }
        val hardCut = body.length > maxChars
        if (hardCut) body = body.take(maxChars)
        val text = buildString {
            append(PromptShield.fence(body))
            if (shield.suspiciousStrings > 0) append("\n\n").append(PromptShield.suspicionNotice(shield.suspiciousStrings))
            notice(kept)?.let { append("\n\n").append(it) }
            if (hardCut) append("\n\n[Output cut at $maxChars characters; one record is larger than the output budget.]")
        }
        return CallToolResult(content = listOf(TextContent(text)))
    }

    /** Render a JSON tree the server assembled itself (composite tools), with the same protections. */
    fun renderTree(element: JsonElement, options: Options = Options()): CallToolResult =
        CallToolResult(content = listOf(TextContent(renderJson(element, options, false, 0))))

    private fun renderError(response: DefenderClient.ApiResponse): CallToolResult {
        val parsed = runCatching { JsonCodec.compact.parseToJsonElement(response.text) as? JsonObject }.getOrNull()
        val error = parsed?.get("error") as? JsonObject
        val code = (error?.get("code") as? JsonPrimitive)?.contentOrNull?.takeIf { ERROR_CODE.matches(it) }
        val message = (error?.get("message") as? JsonPrimitive)?.contentOrNull
        val text = buildString {
            append("Defender API returned HTTP ${response.status}")
            code?.let { append(" ($it)") }
            append('.')
            statusHint(response.status)?.let { append(' ').append(it) }
            val detail = message ?: response.text.takeIf { it.isNotBlank() && parsed == null }
            if (detail != null) {
                val cleaned = PromptShield.clean(detail.take(MAX_ERROR_DETAIL))
                append("\n\n")
                append(PromptShield.fence(cleaned))
                if (PromptShield.looksLikeInjection(cleaned)) append("\n\n").append(PromptShield.suspicionNotice(1))
            }
        }
        return CallToolResult(content = listOf(TextContent(text)), isError = true)
    }

    private fun renderText(raw: String, truncated: Boolean, limit: Long): String {
        val cleaned = PromptShield.clean(raw)
        val cut = cleaned.length > maxChars
        val body = if (cut) cleaned.take(maxChars) else cleaned
        return buildString {
            append(PromptShield.fence(body))
            if (PromptShield.looksLikeInjection(body)) append("\n\n").append(PromptShield.suspicionNotice(1))
            if (cut) append("\n\n[Output cut at $maxChars characters; narrow the request to see the rest.]")
            if (truncated) append("\n[Response body truncated at $limit bytes by the server's memory guard.]")
        }
    }

    private fun renderJson(element: JsonElement, options: Options, truncated: Boolean, limit: Long): String {
        var root = element
        var moreAvailable = false
        if (root is JsonObject) {
            if (root.containsKey(NEXT_LINK)) moreAvailable = true
            root = JsonObject(root.filterKeys { it != NEXT_LINK && it != CONTEXT && !it.startsWith("@odata.") })
        }

        val listKey = (root as? JsonObject)?.keys?.firstOrNull { it in LIST_KEYS && root[it] is JsonArray }
        var records: List<JsonElement>? = listKey?.let { (root as JsonObject)[it] as JsonArray }
            ?: (root as? JsonArray)?.toList()
        val totalRecords = records?.size
        var rowCapped = false
        if (records != null && options.maxRecords != null && records.size > options.maxRecords) {
            records = records.take(options.maxRecords)
            rowCapped = true
        }

        fun assemble(keep: Int?): JsonElement = when {
            records == null || keep == null -> root
            listKey != null -> JsonObject((root as JsonObject).toMutableMap().apply { put(listKey, JsonArray(records.take(keep))) })
            else -> JsonArray(records.take(keep))
        }

        var shield = PromptShield.sanitize(assemble(records?.size))
        var body = JsonCodec.pretty.encodeToString(JsonElement.serializer(), shield.element)
        var kept = records?.size
        if (body.length > maxChars && records != null && records.isNotEmpty()) {
            // Binary search the largest record prefix that fits the budget.
            var lo = 0
            var hi = records.size
            while (lo < hi) {
                val mid = (lo + hi + 1) / 2
                val candidate = JsonCodec.pretty.encodeToString(JsonElement.serializer(), PromptShield.sanitize(assemble(mid)).element)
                if (candidate.length <= maxChars) lo = mid else hi = mid - 1
            }
            kept = lo
            shield = PromptShield.sanitize(assemble(lo))
            body = JsonCodec.pretty.encodeToString(JsonElement.serializer(), shield.element)
        }
        val hardCut = body.length > maxChars
        if (hardCut) body = body.take(maxChars)

        return buildString {
            append(PromptShield.fence(body))
            if (shield.suspiciousStrings > 0) append("\n\n").append(PromptShield.suspicionNotice(shield.suspiciousStrings))
            val trimmed = totalRecords != null && kept != null && kept < totalRecords
            if (trimmed) {
                append("\n\n[Showing $kept of $totalRecords records")
                append(if (rowCapped && kept == options.maxRecords) " (row cap)" else " to stay within the output budget")
                append(". ").append(options.hint ?: "Narrow the request (filters, a more specific identifier) to see the rest.").append("]")
            } else if (moreAvailable) {
                append("\n\n[More results are available; narrow the request to reach them.]")
            }
            if (hardCut) append("\n\n[Output cut at $maxChars characters; the result is a single large record. Narrow the request.]")
            if (truncated) append("\n[Response body truncated at $limit bytes by the server's memory guard; the data may be incomplete.]")
        }
    }

    companion object {
        private const val NEXT_LINK = "@odata.nextLink"
        private const val CONTEXT = "@odata.context"
        private const val MAX_ERROR_DETAIL = 2_000
        private val LIST_KEYS = listOf("value", "Results", "results")
        private val ERROR_CODE = Regex("^[A-Za-z0-9_.]{1,64}$")

        /** Server-authored next step for an HTTP status. Never quotes the response. */
        internal fun statusHint(status: Int): String? = when (status) {
            in 300..399 -> "The API answered with a redirect, which this server never follows because the bearer token " +
                "would travel with it. Check ${Config.ENV_REGION} / ${Config.ENV_CLOUD}."
            400 -> "The request was rejected as malformed: re-check identifiers, filter syntax and value formats."
            401 -> "Authentication failed even after refreshing the token: check the app registration's credentials and that admin consent was granted."
            403 -> "Forbidden: the app registration lacks the required Defender API permission (or admin consent), " +
                "or the device is outside the app's RBAC device-group scope."
            404 -> "Not found: the identifier may be wrong, or the entity is outside the retention period."
            409 -> "Conflict: the entity is in a state that does not allow this operation (e.g. an action is already pending)."
            429 -> "Rate limited by Defender (per-tenant quota or hunting CPU quota): wait before retrying."
            in 500..599 -> "Defender service error: retrying later may succeed."
            else -> null
        }
    }
}
