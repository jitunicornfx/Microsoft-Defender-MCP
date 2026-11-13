package com.jitunicornfx.defender.mcp.tools

import com.jitunicornfx.defender.mcp.OData
import com.jitunicornfx.defender.mcp.PageCursorStore
import com.jitunicornfx.defender.mcp.ResponseRenderer
import com.jitunicornfx.defender.mcp.SchemaBuilder
import com.jitunicornfx.defender.mcp.TENANT_ARG
import com.jitunicornfx.defender.mcp.ToolCall
import com.jitunicornfx.defender.mcp.Validators
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

internal const val MAX_TOP = 10_000
internal const val DEFAULT_TOP = 50
internal const val MAX_SKIP = 1_000_000
internal const val MAX_PAGES = 10

/** JSON-Schema patterns mirrored from [Validators], so clients can validate before calling. */
internal object Patterns {
    const val MACHINE_ID = "^[0-9a-fA-F]{40}$"
    const val GUID = "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
    const val OPAQUE_ID = "^[A-Za-z0-9_-]{1,128}$"
    const val STATE_NAME = "^[A-Za-z]{1,40}$"
}

private val STATE_NAME = Regex(Patterns.STATE_NAME)

/** A PascalCase enum-like state value (`Running`, `Active`, ...), validated but not enumerated. */
internal fun stateName(value: String, field: String): String {
    val v = value.trim()
    require(STATE_NAME.matches(v)) { "$field must be a single word of letters, such as Running." }
    return v
}

/** The `top`, `skip` and raw `filter` parameters shared by every OData list tool. */
internal fun SchemaBuilder.paging(filterFields: Set<String>, defaultTop: Int = DEFAULT_TOP) {
    integer("top", "Maximum records to return (OData \$top).", 1, MAX_TOP, defaultTop)
    integer("skip", "Records to skip in the first request (OData \$skip). To continue a listing, use page_token instead.", 0, MAX_SKIP, 0)
    string(
        "filter",
        "Optional raw OData \$filter, ANDed with the other filters. Allowed fields: " +
            filterFields.sorted().joinToString(", ") + ". Example: healthStatus eq 'Active' and riskScore eq 'High'.",
        maxLength = OData.MAX_FILTER_LENGTH,
    )
    cursorParams(listing = true)
}

/**
 * `page_token` and `max_pages`, for every tool that returns a collection. The token is opaque and
 * server-issued; the API's own next-page link never leaves the server.
 */
internal fun SchemaBuilder.cursorParams(listing: Boolean = false) {
    string(
        "page_token",
        "Continue a previous listing: pass the page_token from its result" +
            (if (listing) " and no other arguments except max_pages" else " with the same identifiers") + ".",
        pattern = PageCursorStore.TOKEN_PATTERN,
        maxLength = 32,
    )
    integer("max_pages", "Pages to fetch in this call, following the API's next-page links (results still respect the output budget).", 1, MAX_PAGES, 1)
}

/** Query parameters for an OData list call plus the rendering options matching its paging. */
internal fun ToolCall.listQuery(
    structured: String?,
    filterFields: Set<String>,
    defaultTop: Int = DEFAULT_TOP,
    orderBy: String? = null,
): Pair<List<Pair<String, String>>, ResponseRenderer.Options> {
    if (args.optString("page_token") != null) {
        // The token's link already carries the original filters, $top and $skip; anything else would be silently ignored.
        val extra = args.present - setOf("page_token", "max_pages", TENANT_ARG)
        require(extra.isEmpty()) {
            "page_token continues an existing listing, so it cannot be combined with ${extra.sorted().joinToString(", ")}. " +
                "Pass only page_token (and optionally max_pages), or start a new listing without page_token."
        }
        return emptyList<Pair<String, String>>() to ResponseRenderer.Options()
    }
    val raw = args.optString("filter")?.let { OData.validate(it, filterFields) }
    val filter = OData.and(structured, raw?.let { "($it)" })
    val top = args.int("top", 1, MAX_TOP, defaultTop)
    val skip = args.int("skip", 0, MAX_SKIP, 0)
    val query = buildList {
        add("\$top" to top.toString())
        if (skip > 0) add("\$skip" to skip.toString())
        filter?.let { add("\$filter" to it) }
        orderBy?.let { add("\$orderby" to it) }
    }
    return query to ResponseRenderer.Options()
}

/** List a collection at [path] with server-side paging (see [com.jitunicornfx.defender.mcp.Pager]). */
internal suspend fun ToolCall.pagedList(path: String, query: List<Pair<String, String>> = emptyList()): CallToolResult =
    pager.list(spec.name, path, query, args.optString("page_token"), args.int("max_pages", 1, MAX_PAGES, 1))

/** GET [path] and render it; the shape of single-entity read tools. */
internal suspend fun ToolCall.getAndRender(
    path: String,
    query: List<Pair<String, String>> = emptyList(),
    options: ResponseRenderer.Options = ResponseRenderer.Options(),
): CallToolResult = render(client.get(path, query), options)

internal fun seg(value: String) = Validators.seg(value)

internal fun jsonOf(vararg pairs: Pair<String, Any?>): JsonObject = JsonObject(
    pairs.mapNotNull { (k, v) ->
        when (v) {
            null -> null
            is String -> k to JsonPrimitive(v)
            is Number -> k to JsonPrimitive(v)
            is Boolean -> k to JsonPrimitive(v)
            is kotlinx.serialization.json.JsonElement -> k to v
            else -> throw IllegalArgumentException("unsupported JSON value for $k")
        }
    }.toMap(),
)
