package com.jitunicornfx.defender.mcp

import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import java.net.URI
import java.security.SecureRandom
import java.util.Base64

/**
 * Server-side paging that follows the Microsoft Graph / OData paging rules
 * (https://learn.microsoft.com/en-us/graph/paging):
 *
 *  - **`@odata.nextLink` is requested verbatim.** It already carries `$skip`/`$skiptoken` and every
 *    original query option; it is never parsed apart and rebuilt.
 *  - **The model never sees a URL.** Each continuation is stored here under an opaque, random,
 *    short-lived `page_token`, bound to the tool that issued it. A link taken from a response could
 *    otherwise be relayed or rewritten by a manipulated model, and remote URLs are untrusted data.
 *  - **Links are checked before they are stored**: https, an allow-listed Defender host for the
 *    configured cloud, and the SAME resource path as the original request, so a response can never
 *    steer the credentialed client to another host or another endpoint.
 *  - **`DirectoryPageTokenNotFoundException` recovery**: Graph documents that a token obtained from
 *    a retried request may be invalid for later pages, and that the client must keep the link from
 *    the last successful response. Every cursor therefore also remembers the link of the page that
 *    produced it (and how many of its records were already delivered). If the API rejects a page
 *    token with that error, the pager re-requests that last good link once, skips the records the
 *    caller already has, and continues from its fresh nextLink.
 */

/** Where the next page starts: a link to GET plus how many of that page's records to skip. */
data class PageCursor(
    val tool: String,
    /** The resource path every link of this listing must stay on (lowercased, normalized). */
    val resourcePath: String,
    /** Absolute URL to request verbatim. */
    val link: String,
    /** Records at the start of [link]'s page that were already returned. */
    val offset: Int = 0,
    /** The last link known to have succeeded, used to recover from an invalid page token. */
    val fallback: PageCursor? = null,
)

/**
 * Opaque, expiring page tokens. Bounded in size (oldest evicted first) and time, so abandoned
 * listings cannot accumulate. Tokens are 192-bit random values, unguessable and unforgeable, and a
 * token only works for the tool that issued it.
 */
class PageCursorStore(
    private val ttlMillis: Long = DEFAULT_TTL_MILLIS,
    private val maxEntries: Int = DEFAULT_MAX_ENTRIES,
    private val clock: () -> Long = System::currentTimeMillis,
) {
    private class Entry(val cursor: PageCursor, val expiresAt: Long)

    private val entries = LinkedHashMap<String, Entry>()
    private val random = SecureRandom()

    @Synchronized
    fun put(cursor: PageCursor): String {
        purge()
        while (entries.size >= maxEntries) entries.remove(entries.keys.first())
        val bytes = ByteArray(24).also(random::nextBytes)
        val token = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
        entries[token] = Entry(cursor, clock() + ttlMillis)
        return token
    }

    /**
     * The cursor for [token] if it exists, has not expired and belongs to [tool]. Tokens stay valid
     * until they expire, so a client that retries a call with the same token gets the same page.
     */
    @Synchronized
    fun get(token: String, tool: String): PageCursor? {
        purge()
        val entry = entries[token] ?: return null
        return entry.cursor.takeIf { it.tool == tool }
    }

    @Synchronized
    fun remove(token: String) {
        entries.remove(token)
    }

    @Synchronized
    fun size(): Int {
        purge()
        return entries.size
    }

    private fun purge() {
        val now = clock()
        entries.values.removeAll { it.expiresAt <= now }
    }

    companion object {
        const val DEFAULT_TTL_MILLIS = 30 * 60_000L
        const val DEFAULT_MAX_ENTRIES = 1_000
        const val TOKEN_PATTERN = "^[A-Za-z0-9_-]{32}$"
        private val TOKEN = Regex(TOKEN_PATTERN)

        fun isWellFormed(token: String) = TOKEN.matches(token)
    }
}

/** Which hosts and paths a next-page link may point at. */
object NextLinkPolicy {
    /**
     * Hosts the Defender API may hand out nextLinks on, for [config]'s cloud: the configured host,
     * and in the commercial cloud the global, legacy and regional Defender hosts. Fixed names only.
     */
    fun allowedHosts(config: Config): Set<String> = buildSet {
        add(URI(config.apiBaseUrl).host.lowercase())
        add(URI(config.cloud.apiBaseUrl).host.lowercase())
        if (config.cloud == CloudEnvironment.COMMERCIAL) {
            add("api.securitycenter.microsoft.com")
            DefenderRegion.entries.forEach { add(it.host) }
            listOf("us", "eu", "uk", "au").forEach { add("api-$it.securitycenter.microsoft.com") }
        }
    }

    /** `/api/v1.0/machines/` and `/API/Machines` both normalize to `/api/machines`. */
    fun normalizePath(path: String): String =
        path.lowercase().trimEnd('/').replaceFirst(Regex("^/api/v\\d+(\\.\\d+)?/"), "/api/")

    /**
     * Validate [link] for a listing of [resourcePath]; returns it unchanged when acceptable, null
     * otherwise. A link that fails is never requested.
     */
    fun accept(link: String, resourcePath: String, config: Config): String? {
        if (link.length > MAX_LINK_LENGTH || link.any { it.isISOControl() || it == ' ' }) return null
        val uri = runCatching { URI(link) }.getOrNull() ?: return null
        if (uri.scheme != "https" || uri.rawUserInfo != null || uri.rawFragment != null) return null
        if (uri.port != -1 && uri.port != 443) return null
        val host = uri.host?.lowercase() ?: return null
        if (host !in allowedHosts(config)) return null
        val path = uri.rawPath ?: return null
        if (path.contains("%2e", ignoreCase = true) || path.split('/').any { it == "." || it == ".." }) return null
        if (normalizePath(path) != resourcePath) return null
        return link
    }

    const val MAX_LINK_LENGTH = 8_192
}

/**
 * Fetches one or more pages of a collection and renders them with an opaque continuation token.
 * Coroutine-friendly: pages are requested sequentially (each needs the previous page's link), each
 * through the shared rate limiters.
 */
class Pager(
    private val config: Config,
    private val client: DefenderClient,
    private val renderer: ResponseRenderer,
    private val cursors: PageCursorStore,
) {
    /** One fetched page: the cursor that produced it and the records it contributed. */
    private class Segment(val cursor: PageCursor, val records: List<JsonElement>)

    /**
     * List a collection.
     *
     * @param tool the calling tool's name (tokens are bound to it).
     * @param path the resource path, already validated and encoded.
     * @param query the first request's query options (`$top`, `$skip`, `$filter`); ignored when resuming.
     * @param pageToken a token from a previous call, to continue that listing.
     * @param maxPages how many pages to follow in this call.
     */
    suspend fun list(
        tool: String,
        path: String,
        query: List<Pair<String, String>>,
        pageToken: String?,
        maxPages: Int,
    ): CallToolResult {
        val start = if (pageToken != null) {
            require(PageCursorStore.isWellFormed(pageToken)) { "page_token is not a token issued by this server." }
            val resumed = cursors.get(pageToken, tool) ?: throw IllegalArgumentException(
                "page_token is unknown or has expired (tokens last ${PageCursorStore.DEFAULT_TTL_MILLIS / 60_000} minutes and only " +
                    "work with the tool and tenant that issued them). Restart the listing without page_token.",
            )
            require(resumed.resourcePath == NextLinkPolicy.normalizePath(path)) {
                "page_token belongs to a different listing (another device, user, domain or IP). Pass the same identifiers as the call that issued it."
            }
            resumed
        } else {
            PageCursor(tool, NextLinkPolicy.normalizePath(path), client.urlFor(path, query))
        }

        val segments = mutableListOf<Segment>()
        var cursor: PageCursor? = start
        var recovered = false
        var stopNotice: String? = null
        var pages = 0
        var gatheredChars = 0L
        // Stop following links once more text is in hand than one result can show: the rest would be
        // parsed only to be thrown away (and fetched again on the next call).
        while (cursor != null && pages < maxPages && gatheredChars <= renderer.maxChars) {
            val response = client.getAbsolute(cursor.link)
            if (!response.ok) {
                // Only a request that used a page link can have a stale page token; a first request's error is shown as is.
                if (isPageTokenNotFound(response) && (pageToken != null || cursor.fallback != null || recovered)) {
                    val fallback = cursor.fallback
                    if (fallback != null && !recovered) {
                        // Re-read the last page that succeeded, skip what was already delivered from it,
                        // and continue from its fresh nextLink.
                        recovered = true
                        cursor = fallback.copy(offset = fallback.offset + cursor.offset, fallback = null)
                        continue
                    }
                    pageToken?.let(cursors::remove)
                    if (segments.all { it.records.isEmpty() }) return pageTokenExpired()
                    stopNotice = "[Paging stopped: the next page token was rejected (DirectoryPageTokenNotFoundException). " +
                        "The records above are valid; restart the listing without page_token to see the rest.]"
                    cursor = null
                    break
                }
                if (segments.isEmpty()) return renderer.render(response)
                stopNotice = "[Paging stopped early: the next page returned HTTP ${response.status}. The records above are valid; " +
                    "call again with the page_token below to retry that page.]"
                break
            }
            val json = runCatching { JsonCodec.compact.parseToJsonElement(response.text) }.getOrNull()
            val records = (json as? JsonObject)?.get("value") as? JsonArray
            if (json !is JsonObject || records == null) {
                // Not a collection: nothing to page; show it as it is.
                if (segments.isEmpty()) return renderer.render(response)
                stopNotice = if (response.truncated) {
                    // Retrying would hit the same memory guard, so no retry token: a smaller 'top' is the fix.
                    cursor = null
                    "[Paging stopped: the next page exceeded the server's ${response.limitBytes}-byte memory guard. Restart the " +
                        "listing with a lower 'top' to page through the rest.]"
                } else {
                    // Keep the cursor: the page_token below retries this page.
                    "[Paging stopped early: the next page was not a record list. The records above are valid; call again with " +
                        "the page_token below to retry that page.]"
                }
                break
            }
            val current: PageCursor = cursor
            val rawNext = (json["@odata.nextLink"] as? JsonPrimitive)?.contentOrNull
            val next = rawNext?.let { NextLinkPolicy.accept(it, current.resourcePath, config) }
            if (rawNext != null && next == null) {
                stopNotice = "[Defender returned a next-page link that failed this server's safety checks (unexpected host or " +
                    "path), so paging stopped here. Narrow the query to see the remaining records.]"
            }
            // An offset past the end of this page (only after a recovery) carries into the next page.
            val carry = (current.offset - records.size).coerceAtLeast(0)
            val skippedWholePage = current.offset >= records.size && records.isNotEmpty()
            segments += Segment(current, records.drop(current.offset))
            gatheredChars += response.text.length
            if (!(skippedWholePage && next != null)) pages++
            // The page just read is the last known-good link: re-reading it in full and skipping all of its
            // records is how a later invalid page token is recovered from.
            val goodPoint = current.copy(offset = records.size, fallback = null)
            cursor = next?.let { PageCursor(tool, current.resourcePath, it, carry, goodPoint) }
            if (response.truncated) {
                stopNotice = "[A page was truncated at ${response.limitBytes} bytes by the server's memory guard; " +
                    "lower 'top' to page through the rest.]"
                cursor = null
            }
        }

        val all = segments.flatMap { it.records }
        return renderer.renderCollection(all) { kept ->
            val continuation = continuationAfter(segments, kept) ?: if (kept == all.size) cursor else null
            buildString {
                if (kept < all.size || continuation != null) {
                    append("[Showing ${kept} record(s)")
                    if (kept < all.size) append(" of ${all.size} fetched, to stay within the output budget")
                    append(".")
                    if (continuation != null) {
                        append(" More results are available: call this tool again with page_token=\"")
                        append(cursors.put(continuation))
                        append("\" (keep identifier arguments such as machine_id; omit filters, top and skip).")
                    }
                    append("]")
                }
                stopNotice?.let { if (isNotEmpty()) append("\n"); append(it) }
                if (recovered) {
                    if (isNotEmpty()) append("\n")
                    append(
                        "[A stale page token (DirectoryPageTokenNotFoundException) was replaced by re-reading the last successful " +
                            "page and resuming by position. If records were added or removed meanwhile, a few may be repeated or missed.]",
                    )
                }
            }.ifEmpty { null }
        }
    }

    /** The cursor pointing at record [kept] (zero-based, across all segments), or null when all were shown. */
    private fun continuationAfter(segments: List<Segment>, kept: Int): PageCursor? {
        var start = 0
        for (segment in segments) {
            val end = start + segment.records.size
            if (kept < end) return segment.cursor.copy(offset = segment.cursor.offset + (kept - start))
            start = end
        }
        return null
    }

    private fun pageTokenExpired(): CallToolResult = errorResult(
        "The paging token was rejected by the Defender API (DirectoryPageTokenNotFoundException): it is no longer valid, " +
            "typically because it came from a retried request or the listing changed. Nothing is wrong with your query: " +
            "restart the listing without page_token.",
    )

    companion object {
        const val PAGE_TOKEN_NOT_FOUND = "DirectoryPageTokenNotFoundException"

        /** True when [response] reports an invalid/expired page token. Only a boolean leaves this check. */
        internal fun isPageTokenNotFound(response: DefenderClient.ApiResponse): Boolean {
            if (response.ok) return false
            val error = runCatching {
                (JsonCodec.compact.parseToJsonElement(response.text) as? JsonObject)?.get("error") as? JsonObject
            }.getOrNull()
            val code = (error?.get("code") as? JsonPrimitive)?.contentOrNull
            val message = (error?.get("message") as? JsonPrimitive)?.contentOrNull
            return listOfNotNull(code, message, response.text.takeIf { error == null })
                .any { it.contains(PAGE_TOKEN_NOT_FOUND, ignoreCase = true) }
        }
    }
}
