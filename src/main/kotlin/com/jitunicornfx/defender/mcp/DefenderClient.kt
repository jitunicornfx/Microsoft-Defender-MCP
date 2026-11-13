package com.jitunicornfx.defender.mcp

import io.ktor.client.HttpClient
import io.ktor.client.HttpClientConfig
import io.ktor.client.engine.HttpClientEngine
import io.ktor.client.engine.okhttp.OkHttp
import io.ktor.client.plugins.HttpTimeout
import io.ktor.client.plugins.timeout
import io.ktor.client.request.header
import io.ktor.client.request.prepareRequest
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsChannel
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import io.ktor.http.URLBuilder
import io.ktor.http.contentType
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.readAvailable
import kotlinx.coroutines.delay
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.serialization.json.JsonElement
import java.io.ByteArrayOutputStream
import java.net.URI

/** Which upstream API, and so which base URL, token scope and rate limiter, a request goes to. */
enum class Upstream { DEFENDER, GRAPH }

/** Rate-limit pool a Defender request draws from. */
enum class RateBucket { DEFAULT, HUNTING, PACKAGE_URI }

/**
 * HTTP client for the Defender for Endpoint API (and Microsoft Graph for hunting).
 *
 *  - **Fixed destinations**: a request's URL is a configured base URL plus a server-built path, or
 *    (for paging only) an `@odata.nextLink` that [NextLinkPolicy] accepted: https, an allow-listed
 *    Defender host for the cloud, the same resource path. [getAbsolute] re-checks host, scheme, port,
 *    path prefix and length itself. Download links and any other response URL are never fetched.
 *  - **No redirects**: a 3xx could otherwise forward the bearer token to an arbitrary `Location`.
 *  - **Bounded memory**: bodies stream through a byte cap that aborts the transfer.
 *  - **Coroutine pacing**: a [Semaphore] bounds concurrent requests; per-bucket sliding-window
 *    limiters keep calls inside Defender's published quotas; 429s are retried after `Retry-After`
 *    (bounded), and a 401 refreshes the token once.
 */
class DefenderClient(
    private val config: Config,
    engine: HttpClientEngine? = null,
    clock: () -> Long = System::currentTimeMillis,
    private val sleep: suspend (Long) -> Unit = { delay(it) },
    /** Longest `Retry-After` honoured; a longer one is returned to the caller as the 429 it is. */
    private val maxRetryAfterMillis: Long = 30_000,
    private val maxRetries: Int = 2,
) : AutoCloseable {

    /** Raw HTTP result. [text] is the (possibly truncated) body decoded as UTF-8. */
    data class ApiResponse(
        val status: Int,
        val contentType: String?,
        val text: String,
        val truncated: Boolean = false,
        val limitBytes: Long = 0,
    ) {
        val ok: Boolean get() = status in 200..299
    }

    private val http: HttpClient = if (engine != null) {
        HttpClient(engine) { configure() }
    } else {
        HttpClient(OkHttp) {
            configure()
            engine {
                config {
                    followRedirects(false)
                    followSslRedirects(false)
                    // Off: OkHttp would otherwise silently replay a POST whose response was lost, and a
                    // state change must never run twice. Retries happen only in request(), which
                    // knows which calls are idempotent.
                    retryOnConnectionFailure(false)
                }
            }
        }
    }

    private fun HttpClientConfig<*>.configure() {
        expectSuccess = false
        followRedirects = false
        install(HttpTimeout) {
            requestTimeoutMillis = config.requestTimeoutMillis
            connectTimeoutMillis = 15_000
            socketTimeoutMillis = config.requestTimeoutMillis
        }
    }

    val tokens = EntraTokenProvider(config, http, clock)
    private val concurrency = Semaphore(config.maxConcurrentRequests)
    private val limiters = mapOf(
        RateBucket.DEFAULT to SlidingWindowRateLimiter.defenderDefault(clock, sleep),
        RateBucket.HUNTING to SlidingWindowRateLimiter.advancedHunting(clock, sleep),
        RateBucket.PACKAGE_URI to SlidingWindowRateLimiter(listOf(RateRule(2, 60_000), RateRule(120, 3_600_000)), clock, sleep),
    )

    private fun baseUrl(upstream: Upstream) = when (upstream) {
        Upstream.DEFENDER -> config.apiBaseUrl
        Upstream.GRAPH -> config.cloud.graphBaseUrl
    }

    private fun scope(upstream: Upstream) = when (upstream) {
        Upstream.DEFENDER -> config.cloud.scope
        Upstream.GRAPH -> config.cloud.graphScope
    }

    suspend fun get(
        path: String,
        query: List<Pair<String, String>> = emptyList(),
        bucket: RateBucket = RateBucket.DEFAULT,
    ): ApiResponse = request(HttpMethod.Get, path, query, null, bucket, idempotent = true)

    /**
     * Perform one API call.
     *
     * @param path absolute path beginning with `/`, built from validated, [Validators.seg]-encoded parts.
     * @param idempotent whether a transient 5xx may be retried (true for reads, including the
     *   read-only hunting POST; false for state changes, which are never replayed on a 5xx because
     *   the first attempt may have taken effect).
     */
    suspend fun request(
        method: HttpMethod,
        path: String,
        query: List<Pair<String, String>> = emptyList(),
        body: JsonElement? = null,
        bucket: RateBucket = RateBucket.DEFAULT,
        idempotent: Boolean = method == HttpMethod.Get,
        upstream: Upstream = Upstream.DEFENDER,
    ): ApiResponse {
        require(path.startsWith("/") && !path.startsWith("//")) { "path must be absolute" }
        return send(method, baseUrl(upstream) + path, query, body, bucket, idempotent, scope(upstream))
    }

    /** The absolute URL a GET of [path] with [query] would request; the first link of a paged listing. */
    fun urlFor(path: String, query: List<Pair<String, String>> = emptyList()): String {
        require(path.startsWith("/") && !path.startsWith("//")) { "path must be absolute" }
        return URLBuilder(config.apiBaseUrl + path).apply { query.forEach { (k, v) -> parameters.append(k, v) } }.buildString()
    }

    /**
     * GET an absolute Defender URL as-is: the first link of a listing or an `@odata.nextLink` that
     * [NextLinkPolicy] accepted. The host is checked again here, so no caller can send the bearer
     * token to a host outside the cloud's Defender hosts.
     */
    suspend fun getAbsolute(link: String): ApiResponse {
        val uri = runCatching { URI(link) }.getOrNull()
        check(
            uri != null && uri.scheme == "https" && uri.rawUserInfo == null && uri.rawFragment == null &&
                (uri.port == -1 || uri.port == 443) && link.length <= NextLinkPolicy.MAX_LINK_LENGTH &&
                link.none { it.isISOControl() || it == ' ' } && uri.rawPath?.startsWith("/api/", ignoreCase = true) == true &&
                uri.host?.lowercase() in NextLinkPolicy.allowedHosts(config),
        ) {
            "Refusing to request a link outside the configured Defender hosts."
        }
        return send(HttpMethod.Get, link, emptyList(), null, RateBucket.DEFAULT, true, config.cloud.scope)
    }

    private suspend fun send(
        method: HttpMethod,
        url: String,
        query: List<Pair<String, String>>,
        body: JsonElement?,
        bucket: RateBucket,
        idempotent: Boolean,
        scope: String,
    ): ApiResponse {
        var attempt = 0
        var refreshedToken = false
        while (true) {
            limiters.getValue(bucket).acquire()
            val token = tokens.token(scope)
            val response = concurrency.withPermit {
                http.prepareRequest(url) {
                    this.method = method
                    header(HttpHeaders.Authorization, "Bearer $token")
                    header(HttpHeaders.Accept, "application/json")
                    url { query.forEach { (k, v) -> parameters.append(k, v) } }
                    if (bucket == RateBucket.HUNTING) {
                        val huntingTimeout = maxOf(config.requestTimeoutMillis, HUNTING_TIMEOUT_MILLIS)
                        timeout {
                            requestTimeoutMillis = huntingTimeout
                            socketTimeoutMillis = huntingTimeout
                        }
                    }
                    if (body != null) {
                        contentType(ContentType.Application.Json)
                        setBody(JsonCodec.compact.encodeToString(JsonElement.serializer(), body))
                    }
                }.execute { it.toApiResponse(it.headers[HttpHeaders.RetryAfter]) }
            }
            val (api, retryAfter) = response
            when {
                api.status == 401 && !refreshedToken -> {
                    tokens.invalidate(scope)
                    refreshedToken = true
                    continue
                }
                api.status == 429 && attempt < maxRetries -> {
                    val wait = retryAfterMillis(retryAfter, attempt)
                    if (wait > maxRetryAfterMillis) return api
                    attempt++
                    sleep(wait)
                    continue
                }
                api.status in TRANSIENT && idempotent && attempt < maxRetries -> {
                    attempt++
                    sleep(backoffMillis(attempt))
                    continue
                }
                else -> return api
            }
        }
    }

    private suspend fun HttpResponse.toApiResponse(retryAfter: String?): Pair<ApiResponse, String?> {
        val limit = config.maxResponseBytes
        val (bytes, truncated) = readCapped(bodyAsChannel(), limit)
        val text = (if (truncated) trimIncompleteUtf8(bytes) else bytes).toString(Charsets.UTF_8)
        return ApiResponse(
            status = status.value,
            contentType = headers[HttpHeaders.ContentType],
            text = text,
            truncated = truncated,
            limitBytes = limit,
        ) to retryAfter
    }

    override fun close() {
        http.close()
    }

    companion object {
        private val TRANSIENT = setOf(502, 503, 504)

        /** `Retry-After` in seconds (the HTTP-date form is not used by Defender), else exponential backoff. */
        internal fun retryAfterMillis(header: String?, attempt: Int): Long {
            val seconds = header?.trim()?.toLongOrNull()?.takeIf { it >= 0 } ?: return backoffMillis(attempt + 1)
            // Saturate rather than overflow: a huge Retry-After must stay huge, never wrap to "now".
            return if (seconds > Long.MAX_VALUE / 1000) Long.MAX_VALUE else seconds * 1000
        }

        /** Advanced hunting may run for 200 s server-side; give it room beyond the general timeout. */
        const val HUNTING_TIMEOUT_MILLIS = 210_000L

        internal fun backoffMillis(attempt: Int): Long = 1_000L shl (attempt - 1).coerceIn(0, 5)

        /** Read at most [limit] bytes from [channel]; returns the bytes and whether more remained. */
        internal suspend fun readCapped(channel: ByteReadChannel, limit: Long): Pair<ByteArray, Boolean> {
            val out = ByteArrayOutputStream()
            val buffer = ByteArray(16 * 1024)
            while (true) {
                val read = channel.readAvailable(buffer, 0, buffer.size)
                if (read < 0) break
                if (read == 0) continue
                val remaining = limit - out.size()
                if (read > remaining) {
                    out.write(buffer, 0, remaining.toInt())
                    channel.cancel(null)
                    return out.toByteArray() to true
                }
                out.write(buffer, 0, read)
                if (out.size() >= limit) {
                    val more = channel.readAvailable(buffer, 0, 1) > 0
                    channel.cancel(null)
                    return out.toByteArray() to more
                }
            }
            return out.toByteArray() to false
        }

        /** Drop a trailing incomplete UTF-8 sequence left where the byte cap split a character. */
        internal fun trimIncompleteUtf8(bytes: ByteArray): ByteArray {
            if (bytes.isEmpty()) return bytes
            var lead = bytes.size - 1
            while (lead >= 0 && (bytes[lead].toInt() and 0xC0) == 0x80) {
                if (bytes.size - lead > 4) return bytes
                lead--
            }
            if (lead < 0) return bytes
            val b = bytes[lead].toInt() and 0xFF
            val expected = when {
                b and 0x80 == 0x00 -> 1
                b and 0xE0 == 0xC0 -> 2
                b and 0xF0 == 0xE0 -> 3
                b and 0xF8 == 0xF0 -> 4
                else -> return bytes
            }
            return if (lead + expected > bytes.size) bytes.copyOf(lead) else bytes
        }
    }
}
