package com.jitunicornfx.defender.mcp

import io.ktor.client.HttpClient
import io.ktor.client.request.forms.FormDataContent
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpHeaders
import io.ktor.http.Parameters
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull
import java.util.concurrent.ConcurrentHashMap

/** Raised when Entra ID refuses or fails a token request. Its message is entirely server-authored. */
class TokenAcquisitionException(message: String) : RuntimeException(message)

/**
 * Acquires OAuth 2.0 client-credentials access tokens from Microsoft Entra ID, one cached token per
 * scope (Defender API, and Microsoft Graph when it is the hunting backend).
 *
 * Coroutine-safe: concurrent tool calls that find the token missing or near expiry wait on one
 * [Mutex] per scope, so exactly one refresh happens and the rest reuse its result. Tokens are
 * refreshed [refreshSkewMillis] before they expire. Nothing from an error response's free text
 * (`error_description`) is ever surfaced: only the OAuth `error` code and `AADSTS` numbers, both
 * validated against strict patterns, are reported, with fixed hints for the common ones.
 */
class EntraTokenProvider(
    private val config: Config,
    private val http: HttpClient,
    private val clock: () -> Long = System::currentTimeMillis,
    private val refreshSkewMillis: Long = 5 * 60_000L,
) {
    /** [refreshAt] is when to stop reusing the token: the skew before expiry, or half its life if shorter. */
    private data class CachedToken(val value: String, val refreshAt: Long)

    private val cache = ConcurrentHashMap<String, CachedToken>()
    private val locks = ConcurrentHashMap<String, Mutex>()

    /** A valid bearer token for [scope], from cache or freshly acquired. */
    suspend fun token(scope: String): String {
        fresh(scope)?.let { return it }
        return locks.computeIfAbsent(scope) { Mutex() }.withLock {
            // Another caller may have refreshed while this one waited.
            fresh(scope) ?: acquire(scope).also { cache[scope] = it }.value
        }
    }

    /** Forget the cached token for [scope] (after the API rejected it with 401). */
    fun invalidate(scope: String) {
        cache.remove(scope)
    }

    private fun fresh(scope: String): String? =
        cache[scope]?.takeIf { clock() < it.refreshAt }?.value

    private suspend fun acquire(scope: String): CachedToken {
        val creds = config.credentials
        val response = try {
            http.post(config.tokenUrl) {
                header(HttpHeaders.Accept, "application/json")
                setBody(
                    FormDataContent(
                        Parameters.build {
                            append("grant_type", "client_credentials")
                            append("client_id", creds.clientId)
                            append("client_secret", creds.clientSecret)
                            append("scope", scope)
                        },
                    ),
                )
            }
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (e: Exception) {
            throw TokenAcquisitionException(
                "Could not reach Microsoft Entra ID at ${config.cloud.loginBaseUrl} (${e::class.simpleName}). " +
                    "Check network access and proxy settings.",
            )
        }
        val text = runCatching { response.bodyAsText() }.getOrDefault("")
        val json = runCatching { Json.parseToJsonElement(text) as? JsonObject }.getOrNull()
        if (response.status.value !in 200..299) {
            throw TokenAcquisitionException(
                describeFailure(response.status.value, json, config.tenantName.takeIf { config.namedTenants }, config::variableFor),
            )
        }
        val token = (json?.get("access_token") as? JsonPrimitive)?.takeIf { it.isString }?.contentOrNull
            ?: throw TokenAcquisitionException("Microsoft Entra ID returned a token response without an access_token.")
        if (!TOKEN_CHARS.matches(token)) throw TokenAcquisitionException("Microsoft Entra ID returned a malformed access token.")
        val expiresIn = (json["expires_in"] as? JsonPrimitive)?.let { it.longOrNull ?: it.contentOrNull?.toLongOrNull() } ?: 3_600L
        val lifetime = expiresIn.coerceIn(60L, 86_400L) * 1000
        // A short-lived token must still be reused for a while, or every call would fetch a new one.
        return CachedToken(token, clock() + lifetime - minOf(refreshSkewMillis, lifetime / 2))
    }

    companion object {
        /** JWT/opaque token alphabet; anything else (CR/LF in particular) could split a header. */
        private val TOKEN_CHARS = Regex("^[A-Za-z0-9._~+/=-]{16,16384}$")
        private val OAUTH_ERROR = Regex("^[a-z_]{1,64}$")

        /** Hints per AADSTS code; [v] maps a setting suffix to the variable that holds it for this tenant. */
        private fun hint(code: Int, v: (String) -> String): String? = when (code) {
            7000215 -> "the client secret is invalid; check ${v("CLIENT_SECRET")} holds the secret VALUE, not its ID"
            7000222 -> "the client secret has expired; create a new one in the app registration"
            700016 -> "the application was not found in the tenant; check ${v("CLIENT_ID")} and ${v("TENANT_ID")}"
            90002 -> "the tenant was not found; check ${v("TENANT_ID")} and ${v("CLOUD")}"
            900023 -> "the tenant identifier is not valid; check ${v("TENANT_ID")}"
            500011 -> "the resource principal was not found; the Defender API may not be provisioned in this tenant or cloud"
            1003031 -> "access was blocked by a Conditional Access policy for workload identities"
            53003 -> "access was blocked by a Conditional Access policy"
            else -> null
        }

        /**
         * A fixed, fully server-authored explanation of a failed token response. [tenantName] (named
         * tenants only) and [variable] make the message point at the right tenant and its own variables.
         */
        internal fun describeFailure(
            status: Int,
            json: JsonObject?,
            tenantName: String? = null,
            variable: (String) -> String = { "DEFENDER_$it" },
        ): String {
            val error = json?.get("error")?.let { runCatching { it.jsonPrimitive.contentOrNull }.getOrNull() }
                ?.takeIf { OAUTH_ERROR.matches(it) }
            val codes = json?.get("error_codes")?.let { el ->
                runCatching { el.jsonArray.mapNotNull { it.jsonPrimitive.intOrNull } }.getOrNull()
            }.orEmpty().take(5)
            return buildString {
                append("Microsoft Entra ID refused the token request")
                tenantName?.let { append(" for tenant '$it'") }
                append(" (HTTP $status")
                error?.let { append(", $it") }
                codes.forEach { append(", AADSTS$it") }
                append(").")
                val hint = codes.firstNotNullOfOrNull { hint(it, variable) }
                    ?: when (error) {
                        "invalid_client" -> "the client ID or secret is wrong"
                        "unauthorized_client" -> "the application is not allowed to use the client-credentials flow"
                        "invalid_scope" -> "the requested API scope is not valid for this cloud"
                        else -> null
                    }
                hint?.let { append(" Likely cause: $it.") }
            }
        }
    }
}
