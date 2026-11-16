package com.jitunicornfx.defender.mcp.tools

import com.jitunicornfx.defender.mcp.AccessLevel
import com.jitunicornfx.defender.mcp.JsonCodec
import com.jitunicornfx.defender.mcp.OData
import com.jitunicornfx.defender.mcp.ToolCall
import com.jitunicornfx.defender.mcp.ToolSpec
import com.jitunicornfx.defender.mcp.Validators
import com.jitunicornfx.defender.mcp.errorResult
import com.jitunicornfx.defender.mcp.tool
import io.ktor.http.HttpMethod
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import java.net.URI
import java.time.Duration
import java.time.Instant
import java.time.format.DateTimeFormatter

/**
 * Custom indicators (IoCs): tenant-wide allow/block/audit rules for file hashes, certificates, IPs,
 * domains and URLs. (Not to be confused with `defender_indicator_lookup`, which reads alerts for an IP
 * or domain.)
 *
 * Every submit is a tenant-wide (or device-group-wide) policy change, so it is tiered by its effect:
 * Audit and Warn need the write level; Block, BlockAndRemediate and Allowed (which suppresses detections)
 * need the destructive level. An expiration is mandatory and capped, the per-type action rules are
 * enforced before the API sees the request, and because posting an existing value silently overwrites
 * it, the server looks for an existing indicator first and tells the approver "create" or "overwrite".
 */
object CustomIndicatorTools {
    val TYPES = listOf("FileSha1", "FileSha256", "FileMd5", "CertificateThumbprint", "IpAddress", "DomainName", "Url")
    val ACTIONS = listOf("Audit", "Warn", "Block", "BlockAndRemediate", "Allowed")
    val SEVERITIES = listOf("Informational", "Low", "Medium", "High")
    val FILTER_FIELDS = setOf(
        "application", "createdByDisplayName", "expirationTime", "generateAlert", "title", "rbacGroupNames",
        "rbacGroupIds", "indicatorValue", "indicatorType", "creationTimeDateTimeUtc", "createdBy", "action", "severity",
    )

    /** Actions that block, remediate or suppress detection: destructive tier. */
    val DESTRUCTIVE_ACTIONS = setOf("Block", "BlockAndRemediate", "Allowed")

    /** Which actions each indicator type supports (Microsoft's matrix; the retired Alert/AlertAndBlock are not offered). */
    val ACTIONS_BY_TYPE: Map<String, Set<String>> = mapOf(
        "FileSha1" to setOf("Allowed", "Audit", "Warn", "Block", "BlockAndRemediate"),
        "FileSha256" to setOf("Allowed", "Audit", "Warn", "Block", "BlockAndRemediate"),
        "FileMd5" to setOf("Allowed", "Audit", "Warn", "Block", "BlockAndRemediate"),
        "CertificateThumbprint" to setOf("Allowed", "BlockAndRemediate"),
        "IpAddress" to setOf("Allowed", "Audit", "Warn", "Block"),
        "DomainName" to setOf("Allowed", "Audit", "Warn", "Block"),
        "Url" to setOf("Allowed", "Audit", "Warn", "Block"),
    )

    const val MAX_EXPIRATION_DAYS = 365L
    const val MAX_TITLE = 200
    const val MAX_URL = 2_048
    const val MAX_RBAC_GROUPS = 20

    /**
     * Domains whose blocking would take down Windows, Defender itself or Microsoft 365. A DomainName
     * indicator also matches every subdomain, so these are refused outright as Block targets.
     */
    val CRITICAL_DOMAINS = setOf(
        "microsoft.com", "windows.com", "windowsupdate.com", "microsoftonline.com", "office.com", "office365.com",
        "live.com", "azure.com", "azureedge.net", "msftauth.net", "security.microsoft.com", "securitycenter.microsoft.com",
        "windows.net", "digicert.com", "verisign.com", "akamaiedge.net", "akadns.net",
    )

    private val HEX = Regex("^[0-9a-fA-F]+$")
    private val INDICATOR_ID = Regex("^[0-9]{1,20}$")

    /** Validate [raw] as an indicator of [type]; returns the canonical value. */
    internal fun validateValue(type: String, raw: String): String {
        val v = raw.trim()
        fun hex(len: Int, what: String): String {
            require(v.length == len && HEX.matches(v)) { "indicator_value must be a $len-character hexadecimal $what." }
            return v.lowercase()
        }
        return when (type) {
            "FileSha1" -> hex(40, "SHA-1")
            "FileSha256" -> hex(64, "SHA-256")
            "FileMd5" -> hex(32, "MD5")
            "CertificateThumbprint" -> hex(40, "certificate thumbprint (SHA-1)")
            "IpAddress" -> {
                require(!v.contains('/') && !v.contains('-') && !v.contains('*')) { "indicator_value must be a single IP: CIDR, ranges and wildcards are not supported." }
                val ip = Validators.ipAddress(v, "indicator_value")
                // Defender only matches IPv6 written with all eight segments.
                require(!ip.contains(':') || (!ip.contains("::") && ip.count { it == ':' } == 7)) {
                    "indicator_value: IPv6 must be written with all 8 segments (no '::' compression)."
                }
                ip
            }
            "DomainName" -> {
                require(!v.contains('*')) { "indicator_value: wildcards are not supported (a domain already matches its subdomains)." }
                Validators.domain(v, "indicator_value")
            }
            "Url" -> {
                require(v.length <= MAX_URL && v.none { it.isISOControl() || it.isWhitespace() } && !Validators.INVISIBLE.containsMatchIn(v)) {
                    "indicator_value must be a URL of at most $MAX_URL characters, without spaces or control characters."
                }
                val uri = runCatching { URI(v) }.getOrNull()
                require(uri != null && (uri.scheme == "http" || uri.scheme == "https") && uri.host != null && !v.contains('*')) {
                    "indicator_value must be an absolute http(s) URL without wildcards."
                }
                // 'https://microsoft.com@evil.example/' targets evil.example; refuse forms that disguise the host.
                require(uri.rawUserInfo == null && !v.substringAfter("://").substringBefore('/').contains('@')) {
                    "indicator_value must not contain user info (user@host): it hides the real host."
                }
                require(uri.rawFragment == null) { "indicator_value must not contain a fragment (#...)." }
                v
            }
            else -> throw IllegalArgumentException("indicator_type must be one of: ${TYPES.joinToString(", ")}.")
        }
    }

    /**
     * True when blocking [domain] would also block a critical Microsoft/PKI domain: the domain is one, or a
     * parent of one (blocking `com` would block everything). A *subdomain* of a critical domain stays allowed:
     * attackers host payloads on e.g. `evil.blob.core.windows.net`, and blocking that host must remain possible.
     */
    internal fun isCriticalDomain(domain: String): Boolean =
        CRITICAL_DOMAINS.any { domain == it || it.endsWith(".$domain") }

    private fun JsonObject.text(key: String): String? = (this[key] as? JsonPrimitive)?.contentOrNull?.takeIf { it.isNotBlank() }

    /** Existing indicators for [value] (any type), or null when the lookup failed. */
    private suspend fun ToolCall.existingFor(value: String): List<JsonObject>? {
        val response = client.get("/api/indicators", listOf("\$filter" to "indicatorValue eq ${OData.quote(value)}", "\$top" to EXISTING_PAGE.toString()))
        if (!response.ok) return null
        val json = runCatching { JsonCodec.compact.parseToJsonElement(response.text) as? JsonObject }.getOrNull() ?: return null
        // A 200 without a 'value' array has not answered the question: treat it as a failed lookup, never as "none".
        val values = (json["value"] as? JsonArray)?.mapNotNull { it as? JsonObject } ?: return null
        // The answer must be complete: if the API ignored the filter (or there are more pages), an existing indicator
        // could be missed and silently overwritten, so an incomplete answer is a failed lookup.
        if (json.containsKey("@odata.nextLink") || values.size >= EXISTING_PAGE) return null
        // Never trust the server-side filter alone: keep only exact matches (hashes compare case-insensitively).
        return values.filter { it.text("indicatorValue")?.trim().equals(value, ignoreCase = true) }
    }

    /** Page size for the existing-indicator check; a value has at most a handful (one per type and scope). */
    const val EXISTING_PAGE = 100

    val listIndicators: ToolSpec = tool(
        name = "defender_list_indicators",
        description = "List active custom indicators (IoCs: allow/block/audit rules for file hashes, certificates, IPs, " +
            "domains and URLs). Not the same as defender_indicator_lookup, which reads alerts for an IP or domain.",
        params = {
            string("indicator_value", "Only the indicator with exactly this value.", maxLength = MAX_URL)
            string("indicator_type", "Only indicators of this type.", enum = TYPES)
            string("action", "Only indicators with this action.", enum = ACTIONS)
            paging(FILTER_FIELDS)
        },
    ) {
        val structured = OData.and(
            args.optString("indicator_value")?.let { "indicatorValue eq ${OData.quote(it.trim())}" },
            args.optEnum("indicator_type", TYPES)?.let { "indicatorType eq ${OData.quote(it)}" },
            args.optEnum("action", ACTIONS)?.let { "action eq ${OData.quote(it)}" },
        )
        val (query, _) = listQuery(structured, FILTER_FIELDS)
        pagedList("/api/indicators", query)
    }

    val submitIndicator: ToolSpec = tool(
        name = "defender_submit_indicator",
        description = "Create (or overwrite) a custom indicator: a tenant-wide rule for a file hash, certificate, IP, domain or URL. " +
            "Audit/Warn need the write access level; Block, BlockAndRemediate and Allowed (which SUPPRESSES detections) need the " +
            "destructive level. An expiration is required. A domain also matches all its subdomains. Requires human approval; " +
            "the prompt says whether an existing indicator would be overwritten.",
        access = AccessLevel.WRITE,
        destructive = true,
        idempotent = true,
        params = {
            string("indicator_value", "The hash, thumbprint, IP, domain or URL.", required = true, maxLength = MAX_URL)
            string("indicator_type", "Indicator type.", required = true, enum = TYPES)
            string("action", "What Defender does on a match.", required = true, enum = ACTIONS)
            string("title", "Short title (shown in alerts).", required = true, maxLength = MAX_TITLE)
            string("description", "Why this indicator exists (reference the alert or ticket).", required = true, maxLength = Validators.MAX_COMMENT_LENGTH)
            string("expiration_time", "When the indicator expires (ISO-8601, in the future, at most $MAX_EXPIRATION_DAYS days ahead).", required = true, format = "date-time")
            string("severity", "Severity of resulting alerts.", enum = SEVERITIES)
            stringArray("rbac_group_names", "Device groups to scope it to. Omit to apply to ALL devices.", MAX_RBAC_GROUPS)
            boolean("generate_alert", "Raise an alert on a match (always true for Audit).", default = false)
            string("recommended_actions", "Recommended actions shown with alerts.", maxLength = Validators.MAX_COMMENT_LENGTH)
        },
    ) {
        val type = args.enum("indicator_type", TYPES)
        val action = args.enum("action", ACTIONS)
        require(action in ACTIONS_BY_TYPE.getValue(type)) {
            "action $action is not supported for $type indicators; supported: ${ACTIONS_BY_TYPE.getValue(type).sorted().joinToString(", ")}."
        }
        val value = validateValue(type, args.string("indicator_value"))
        val title = Validators.comment(args.string("title"), "title").also { require(it.length <= MAX_TITLE) { "title must be at most $MAX_TITLE characters." } }
        val description = Validators.comment(args.string("description"), "description")
        val expiration = Validators.timestamp(args.string("expiration_time"), "expiration_time")
        val now = Instant.now()
        require(expiration.isAfter(now)) { "expiration_time must be in the future." }
        require(!expiration.isAfter(now.plus(Duration.ofDays(MAX_EXPIRATION_DAYS)))) { "expiration_time must be at most $MAX_EXPIRATION_DAYS days ahead." }
        val severity = args.optEnum("severity", SEVERITIES)
        val groups = args.optStringList("rbac_group_names", MAX_RBAC_GROUPS)?.map { Validators.tag(it, "rbac_group_names") }?.distinct()
        val recommended = args.optString("recommended_actions")?.let { Validators.comment(it, "recommended_actions") }
        val generateAlert = action == "Audit" || args.boolean("generate_alert", false)

        if (action in DESTRUCTIVE_ACTIONS && !tenant.accessLevel.permits(AccessLevel.DESTRUCTIVE)) {
            return@tool errorResult(
                "Refused: a $action indicator blocks, remediates or suppresses detections across the tenant, so it needs the destructive " +
                    "access level (this server/tenant has ${tenant.accessLevel.name.lowercase().replace('_', '-')}). Audit or Warn " +
                    "indicators are allowed at the write level. Nothing was changed.",
            )
        }
        if (type == "DomainName" && action != "Allowed" && isCriticalDomain(value)) {
            return@tool errorResult(
                "Refused: blocking or flagging this domain (and all its subdomains) would affect a domain Windows, Defender or " +
                    "Microsoft 365 depend on. Narrow it to a specific URL, or have an administrator do it in the portal. Nothing was changed.",
            )
        }

        val existing = existingFor(value) ?: return@tool errorResult(
            "Refused: existing indicators could not be checked, and submitting may silently overwrite one. Nothing was changed.",
        )
        fun describe(e: JsonObject) =
            listOfNotNull(e.text("indicatorType"), e.text("action"), e.text("title"), e.text("expirationTime")?.let { "expires $it" })
                .joinToString(" | ")
        // Posting a value that already exists (same type) overwrites that indicator.
        val overwritten = existing.filter { it.text("indicatorType").equals(type, ignoreCase = true) }
        val replacedEnforcement = overwritten.mapNotNull { it.text("action") }.firstOrNull { a -> DESTRUCTIVE_ACTIONS.any { it.equals(a, ignoreCase = true) } }
        if (replacedEnforcement != null && !tenant.accessLevel.permits(AccessLevel.DESTRUCTIVE)) {
            // Replacing a Block/Allowed rule (e.g. with a short-lived Audit) lifts it: that is a delete, which is destructive.
            return@tool errorResult(
                "Refused: an existing $replacedEnforcement indicator for this value would be overwritten, which lifts or changes its " +
                    "enforcement. That needs the destructive access level. Nothing was changed.",
            )
        }
        val facts = buildList {
            if (overwritten.isEmpty()) add("Existing $type indicator" to "none: this creates a new indicator")
            overwritten.take(3).forEach { add("Existing indicator that will be OVERWRITTEN" to describe(it)) }
            existing.filter { it !in overwritten }.take(3).forEach { add("Other indicator for this value (unchanged)" to describe(it)) }
            if (type == "Url") runCatching { URI(value).host }.getOrNull()?.let { add("URL host" to it) }
        }
        val scope = groups?.takeIf { it.isNotEmpty() }?.joinToString(", ") ?: "ALL devices in the tenant"
        authorize(
            (if (overwritten.isNotEmpty()) "OVERWRITE the existing ${overwritten.first().text("action") ?: ""} indicator with: " else "") +
                "${action.uppercase()} $type indicator for '$value' (scope: $scope; expires ${DateTimeFormatter.ISO_INSTANT.format(expiration)})" +
                if (type == "DomainName") " — also matches every subdomain" else "",
            buildList {
                add("Value" to value)
                add("Type" to type)
                add("Action" to action)
                add("Scope" to scope)
                add("Title" to title)
                add("Description" to description)
            },
            facts = facts,
        )?.let { return@tool it }

        render(
            client.request(
                HttpMethod.Post,
                "/api/indicators",
                body = jsonOf(
                    "indicatorValue" to value,
                    "indicatorType" to type,
                    "action" to action,
                    "title" to title,
                    "description" to description,
                    "expirationTime" to DateTimeFormatter.ISO_INSTANT.format(expiration),
                    "severity" to severity,
                    "recommendedActions" to recommended,
                    "rbacGroupNames" to groups?.let { g -> JsonArray(g.map { JsonPrimitive(it) }) },
                    "generateAlert" to generateAlert,
                ),
            ),
        )
    }

    val deleteIndicator: ToolSpec = tool(
        name = "defender_delete_indicator",
        description = "Delete a custom indicator by ID. This lifts its rule tenant-wide (a blocked file or URL becomes usable again; " +
            "an allowed file is scanned again) and cannot be undone except by re-creating it. Requires the destructive access " +
            "level and human approval.",
        access = AccessLevel.DESTRUCTIVE,
        destructive = true,
        params = {
            string("indicator_id", "Indicator ID (from defender_list_indicators).", required = true, pattern = "^[0-9]{1,20}$")
            string("comment", "Why it is being deleted (recorded in the audit log).", required = true, maxLength = Validators.MAX_COMMENT_LENGTH)
        },
    ) {
        val id = args.string("indicator_id").trim()
        require(INDICATOR_ID.matches(id)) { "indicator_id must be the numeric indicator ID." }
        val comment = Validators.comment(args.string("comment"))
        val found = findIndicator(id) ?: return@tool errorResult(
            "Refused: indicator $id could not be found (or looked up), so it cannot be shown to the approver. Nothing was changed.",
        )
        authorize(
            "DELETE indicator $id, lifting its rule tenant-wide",
            listOf("Indicator ID" to id, "Comment" to comment),
            facts = listOfNotNull(
                found.text("indicatorValue")?.let { "Value" to it },
                found.text("indicatorType")?.let { "Type" to it },
                found.text("action")?.let { "Action" to it },
                found.text("title")?.let { "Title" to it },
                found.text("createdBy")?.let { "Created by" to it },
            ),
        )?.let { return@tool it }
        render(client.request(HttpMethod.Delete, "/api/indicators/${seg(id)}"))
    }

    /** Largest page Defender returns for /api/indicators; with the 15,000-indicator tenant cap, two pages see them all. */
    const val SCAN_PAGE = 10_000
    const val SCAN_PAGES = 2

    /**
     * The indicator whose `id` is exactly [id], found by reading the list (`id` is not a documented `$filter`
     * field, and a filter the API ignored would return some other indicator). Null when it is not there or the
     * list cannot be read.
     */
    private suspend fun ToolCall.findIndicator(id: String): JsonObject? {
        for (page in 0 until SCAN_PAGES) {
            val response = client.get("/api/indicators", listOf("\$top" to SCAN_PAGE.toString(), "\$skip" to (page * SCAN_PAGE).toString()))
            if (!response.ok) return null
            val values = runCatching {
                ((JsonCodec.compact.parseToJsonElement(response.text) as? JsonObject)?.get("value") as? JsonArray)?.mapNotNull { it as? JsonObject }
            }.getOrNull() ?: return null
            values.firstOrNull { it.text("id") == id }?.let { return it }
            if (values.size < SCAN_PAGE) return null
        }
        return null
    }

    val all: List<ToolSpec> = listOf(listIndicators, submitIndicator, deleteIndicator)
}
