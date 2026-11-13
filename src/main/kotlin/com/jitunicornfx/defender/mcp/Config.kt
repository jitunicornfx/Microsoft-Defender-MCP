package com.jitunicornfx.defender.mcp

/**
 * Microsoft cloud the tenant lives in. Each pins the Entra ID authority, the Defender API host and
 * the OAuth scope together, so a misconfiguration can never send a commercial token to a government
 * host or the reverse.
 */
enum class CloudEnvironment(
    val code: String,
    val loginBaseUrl: String,
    val apiBaseUrl: String,
    val scope: String,
    /** Microsoft Graph host; advanced hunting runs on Graph (`/v1.0/security/runHuntingQuery`). */
    val graphBaseUrl: String,
) {
    COMMERCIAL(
        code = "commercial",
        loginBaseUrl = "https://login.microsoftonline.com",
        apiBaseUrl = "https://api.security.microsoft.com",
        scope = "https://api.securitycenter.microsoft.com/.default",
        graphBaseUrl = "https://graph.microsoft.com",
    ),
    GCC(
        code = "gcc",
        loginBaseUrl = "https://login.microsoftonline.com",
        apiBaseUrl = "https://api-gcc.securitycenter.microsoft.us",
        scope = "https://api-gcc.securitycenter.microsoft.us/.default",
        graphBaseUrl = "https://graph.microsoft.com",
    ),
    GCC_HIGH(
        code = "gcc-high",
        loginBaseUrl = "https://login.microsoftonline.us",
        apiBaseUrl = "https://api-gov.securitycenter.microsoft.us",
        scope = "https://api-gov.securitycenter.microsoft.us/.default",
        graphBaseUrl = "https://graph.microsoft.us",
    ),
    DOD(
        code = "dod",
        loginBaseUrl = "https://login.microsoftonline.us",
        apiBaseUrl = "https://api-gov.securitycenter.microsoft.us",
        scope = "https://api-gov.securitycenter.microsoft.us/.default",
        graphBaseUrl = "https://dod-graph.microsoft.us",
    ),
    ;

    val graphScope: String get() = "$graphBaseUrl/.default"

    companion object {
        fun fromCode(code: String): CloudEnvironment =
            entries.firstOrNull { it.code.equals(code.trim(), ignoreCase = true) }
                ?: throw IllegalArgumentException(
                    "Unknown cloud '$code'. Valid values: ${entries.joinToString(", ") { it.code }}.",
                )
    }
}

/**
 * Regional Defender API endpoints (commercial cloud only). Without a region the global
 * `https://api.security.microsoft.com` is used, which routes to the tenant's own geography.
 * The hosts are fixed here, so no configuration can point the bearer token at another host.
 */
enum class DefenderRegion(val code: String, val host: String) {
    US("us", "us.api.security.microsoft.com"),
    EU("eu", "eu.api.security.microsoft.com"),
    UK("uk", "uk.api.security.microsoft.com"),
    AU("au", "au.api.security.microsoft.com"),
    SWA("swa", "swa.api.security.microsoft.com"),
    INA("ina", "ina.api.security.microsoft.com"),
    AEA("aea", "aea.api.security.microsoft.com"),
    ;

    val baseUrl: String get() = "https://$host"

    companion object {
        fun fromCode(code: String): DefenderRegion =
            entries.firstOrNull { it.code.equals(code.trim(), ignoreCase = true) }
                ?: throw IllegalArgumentException(
                    "Unknown region '$code'. Valid values: ${entries.joinToString(", ") { it.code }}.",
                )
    }
}

/** How much of the API the server may touch. Each level includes the ones before it. */
enum class AccessLevel {
    /** Queries only: nothing in the tenant changes. The default. */
    READ_ONLY,

    /** Adds reversible, low-impact changes: tags, device value, starting investigations, AV scans. */
    WRITE,

    /** Adds actions that disrupt a machine or its user: isolation, app restriction, offboarding, quarantine. */
    DESTRUCTIVE,
    ;

    fun permits(required: AccessLevel): Boolean = ordinal >= required.ordinal

    /** The spelling used in configuration: read-only, write, destructive. */
    val label: String get() = name.lowercase().replace('_', '-')
}

/** Whether a human must approve each state-changing tool call. */
enum class ConfirmationMode {
    /**
     * Ask the human through MCP elicitation before every state-changing call. A client without
     * elicitation support gets a refusal: the server fails closed rather than trusting the model.
     */
    ELICIT,

    /** No human approval (unattended automation). Logged loudly at startup. */
    NONE,
}

/** OAuth client-credentials settings for Microsoft Entra ID. The secret is never printed. */
data class EntraCredentials(
    val tenantId: String,
    val clientId: String,
    val clientSecret: String,
) {
    override fun toString(): String = "EntraCredentials(tenantId=$tenantId, clientId=$clientId, clientSecret=***)"
}

/**
 * One named Defender tenant: the app registration that reaches it and where its API lives. The
 * [name] is chosen by the operator and is what tools take as their `tenant` argument.
 */
data class TenantProfile(
    val name: String,
    val credentials: EntraCredentials,
    val cloud: CloudEnvironment = CloudEnvironment.COMMERCIAL,
    val region: DefenderRegion? = null,
    /** Narrows the server-wide access level for this tenant; null inherits it. Can never widen it. */
    val accessLevel: AccessLevel? = null,
) {
    init {
        Config.validateTenantName(name)
        require(region == null || cloud == CloudEnvironment.COMMERCIAL) {
            "Tenant '$name': a region applies only to the commercial cloud; ${cloud.code} has its own fixed API host."
        }
    }

    val apiBaseUrl: String get() = region?.baseUrl ?: cloud.apiBaseUrl
}

/**
 * Complete server configuration.
 *
 * [credentials], [cloud], [region] describe the first (primary) tenant, named [tenantName]; any
 * further named tenants are in [additionalTenants]. [forTenant] gives the single-tenant view each
 * tenant's API client is built from, so everything below the tenant registry stays single-tenant.
 */
data class Config(
    val credentials: EntraCredentials,
    val cloud: CloudEnvironment = CloudEnvironment.COMMERCIAL,
    /** Regional Defender endpoint (commercial cloud only); null uses https://api.security.microsoft.com. */
    val region: DefenderRegion? = null,
    val accessLevel: AccessLevel = AccessLevel.READ_ONLY,
    val confirmation: ConfirmationMode = ConfirmationMode.ELICIT,
    val requestTimeoutMillis: Long = DEFAULT_TIMEOUT_MS,
    /** Hard cap on bytes read from one HTTP response; a memory guard. */
    val maxResponseBytes: Long = DEFAULT_MAX_RESPONSE_BYTES,
    /** Characters of API data one tool result may carry; the model-context budget. */
    val maxResultChars: Int = DEFAULT_MAX_RESULT_CHARS,
    /** State-changing calls permitted per rolling hour, a brake on a hijacked agent looping. */
    val maxActionsPerHour: Int = DEFAULT_MAX_ACTIONS_PER_HOUR,
    /** Maximum concurrent outbound Defender API requests. */
    val maxConcurrentRequests: Int = DEFAULT_MAX_CONCURRENT_REQUESTS,
    val httpAuthToken: String? = null,
    val httpAllowedOrigins: List<String> = emptyList(),
    /** Glob patterns of tool names to expose; empty exposes every tool the access level permits. */
    val toolGlobs: List<String> = emptyList(),
    /** Name of the primary tenant ([credentials]); `default` for the classic single-tenant variables. */
    val tenantName: String = DEFAULT_TENANT_NAME,
    /** Access-level narrowing for the primary tenant. */
    val tenantAccessLevel: AccessLevel? = null,
    /** Tenants beyond the primary one. */
    val additionalTenants: List<TenantProfile> = emptyList(),
    /** Tenant used when a call names none; null makes the `tenant` argument mandatory with several tenants. */
    val defaultTenant: String? = null,
    /** True when tenants came from [ENV_TENANTS], so their settings live in `DEFENDER_<NAME>_*` variables. */
    val namedTenants: Boolean = false,
    /** Skip the startup check for a newer GitHub release (implies [autoUpdateDisabled]). */
    val updateCheckDisabled: Boolean = false,
    /** Report a newer release but never download or install it. */
    val autoUpdateDisabled: Boolean = false,
) {
    init {
        require(maxResultChars >= MIN_RESULT_CHARS) { "max result chars must be at least $MIN_RESULT_CHARS" }
        require(maxResponseBytes >= 1024) { "max response bytes must be at least 1024" }
        require(requestTimeoutMillis in 1_000..600_000) { "timeout must be between 1000 and 600000 ms" }
        require(maxActionsPerHour in 0..10_000) { "max actions per hour must be between 0 and 10000" }
        require(maxConcurrentRequests in 1..64) { "max concurrent requests must be between 1 and 64" }
        require(region == null || cloud == CloudEnvironment.COMMERCIAL) {
            "$ENV_REGION applies only to the commercial cloud; ${cloud.code} has its own fixed API host."
        }
        validateTenantName(tenantName)
        val names = listOf(tenantName) + additionalTenants.map { it.name }
        require(names.size == names.toSet().size) {
            "Tenant names must be unique; repeated: ${names.groupBy { it }.filterValues { it.size > 1 }.keys.joinToString(", ")}."
        }
        require(defaultTenant == null || defaultTenant in names) {
            "$ENV_DEFAULT_TENANT names '$defaultTenant', which is not a configured tenant (${names.joinToString(", ")})."
        }
    }

    /** The primary tenant as a profile. */
    val primaryTenant: TenantProfile get() = TenantProfile(tenantName, credentials, cloud, region, tenantAccessLevel)

    /** Every configured tenant, primary first. */
    val tenants: List<TenantProfile> get() = listOf(primaryTenant) + additionalTenants

    val isMultiTenant: Boolean get() = additionalTenants.isNotEmpty()

    /** The single-tenant view of this configuration for [tenant]: same server-wide settings, its own credentials and host. */
    fun forTenant(tenant: TenantProfile): Config = copy(
        credentials = tenant.credentials,
        cloud = tenant.cloud,
        region = tenant.region,
        tenantName = tenant.name,
        tenantAccessLevel = tenant.accessLevel,
        additionalTenants = emptyList(),
        defaultTenant = null,
    )

    /** The widest access level any tenant actually has: what the server can really do. */
    val effectiveAccessLevel: AccessLevel get() = tenants.maxOf { accessFor(it) }

    /**
     * The environment variable holding setting [suffix] (`TENANT_ID`, `CLIENT_ID`, `CLIENT_SECRET`, `CLOUD`)
     * for this view's tenant: `DEFENDER_FABRIKAM_CLIENT_SECRET` for named tenants, `DEFENDER_CLIENT_SECRET` otherwise.
     */
    fun variableFor(suffix: String): String = if (namedTenants) tenantPrefix(tenantName) + suffix else "DEFENDER_$suffix"

    /**
     * One notice per tenant whose own access level asks for MORE than the server-wide level allows.
     * Such a setting is capped, by design: a per-tenant variable may narrow access but never widen it.
     * Saying so out loud matters, because otherwise the request is silently ignored.
     */
    fun accessCapNotices(): List<String> = tenants.mapNotNull { t ->
        val wanted = t.accessLevel ?: return@mapNotNull null
        if (wanted.ordinal <= accessLevel.ordinal) return@mapNotNull null
        val variable = if (namedTenants) tenantPrefix(t.name) + "ACCESS_LEVEL" else "the tenant's access level"
        "Tenant '${t.name}' asks for '${wanted.label}' access ($variable), but the server-wide $ENV_ACCESS_LEVEL is " +
            "'${accessLevel.label}', so the tenant is capped at '${accessLevel.label}'. A tenant can narrow the server-wide level " +
            "but never raise it: set $ENV_ACCESS_LEVEL (or --access) to '${wanted.label}' to allow it."
    }

    /** The access level in force for [tenant]: the server-wide level, narrowed by the tenant's own. */
    fun accessFor(tenant: TenantProfile): AccessLevel =
        tenant.accessLevel?.takeIf { it.ordinal < accessLevel.ordinal } ?: accessLevel

    /** The Defender API base URL: the region's host, else the cloud's (https://api.security.microsoft.com for commercial). */
    val apiBaseUrl: String get() = region?.baseUrl ?: cloud.apiBaseUrl

    /** Written by hand so the bearer token never reaches a log. */
    override fun toString(): String =
        "Config(credentials=$credentials, cloud=${cloud.code}, region=${region?.code ?: "global"}, apiBaseUrl=$apiBaseUrl, accessLevel=$accessLevel, " +
            "confirmation=$confirmation, requestTimeoutMillis=$requestTimeoutMillis, maxResponseBytes=$maxResponseBytes, " +
            "maxResultChars=$maxResultChars, maxActionsPerHour=$maxActionsPerHour, " +
            "maxConcurrentRequests=$maxConcurrentRequests, httpAuthToken=${if (httpAuthToken == null) "unset" else "***"}, " +
            "httpAllowedOrigins=$httpAllowedOrigins, toolGlobs=$toolGlobs, tenants=${tenants.map { it.name }}, " +
            "defaultTenant=${defaultTenant ?: "none"}, updateCheckDisabled=$updateCheckDisabled, autoUpdateDisabled=$autoUpdateDisabled)"

    val tokenUrl: String get() = "${cloud.loginBaseUrl}/${credentials.tenantId}/oauth2/v2.0/token"

    companion object {
        const val ENV_DISABLE_UPDATE_CHECK = "DEFENDER_DISABLE_UPDATE_CHECK"
        const val ENV_DISABLE_AUTO_UPDATE = "DEFENDER_DISABLE_AUTO_UPDATE"
        const val ENV_TENANTS = "DEFENDER_TENANTS"
        const val ENV_DEFAULT_TENANT = "DEFENDER_DEFAULT_TENANT"
        const val DEFAULT_TENANT_NAME = "default"
        const val TENANT_NAME_PATTERN = "^[a-z][a-z0-9-]{0,31}$"
        private val TENANT_NAME = Regex(TENANT_NAME_PATTERN)
        const val ENV_TENANT_ID = "DEFENDER_TENANT_ID"
        const val ENV_CLIENT_ID = "DEFENDER_CLIENT_ID"
        const val ENV_CLIENT_SECRET = "DEFENDER_CLIENT_SECRET"
        const val ENV_CLOUD = "DEFENDER_CLOUD"
        const val ENV_REGION = "DEFENDER_REGION"
        const val ENV_ACCESS_LEVEL = "DEFENDER_ACCESS_LEVEL"
        const val ENV_CONFIRMATION = "DEFENDER_CONFIRMATION"
        const val ENV_TIMEOUT_MS = "DEFENDER_TIMEOUT_MS"
        const val ENV_MAX_RESPONSE_BYTES = "DEFENDER_MAX_RESPONSE_BYTES"
        const val ENV_MAX_RESULT_CHARS = "DEFENDER_MAX_RESULT_CHARS"
        const val ENV_MAX_ACTIONS_PER_HOUR = "DEFENDER_MAX_ACTIONS_PER_HOUR"
        const val ENV_MAX_CONCURRENT_REQUESTS = "DEFENDER_MAX_CONCURRENT_REQUESTS"
        const val ENV_MCP_AUTH_TOKEN = "DEFENDER_MCP_AUTH_TOKEN"
        const val ENV_HTTP_ALLOWED_ORIGINS = "DEFENDER_HTTP_ALLOWED_ORIGINS"
        const val ENV_TOOLS = "DEFENDER_TOOLS"

        const val DEFAULT_TIMEOUT_MS = 60_000L
        const val DEFAULT_MAX_RESPONSE_BYTES = 16L * 1024 * 1024
        const val DEFAULT_MAX_RESULT_CHARS = 200_000
        const val MIN_RESULT_CHARS = 2_000
        const val DEFAULT_MAX_ACTIONS_PER_HOUR = 20
        const val DEFAULT_MAX_CONCURRENT_REQUESTS = 4

        /** Entra ID tenant: a GUID or a verified domain name. Anything else could rewrite the token URL path. */
        private val TENANT = Regex("^(?:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?(?:\\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?)+)$")
        private val GUID = Regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


        /** A tenant's name: lowercase letters, digits and '-', starting with a letter, at most 32 characters. */
        fun validateTenantName(value: String): String {
            require(TENANT_NAME.matches(value)) {
                "Tenant name '${value.take(40)}' is invalid: use 1-32 lowercase letters, digits or '-', starting with a letter."
            }
            return value
        }

        /** Environment-variable prefix of a named tenant: `fabrikam-lab` -> `DEFENDER_FABRIKAM_LAB_`. */
        fun tenantPrefix(name: String): String = "DEFENDER_" + name.uppercase().replace('-', '_') + "_"

        fun validateTenantId(value: String, variable: String = ENV_TENANT_ID): String {
            require(TENANT.matches(value)) { "$variable must be a tenant GUID or verified domain name." }
            return value
        }

        fun validateClientId(value: String, variable: String = ENV_CLIENT_ID): String {
            require(GUID.matches(value)) { "$variable must be the application (client) GUID." }
            return value
        }

        fun validateSecret(value: String, variable: String = ENV_CLIENT_SECRET): String {
            require(value.isNotBlank()) { "$variable must not be blank." }
            require(value.none { it.isISOControl() }) { "$variable contains control characters." }
            return value
        }

        fun csv(value: String?): List<String> =
            value?.split(',')?.map { it.trim() }?.filter { it.isNotEmpty() } ?: emptyList()

        fun parseAccessLevel(value: String): AccessLevel = when (value.trim().lowercase()) {
            "read", "read-only", "readonly", "read_only" -> AccessLevel.READ_ONLY
            "write" -> AccessLevel.WRITE
            "destructive", "full" -> AccessLevel.DESTRUCTIVE
            else -> throw IllegalArgumentException("Unknown access level '$value'. Valid values: read-only, write, destructive.")
        }

        fun parseConfirmation(value: String): ConfirmationMode = when (value.trim().lowercase()) {
            "elicit", "human", "on" -> ConfirmationMode.ELICIT
            "none", "off" -> ConfirmationMode.NONE
            else -> throw IllegalArgumentException("Unknown confirmation mode '$value'. Valid values: elicit, none.")
        }

        /**
         * A boolean switch: 1/true/yes/on or 0/false/no/off (any case), unset or blank meaning false.
         * Anything else fails startup, so a typo never silently leaves a safety switch off.
         */
        internal fun parseFlag(name: String, value: String?): Boolean = when (value?.trim()?.lowercase()) {
            null, "" -> false
            "1", "true", "yes", "on" -> true
            "0", "false", "no", "off" -> false
            else -> throw IllegalArgumentException("$name must be 1/true/yes/on or 0/false/no/off.")
        }

        private fun Map<String, String>.trimmed(key: String): String? = this[key]?.trim()?.takeIf { it.isNotEmpty() }

        private fun Map<String, String>.long(key: String, default: Long): Long =
            trimmed(key)?.let { it.toLongOrNull() ?: throw IllegalArgumentException("$key must be a whole number.") } ?: default

        private fun Map<String, String>.int(key: String, default: Int): Int =
            trimmed(key)?.let { it.toIntOrNull() ?: throw IllegalArgumentException("$key must be a whole number.") } ?: default

        /** Build a [Config] from environment variables; throws [IllegalArgumentException] with a fix-it message. */
        fun fromEnv(env: Map<String, String> = System.getenv()): Config {
            val globalCloud = env.trimmed(ENV_CLOUD)?.let(CloudEnvironment::fromCode) ?: CloudEnvironment.COMMERCIAL
            val globalRegion = env.trimmed(ENV_REGION)?.let(DefenderRegion::fromCode)
            val tenants = parseTenants(env, globalCloud, globalRegion)
            val primary = tenants.first()
            val token = env[ENV_MCP_AUTH_TOKEN]?.takeIf { it.isNotEmpty() }?.also {
                require(it.none { c -> c.isISOControl() || c.isWhitespace() }) {
                    "$ENV_MCP_AUTH_TOKEN must not contain whitespace or control characters."
                }
            }
            return Config(
                credentials = primary.credentials,
                cloud = primary.cloud,
                region = primary.region,
                accessLevel = env.trimmed(ENV_ACCESS_LEVEL)?.let(::parseAccessLevel) ?: AccessLevel.READ_ONLY,
                confirmation = env.trimmed(ENV_CONFIRMATION)?.let(::parseConfirmation) ?: ConfirmationMode.ELICIT,
                requestTimeoutMillis = env.long(ENV_TIMEOUT_MS, DEFAULT_TIMEOUT_MS),
                maxResponseBytes = env.long(ENV_MAX_RESPONSE_BYTES, DEFAULT_MAX_RESPONSE_BYTES),
                maxResultChars = env.int(ENV_MAX_RESULT_CHARS, DEFAULT_MAX_RESULT_CHARS),
                maxActionsPerHour = env.int(ENV_MAX_ACTIONS_PER_HOUR, DEFAULT_MAX_ACTIONS_PER_HOUR),
                maxConcurrentRequests = env.int(ENV_MAX_CONCURRENT_REQUESTS, DEFAULT_MAX_CONCURRENT_REQUESTS),
                httpAuthToken = token,
                httpAllowedOrigins = csv(env[ENV_HTTP_ALLOWED_ORIGINS]),
                toolGlobs = csv(env[ENV_TOOLS]),
                tenantName = primary.name,
                tenantAccessLevel = primary.accessLevel,
                additionalTenants = tenants.drop(1),
                defaultTenant = env.trimmed(ENV_DEFAULT_TENANT)?.lowercase(),
                namedTenants = env.trimmed(ENV_TENANTS) != null,
                updateCheckDisabled = parseFlag(ENV_DISABLE_UPDATE_CHECK, env[ENV_DISABLE_UPDATE_CHECK]),
                autoUpdateDisabled = parseFlag(ENV_DISABLE_AUTO_UPDATE, env[ENV_DISABLE_AUTO_UPDATE]),
            )
        }

        /**
         * The configured tenants. With [ENV_TENANTS] (`contoso,fabrikam`), each named tenant reads
         * `DEFENDER_<NAME>_TENANT_ID`, `_CLIENT_ID`, `_CLIENT_SECRET` and optionally `_CLOUD`, `_REGION`,
         * `_ACCESS_LEVEL`. [ENV_CLOUD]/[ENV_REGION] are defaults for tenants that set none (the region only
         * for commercial tenants). Without [ENV_TENANTS], the classic variables define one tenant named
         * `default`. Mixing the two is refused, so it is never ambiguous which secret a tenant uses.
         */
        private fun parseTenants(env: Map<String, String>, globalCloud: CloudEnvironment, globalRegion: DefenderRegion?): List<TenantProfile> {
            val named = env.trimmed(ENV_TENANTS) ?: return listOf(
                TenantProfile(
                    name = DEFAULT_TENANT_NAME,
                    credentials = credentialsFrom(env, ENV_TENANT_ID, ENV_CLIENT_ID, ENV_CLIENT_SECRET),
                    cloud = globalCloud,
                    region = globalRegion,
                ),
            )
            val legacy = listOf(ENV_TENANT_ID, ENV_CLIENT_ID, ENV_CLIENT_SECRET).filter { !env[it].isNullOrEmpty() }
            require(legacy.isEmpty()) {
                "$ENV_TENANTS is set, so ${legacy.joinToString(", ")} must not be: give each named tenant its own " +
                    "DEFENDER_<NAME>_TENANT_ID, _CLIENT_ID and _CLIENT_SECRET."
            }
            val names = csv(named).map { validateTenantName(it.lowercase()) }
            require(names.isNotEmpty()) { "$ENV_TENANTS must list at least one tenant name." }
            require(names.size == names.toSet().size) { "$ENV_TENANTS lists a tenant name more than once." }
            return names.map { name ->
                val p = tenantPrefix(name)
                val cloud = env.trimmed(p + "CLOUD")?.let(CloudEnvironment::fromCode) ?: globalCloud
                TenantProfile(
                    name = name,
                    credentials = credentialsFrom(env, p + "TENANT_ID", p + "CLIENT_ID", p + "CLIENT_SECRET"),
                    cloud = cloud,
                    region = env.trimmed(p + "REGION")?.let(DefenderRegion::fromCode)
                        ?: globalRegion.takeIf { cloud == CloudEnvironment.COMMERCIAL },
                    accessLevel = env.trimmed(p + "ACCESS_LEVEL")?.let(::parseAccessLevel),
                )
            }
        }

        private fun credentialsFrom(env: Map<String, String>, tenantVar: String, clientVar: String, secretVar: String): EntraCredentials {
            val tenant = env.trimmed(tenantVar) ?: throw IllegalArgumentException("$tenantVar is required.")
            val clientId = env.trimmed(clientVar) ?: throw IllegalArgumentException("$clientVar is required.")
            // The secret is taken verbatim (not trimmed): a trailing space may be part of it.
            val secret = env[secretVar]?.takeIf { it.isNotEmpty() } ?: throw IllegalArgumentException("$secretVar is required.")
            return EntraCredentials(
                tenantId = validateTenantId(tenant, tenantVar),
                clientId = validateClientId(clientId, clientVar),
                clientSecret = validateSecret(secret, secretVar),
            )
        }
    }
}
