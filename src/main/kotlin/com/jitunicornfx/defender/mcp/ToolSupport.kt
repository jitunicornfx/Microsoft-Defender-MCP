package com.jitunicornfx.defender.mcp

import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import io.modelcontextprotocol.kotlin.sdk.types.Tool
import io.modelcontextprotocol.kotlin.sdk.types.ToolAnnotations
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonObjectBuilder
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.add
import kotlinx.serialization.json.put

/** Shared JSON encoders. */
object JsonCodec {
    val pretty: Json = Json {
        prettyPrint = true
        prettyPrintIndent = "  "
    }
    val compact: Json = Json
}

fun textResult(message: String): CallToolResult = CallToolResult(content = listOf(TextContent(message)))

fun errorResult(message: String): CallToolResult = CallToolResult(content = listOf(TextContent(message)), isError = true)

/**
 * Small DSL for tool input schemas. Every property gets a description (models rely on them) and,
 * where the API constrains a value, the matching JSON-Schema keywords so well-behaved clients
 * validate before calling. The server re-validates everything regardless.
 */
class SchemaBuilder {
    private val props = mutableMapOf<String, JsonObject>()
    private val required = mutableListOf<String>()

    val names: Set<String> get() = props.keys

    private fun add(name: String, isRequired: Boolean, body: JsonObjectBuilder.() -> Unit) {
        props[name] = buildJsonObject(body)
        if (isRequired) required += name
    }

    fun string(
        name: String,
        description: String,
        required: Boolean = false,
        pattern: String? = null,
        enum: List<String>? = null,
        maxLength: Int? = null,
        format: String? = null,
    ) = add(name, required) {
        put("type", "string")
        put("description", description)
        pattern?.let { put("pattern", it) }
        enum?.let { values -> put("enum", buildJsonArray { values.forEach { add(JsonPrimitive(it)) } }) }
        maxLength?.let { put("maxLength", it) }
        format?.let { put("format", it) }
    }

    fun integer(name: String, description: String, min: Int, max: Int, default: Int? = null, required: Boolean = false) =
        add(name, required) {
            put("type", "integer")
            put("description", description)
            put("minimum", min)
            put("maximum", max)
            default?.let { put("default", it) }
        }

    fun boolean(name: String, description: String, default: Boolean? = null) = add(name, false) {
        put("type", "boolean")
        put("description", description)
        default?.let { put("default", it) }
    }

    fun stringArray(name: String, description: String, maxItems: Int, required: Boolean = false, itemPattern: String? = null) =
        add(name, required) {
            put("type", "array")
            put("description", description)
            put("minItems", 1)
            put("maxItems", maxItems)
            put("uniqueItems", true)
            put(
                "items",
                buildJsonObject {
                    put("type", "string")
                    itemPattern?.let { put("pattern", it) }
                },
            )
        }

    fun build(): ToolSchema = ToolSchema(
        properties = JsonObject(props),
        required = required.takeIf { it.isNotEmpty() }?.toList(),
    )
}

fun schema(block: SchemaBuilder.() -> Unit): Pair<ToolSchema, Set<String>> {
    val builder = SchemaBuilder().apply(block)
    return builder.build() to builder.names
}

/**
 * Typed, validating reader over a tool call's arguments.
 *
 * Unknown argument names are refused outright: a model steered by injected text may try to smuggle
 * extra parameters, and a misspelled filter silently ignored is a wrong answer presented as a right
 * one. Lenient on representation (`"5"` for 5, `"true"` for true) because clients differ, strict on
 * meaning.
 */
class Args(private val json: JsonObject, allowed: Set<String>) {
    /** Names of the arguments actually supplied (non-null). */
    val present: Set<String> get() = json.filterValues { it !is JsonNull }.keys

    init {
        val unknown = json.keys - allowed
        require(unknown.isEmpty()) {
            "Unknown argument(s): ${unknown.sorted().joinToString(", ") { it.take(40) }}. " +
                "Accepted: ${allowed.sorted().joinToString(", ").ifEmpty { "(none)" }}."
        }
    }

    private fun primitive(name: String): JsonPrimitive? = when (val e = json[name]) {
        null, is JsonNull -> null
        is JsonPrimitive -> e
        else -> throw IllegalArgumentException("$name must be a single value, not an object or array.")
    }

    fun optString(name: String): String? = primitive(name)?.contentOrNull?.takeIf { it.isNotBlank() }

    fun string(name: String): String = optString(name) ?: throw IllegalArgumentException("$name is required.")

    fun optInt(name: String, min: Int, max: Int): Int? {
        val p = primitive(name) ?: return null
        val value = p.contentOrNull?.trim()?.let { text ->
            text.toLongOrNull() ?: text.toDoubleOrNull()?.takeIf { it == Math.floor(it) && !it.isInfinite() }?.toLong()
        } ?: throw IllegalArgumentException("$name must be a whole number.")
        require(value in min..max) { "$name must be between $min and $max." }
        return value.toInt()
    }

    fun int(name: String, min: Int, max: Int, default: Int): Int = optInt(name, min, max) ?: default

    fun optBoolean(name: String): Boolean? {
        val p = primitive(name) ?: return null
        return p.booleanOrNull ?: when (p.contentOrNull?.trim()?.lowercase()) {
            "true" -> true
            "false" -> false
            else -> throw IllegalArgumentException("$name must be true or false.")
        }
    }

    fun boolean(name: String, default: Boolean): Boolean = optBoolean(name) ?: default

    fun optStringList(name: String, maxItems: Int): List<String>? {
        val e = json[name] ?: return null
        if (e is JsonNull) return null
        val items = when (e) {
            is JsonArray -> e.map {
                (it as? JsonPrimitive)?.takeIf { p -> p.isString }?.content
                    ?: throw IllegalArgumentException("$name must be an array of strings.")
            }
            // Some clients send a comma-separated string instead of an array.
            is JsonPrimitive -> e.content.split(',').map { it.trim() }.filter { it.isNotEmpty() }
            else -> throw IllegalArgumentException("$name must be an array of strings.")
        }
        require(items.size <= maxItems) { "$name accepts at most $maxItems items." }
        return items
    }

    /** One of [allowed], matched case-insensitively and returned in its canonical spelling. */
    fun optEnum(name: String, allowed: List<String>): String? = optString(name)?.let { v ->
        allowed.firstOrNull { it.equals(v.trim(), ignoreCase = true) }
            ?: throw IllegalArgumentException("$name must be one of: ${allowed.joinToString(", ")}.")
    }

    fun enum(name: String, allowed: List<String>): String = optEnum(name, allowed) ?: throw IllegalArgumentException("$name is required.")
}

/**
 * One MCP tool: its definition, the access level it needs, and its handler.
 *
 * [access] decides whether the tool is registered at all; [confirm] whether each call needs human
 * approval through the [ActionGate] (every state-changing tool, plus reads that hand out secrets).
 */
class ToolSpec(
    val name: String,
    val description: String,
    val inputSchema: ToolSchema,
    val argNames: Set<String>,
    val access: AccessLevel = AccessLevel.READ_ONLY,
    val confirm: Boolean = access != AccessLevel.READ_ONLY,
    val readOnly: Boolean = access == AccessLevel.READ_ONLY,
    val destructive: Boolean = false,
    val idempotent: Boolean = false,
    /** Whether the tool acts on one tenant (every API tool) or describes the server as a whole. */
    val tenantScoped: Boolean = true,
    val handler: suspend ToolCall.() -> CallToolResult,
) {
    /**
     * This tool with a `tenant` argument listing [names] (the operator's tenant names), required
     * unless a default tenant is configured. Added centrally, so no tool handler deals with tenants.
     */
    fun withTenantParameter(names: List<String>, required: Boolean): ToolSpec {
        val property = buildJsonObject {
            put("type", "string")
            put(
                "description",
                "Which configured Defender tenant to use" + (if (required) "" else " (defaults to the configured default tenant)") +
                    ". One of: ${names.joinToString(", ")}.",
            )
            put("enum", buildJsonArray { names.forEach { add(JsonPrimitive(it)) } })
        }
        val schema = ToolSchema(
            properties = JsonObject((inputSchema.properties ?: JsonObject(emptyMap())) + (TENANT_ARG to property)),
            required = ((inputSchema.required ?: emptyList()) + listOfNotNull(TENANT_ARG.takeIf { required })).takeIf { it.isNotEmpty() },
        )
        return ToolSpec(name, description, schema, argNames + TENANT_ARG, access, confirm, readOnly, destructive, idempotent, tenantScoped, handler)
    }

    fun definition(): Tool = Tool(
        name = name,
        inputSchema = inputSchema,
        description = description,
        annotations = ToolAnnotations(
            title = name.removePrefix("defender_").replace('_', ' '),
            readOnlyHint = readOnly,
            destructiveHint = if (readOnly) null else destructive,
            idempotentHint = if (readOnly) null else idempotent,
            openWorldHint = true,
        ),
    )
}

/** Build a [ToolSpec] with its schema from the DSL. */
fun tool(
    name: String,
    description: String,
    access: AccessLevel = AccessLevel.READ_ONLY,
    confirm: Boolean = access != AccessLevel.READ_ONLY,
    readOnly: Boolean = access == AccessLevel.READ_ONLY,
    destructive: Boolean = false,
    idempotent: Boolean = false,
    tenantScoped: Boolean = true,
    params: SchemaBuilder.() -> Unit = {},
    handler: suspend ToolCall.() -> CallToolResult,
): ToolSpec {
    val (schema, names) = schema(params)
    return ToolSpec(name, description, schema, names, access, confirm, readOnly, destructive, idempotent, tenantScoped, handler)
}

/** Name of the argument that selects a tenant. */
const val TENANT_ARG = "tenant"

/**
 * One configured tenant at run time. Everything that holds state against a tenant is per tenant:
 * the API client (and with it the token cache, rate limiters and concurrency limit; Defender's quotas
 * are per tenant) and the page-token store, so a token issued for one tenant means nothing to another.
 */
class TenantContext(
    val profile: TenantProfile,
    /** The single-tenant view of the configuration for this tenant. */
    val config: Config,
    val client: DefenderClient,
    renderer: ResponseRenderer,
    /** Server-wide access level narrowed by the tenant's own. */
    val accessLevel: AccessLevel,
    val cursors: PageCursorStore = PageCursorStore(),
) {
    val name: String get() = profile.name
    val pager: Pager = Pager(config, client, renderer, cursors)
}

/** Everything a tool handler can use; one per server. */
class ToolContext(
    val config: Config,
    val renderer: ResponseRenderer,
    val gate: ActionGate,
    val tenants: List<TenantContext>,
) {
    /** A single-tenant context around [client] (the primary tenant of [config]). */
    constructor(
        config: Config,
        client: DefenderClient,
        renderer: ResponseRenderer,
        gate: ActionGate,
        cursors: PageCursorStore = PageCursorStore(),
    ) : this(
        config,
        renderer,
        gate,
        listOf(
            TenantContext(
                config.primaryTenant,
                config.forTenant(config.primaryTenant),
                client,
                renderer,
                config.accessFor(config.primaryTenant),
                cursors,
            ),
        ),
    )

    init {
        require(tenants.isNotEmpty()) { "at least one tenant is required" }
    }

    val isMultiTenant: Boolean get() = tenants.size > 1

    /** The primary tenant's client, pager and page tokens. */
    val client: DefenderClient get() = tenants.first().client
    val pager: Pager get() = tenants.first().pager
    val cursors: PageCursorStore get() = tenants.first().cursors

    /**
     * The tenant a call targets. [name] is matched case-insensitively against the configured names
     * only; it never reaches a URL. With several tenants and no default, a name is mandatory, so a
     * call can never land on a tenant the caller did not choose.
     */
    fun resolveTenant(name: String?): TenantContext {
        val names = tenants.joinToString(", ") { it.name }
        if (name == null) {
            if (!isMultiTenant) return tenants.first()
            val fallback = config.defaultTenant
                ?: throw IllegalArgumentException("$TENANT_ARG is required: this server has several tenants ($names).")
            return tenants.first { it.name == fallback }
        }
        val wanted = name.trim().lowercase()
        return tenants.firstOrNull { it.name == wanted }
            ?: throw IllegalArgumentException("Unknown $TENANT_ARG '${name.take(40)}'. Configured tenants: $names.")
    }
}

/** One invocation: validated arguments plus the context and the approval hook. */
class ToolCall(
    val spec: ToolSpec,
    val args: Args,
    val ctx: ToolContext,
    private val approver: Approver,
    /** The tenant this call acts on, already resolved and access-checked. */
    val tenant: TenantContext = ctx.tenants.first(),
) {
    val client: DefenderClient get() = tenant.client
    val pager: Pager get() = tenant.pager

    fun render(response: DefenderClient.ApiResponse, options: ResponseRenderer.Options = ResponseRenderer.Options()) =
        ctx.renderer.render(response, options)

    /**
     * Ask the [ActionGate] for permission to perform [summary]; null when approved, otherwise the
     * refusal to return. [details] are shown to the human approver as labelled lines.
     */
    suspend fun authorize(summary: String, details: List<Pair<String, String>>): CallToolResult? =
        if (ctx.isMultiTenant) {
            // The tenant goes in the summary as well as the details, so the human sees which organisation is affected.
            ctx.gate.authorize(spec.name, "$summary in tenant '${tenant.name}'", listOf("Tenant" to tenant.name) + details, approver)
        } else {
            ctx.gate.authorize(spec.name, summary, details, approver)
        }
}
