package com.jitunicornfx.defender.mcp.testutil

import com.jitunicornfx.defender.mcp.AccessLevel
import com.jitunicornfx.defender.mcp.ActionBudget
import com.jitunicornfx.defender.mcp.ActionGate
import com.jitunicornfx.defender.mcp.Approver
import com.jitunicornfx.defender.mcp.ApprovalOutcome
import com.jitunicornfx.defender.mcp.AuditSink
import com.jitunicornfx.defender.mcp.Config
import com.jitunicornfx.defender.mcp.ConfirmationMode
import com.jitunicornfx.defender.mcp.DefenderClient
import com.jitunicornfx.defender.mcp.DefenderRuntime
import com.jitunicornfx.defender.mcp.EntraCredentials
import com.jitunicornfx.defender.mcp.JsonCodec
import com.jitunicornfx.defender.mcp.ResponseRenderer
import com.jitunicornfx.defender.mcp.ToolCall
import com.jitunicornfx.defender.mcp.ToolContext
import com.jitunicornfx.defender.mcp.ToolSpec
import com.jitunicornfx.defender.mcp.buildServer
import com.jitunicornfx.defender.mcp.invokeTool
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.client.request.HttpRequestData
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.content.OutgoingContent
import io.ktor.http.content.TextContent
import io.ktor.http.headersOf
import io.modelcontextprotocol.kotlin.sdk.client.Client
import io.modelcontextprotocol.kotlin.sdk.client.ClientOptions
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.ClientCapabilities
import io.modelcontextprotocol.kotlin.sdk.types.ElicitRequest
import io.modelcontextprotocol.kotlin.sdk.types.ElicitResult
import io.modelcontextprotocol.kotlin.sdk.types.Implementation
import io.modelcontextprotocol.kotlin.sdk.types.TextContent as McpText
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import java.util.Collections

const val TEST_TENANT = "11111111-2222-3333-4444-555555555555"
const val TEST_CLIENT_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
const val TEST_SECRET = "s3cr3t-value~XYZ"
const val MACHINE_ID = "1e5bc9d7e413ddd7902c2932e418702b84d0cc07"
const val ACTION_ID = "7f4bd8a0-8b36-4c0c-9b8b-0f6b1f0f4c11"

/** A valid configuration for tests; never talks to a real tenant (every test uses a [MockEngine]). */
fun testConfig(
    access: AccessLevel = AccessLevel.READ_ONLY,
    confirmation: ConfirmationMode = ConfirmationMode.ELICIT,
    maxResultChars: Int = Config.DEFAULT_MAX_RESULT_CHARS,
    maxActionsPerHour: Int = Config.DEFAULT_MAX_ACTIONS_PER_HOUR,
): Config = Config(
    credentials = EntraCredentials(TEST_TENANT, TEST_CLIENT_ID, TEST_SECRET),
    accessLevel = access,
    confirmation = confirmation,
    maxResultChars = maxResultChars,
    maxActionsPerHour = maxActionsPerHour,
)

/** Canned HTTP response for the mock engine. */
data class Canned(
    val status: HttpStatusCode = HttpStatusCode.OK,
    val body: String = "{}",
    val contentType: String = "application/json",
    val headers: Map<String, String> = emptyMap(),
)

/** A recorded request: method, full URL, headers and the text body, if any. */
data class Recorded(val request: HttpRequestData, val body: String?) {
    val path: String get() = request.url.encodedPath
    val url: String get() = request.url.toString()
    fun bodyJson(): JsonElement = JsonCodec.compact.parseToJsonElement(body!!)
}

/**
 * A mock Microsoft cloud: the Entra ID token endpoint always issues a token, and every other
 * request is answered by [api]. All requests (token and API) are recorded.
 */
class FakeDefender(
    var api: (HttpRequestData) -> Canned = { Canned() },
    var token: (HttpRequestData) -> Canned = {
        Canned(body = """{"token_type":"Bearer","expires_in":3599,"access_token":"eyJ0eXAiOiJKV1QiLCJhbGciOi.test.token"}""")
    },
) {
    val recorded: MutableList<Recorded> = Collections.synchronizedList(mutableListOf())

    val engine = MockEngine { request ->
        val body = when (val content = request.body) {
            is TextContent -> content.text
            is OutgoingContent.ByteArrayContent -> content.bytes().decodeToString()
            else -> null
        }
        recorded += Recorded(request, body)
        val canned = if (request.url.host.startsWith("login.")) token(request) else api(request)
        respond(
            content = canned.body,
            status = canned.status,
            headers = headersOf(
                *(mapOf(HttpHeaders.ContentType to canned.contentType) + canned.headers)
                    .map { (k, v) -> k to listOf(v) }.toTypedArray(),
            ),
        )
    }

    /** API requests only (token requests excluded). */
    val apiRequests: List<Recorded> get() = recorded.filter { !it.request.url.host.startsWith("login.") }
    val tokenRequests: List<Recorded> get() = recorded.filter { it.request.url.host.startsWith("login.") }
    val last: Recorded get() = apiRequests.last()

    fun client(config: Config = testConfig(), sleep: suspend (Long) -> Unit = {}): DefenderClient =
        DefenderClient(config, engine = engine, sleep = sleep)
}

/** An approver with a fixed answer that counts how often it was asked and keeps the last message. */
class FixedApprover(var outcome: ApprovalOutcome = ApprovalOutcome.APPROVED) : Approver {
    var asked = 0
    var lastMessage: String? = null
    override suspend fun approve(message: String): ApprovalOutcome {
        asked++
        lastMessage = message
        return outcome
    }
}

/** Collects audit lines. */
class ListAudit : AuditSink {
    val lines: MutableList<String> = Collections.synchronizedList(mutableListOf())
    override fun record(line: String) {
        lines += line
    }
}

/** Direct (non-MCP) tool invocation, for fast handler tests. */
class ToolHarness(
    val config: Config = testConfig(),
    val fake: FakeDefender = FakeDefender(),
    val approver: FixedApprover = FixedApprover(),
    val audit: ListAudit = ListAudit(),
) {
    val client: DefenderClient = fake.client(config)
    val gate = ActionGate(config.confirmation, ActionBudget(config.maxActionsPerHour), audit)
    val context = ToolContext(config, client, ResponseRenderer(config.maxResultChars), gate)

    suspend fun call(spec: ToolSpec, args: JsonObject = JsonObject(emptyMap())): CallToolResult =
        invokeTool(spec, args, context, approver)

    suspend fun call(spec: ToolSpec, vararg args: Pair<String, Any?>): CallToolResult = call(spec, jsonArgs(*args))
}

/** Build a JsonObject from Kotlin values (String, Number, Boolean, List<String>, null). */
fun jsonArgs(vararg pairs: Pair<String, Any?>): JsonObject = JsonObject(
    pairs.associate { (k, v) ->
        k to when (v) {
            null -> kotlinx.serialization.json.JsonNull
            is String -> kotlinx.serialization.json.JsonPrimitive(v)
            is Number -> kotlinx.serialization.json.JsonPrimitive(v)
            is Boolean -> kotlinx.serialization.json.JsonPrimitive(v)
            is List<*> -> kotlinx.serialization.json.JsonArray(v.map { kotlinx.serialization.json.JsonPrimitive(it as String) })
            is JsonElement -> v
            else -> error("unsupported $v")
        }
    },
)

fun CallToolResult.text(): String = content.filterIsInstance<McpText>().joinToString("\n") { it.text }

val CallToolResult.failed: Boolean get() = isError == true

/**
 * A full in-process MCP client/server pair over [buildServer], so tests exercise tool listing,
 * argument transport and elicitation exactly as a real client would.
 *
 * @param elicitation when non-null the client advertises elicitation and answers with it.
 */
class McpHarness(val runtime: DefenderRuntime, val client: Client) {
    suspend fun call(name: String, args: Map<String, Any?> = emptyMap()): CallToolResult = client.callTool(name, args)
}

suspend fun mcpHarness(
    config: Config = testConfig(),
    fake: FakeDefender = FakeDefender(),
    audit: ListAudit = ListAudit(),
    elicitation: ((ElicitRequest) -> ElicitResult)? = null,
): McpHarness {
    val runtime = DefenderRuntime(
        config,
        client = fake.client(config),
        gate = ActionGate(config.confirmation, ActionBudget(config.maxActionsPerHour), audit),
    )
    val server = buildServer(runtime)
    val (clientTransport, serverTransport) = InMemoryTransport.createLinkedPair()
    val capabilities = if (elicitation != null) ClientCapabilities(elicitation = ClientCapabilities.Elicitation()) else ClientCapabilities()
    val client = Client(Implementation("test-client", "1.0"), ClientOptions(capabilities = capabilities))
    if (elicitation != null) client.setElicitationHandler(elicitation)
    coroutineScope {
        launch { client.connect(clientTransport) }
        launch { server.createSession(serverTransport) }
    }
    return McpHarness(runtime, client)
}

/** Unused-import guard for helpers some specs reference reflectively. */
@Suppress("unused")
private fun keep(call: ToolCall) = call
