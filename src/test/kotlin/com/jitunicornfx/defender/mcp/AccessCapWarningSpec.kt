package com.jitunicornfx.defender.mcp

import com.github.ajalt.clikt.testing.test
import com.jitunicornfx.defender.mcp.testutil.FakeDefender
import com.jitunicornfx.defender.mcp.testutil.text
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotContain
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/**
 * A tenant asking for more access than the server-wide level allows is capped by design; these
 * tests pin that the cap is announced (stderr and server info) instead of happening silently.
 */
class AccessCapWarningSpec : FunSpec({
    val tenantId = "1d56e847-0000-4000-8000-000000000001"
    val clientId = "77518a1a-0000-4000-8000-000000000002"

    // The reported configuration: one named tenant with ACCESS_LEVEL=destructive and no DEFENDER_ACCESS_LEVEL.
    fun reported(vararg extra: Pair<String, String>) = Config.fromEnv(
        mapOf(
            Config.ENV_TENANTS to "illumia",
            "DEFENDER_ILLUMIA_TENANT_ID" to tenantId,
            "DEFENDER_ILLUMIA_CLIENT_ID" to clientId,
            "DEFENDER_ILLUMIA_CLIENT_SECRET" to "test-secret-value",
            "DEFENDER_ILLUMIA_REGION" to "us",
            "DEFENDER_ILLUMIA_ACCESS_LEVEL" to "destructive",
        ) + extra,
    )

    suspend fun serverInfo(config: Config) = DefenderRuntime(config, client = FakeDefender().client(config)).use { rt ->
        JsonCodec.compact.parseToJsonElement(invokeTool(rt.tools.last(), null, rt.context) { ApprovalOutcome.APPROVED }.text()).jsonObject
    }

    test("the reported config is capped at read-only, and the notice names the variable and the fix") {
        val config = reported()
        config.effectiveAccessLevel shouldBe AccessLevel.READ_ONLY
        val notices = config.accessCapNotices()
        notices shouldHaveSize 1
        notices.single() shouldContain "Tenant 'illumia' asks for 'destructive' access (DEFENDER_ILLUMIA_ACCESS_LEVEL)"
        notices.single() shouldContain "server-wide DEFENDER_ACCESS_LEVEL is 'read-only'"
        notices.single() shouldContain "set DEFENDER_ACCESS_LEVEL (or --access) to 'destructive'"
        notices.single() shouldNotContain "test-secret-value"
    }

    test("the cap is printed as a startup warning") {
        val config = reported()
        val r = DefenderMcpCommand({ config }, { _, _, _, _ -> }, { true }).test("")
        r.statusCode shouldBe 0
        r.stderr shouldContain "WARNING: Tenant 'illumia' asks for 'destructive' access"
    }

    test("the cap is reported by defender_server_info, where MCP clients actually show it") {
        val warnings = serverInfo(reported())["accessWarnings"] as JsonArray
        warnings shouldHaveSize 1
        warnings.single().jsonPrimitive.content shouldContain "DEFENDER_ILLUMIA_ACCESS_LEVEL"
    }

    test("setting the server-wide level lifts the cap and the warning disappears") {
        val config = reported(Config.ENV_ACCESS_LEVEL to "destructive")
        config.effectiveAccessLevel shouldBe AccessLevel.DESTRUCTIVE
        config.accessCapNotices().shouldBeEmpty()
        serverInfo(config).containsKey("accessWarnings") shouldBe false
        serverInfo(config)["accessLevel"]!!.jsonPrimitive.content shouldBe "destructive"
    }

    test("--access on the command line also lifts the cap") {
        var served: Config? = null
        val r = DefenderMcpCommand({ reported() }, { _, _, _, c -> served = c }, { true }).test("--access destructive")
        r.stderr shouldNotContain "asks for"
        served!!.effectiveAccessLevel shouldBe AccessLevel.DESTRUCTIVE
    }

    test("a tenant that narrows (or matches) the server-wide level produces no warning") {
        reported(Config.ENV_ACCESS_LEVEL to "destructive", "DEFENDER_ILLUMIA_ACCESS_LEVEL" to "write").accessCapNotices().shouldBeEmpty()
        reported(Config.ENV_ACCESS_LEVEL to "write", "DEFENDER_ILLUMIA_ACCESS_LEVEL" to "write").accessCapNotices().shouldBeEmpty()
    }

    test("only the over-asking tenants are named when several are configured") {
        val config = Config.fromEnv(
            mapOf(
                Config.ENV_TENANTS to "prod,lab",
                Config.ENV_ACCESS_LEVEL to "write",
                "DEFENDER_PROD_TENANT_ID" to tenantId, "DEFENDER_PROD_CLIENT_ID" to clientId, "DEFENDER_PROD_CLIENT_SECRET" to "a",
                "DEFENDER_PROD_ACCESS_LEVEL" to "read-only",
                "DEFENDER_LAB_TENANT_ID" to tenantId, "DEFENDER_LAB_CLIENT_ID" to clientId, "DEFENDER_LAB_CLIENT_SECRET" to "b",
                "DEFENDER_LAB_ACCESS_LEVEL" to "destructive",
            ),
        )
        val notices = config.accessCapNotices()
        notices shouldHaveSize 1
        notices.single() shouldContain "Tenant 'lab' asks for 'destructive'"
        notices.single() shouldContain "capped at 'write'"
    }

    test("a directly-built config without named tenants describes the setting generically") {
        val config = Config(
            EntraCredentials(tenantId, clientId, "s"),
            tenantAccessLevel = AccessLevel.WRITE,
        )
        config.accessCapNotices().single() shouldContain "(the tenant's access level)"
    }
})
