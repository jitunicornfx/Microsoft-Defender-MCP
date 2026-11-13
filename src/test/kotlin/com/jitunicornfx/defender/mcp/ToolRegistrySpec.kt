package com.jitunicornfx.defender.mcp

import com.jitunicornfx.defender.mcp.testutil.FakeDefender
import com.jitunicornfx.defender.mcp.testutil.MACHINE_ID
import com.jitunicornfx.defender.mcp.testutil.TEST_SECRET
import com.jitunicornfx.defender.mcp.testutil.ToolHarness
import com.jitunicornfx.defender.mcp.testutil.failed
import com.jitunicornfx.defender.mcp.testutil.mcpHarness
import com.jitunicornfx.defender.mcp.testutil.testConfig
import com.jitunicornfx.defender.mcp.testutil.text
import com.jitunicornfx.defender.mcp.tools.HuntingTools
import com.jitunicornfx.defender.mcp.tools.IndicatorTools
import com.jitunicornfx.defender.mcp.tools.InvestigationTools
import com.jitunicornfx.defender.mcp.tools.MachineTools
import com.jitunicornfx.defender.mcp.tools.RemediationTools
import com.jitunicornfx.defender.mcp.tools.TriageTools
import com.jitunicornfx.defender.mcp.tools.UserTools
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.collections.shouldContainAll
import io.kotest.matchers.collections.shouldContainExactly
import io.kotest.matchers.collections.shouldContainExactlyInAnyOrder
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.collections.shouldNotContain
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldNotBeBlank
import io.kotest.matchers.string.shouldNotContain
import io.kotest.matchers.string.shouldStartWith
import io.kotest.property.Arb
import io.kotest.property.arbitrary.filter
import io.kotest.property.arbitrary.string
import io.kotest.property.checkAll
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

private fun names(specs: List<ToolSpec>) = specs.map { it.name }

private fun infoJson(result: io.modelcontextprotocol.kotlin.sdk.types.CallToolResult): JsonObject =
    JsonCodec.compact.parseToJsonElement(result.text()).jsonObject

class ToolRegistrySpec : FunSpec({

    context("apiTools") {
        val tools = ToolRegistry.apiTools

        test("is the concatenation of every tool group, in a stable order") {
            names(tools) shouldContainExactly names(
                HuntingTools.all + InvestigationTools.all + MachineTools.all + IndicatorTools.all +
                    RemediationTools.all + UserTools.all + TriageTools.all,
            )
        }

        test("names are unique, prefixed defender_, and never collide with the server-info tool") {
            tools.shouldNotBeEmpty()
            names(tools).toSet().size shouldBe tools.size
            tools.forEach { it.name shouldStartWith "defender_" }
            names(tools) shouldNotContain ToolRegistry.SERVER_INFO_TOOL
            tools.forEach { it.name.matches(Regex("^[a-z0-9_]{1,64}$")) shouldBe true }
        }

        test("every tool has a description and an object schema whose properties are all described") {
            tools.forEach { spec ->
                spec.description.shouldNotBeBlank()
                val schema = spec.definition().inputSchema
                schema.type shouldBe "object"
                val props = schema.properties ?: JsonObject(emptyMap())
                props.keys shouldBe spec.argNames
                props.values.forEach { p ->
                    p.jsonObject["description"]!!.jsonPrimitive.content.shouldNotBeBlank()
                    p.jsonObject["type"]!!.jsonPrimitive.content.shouldNotBeBlank()
                }
                (schema.required ?: emptyList()).forEach { props.keys shouldContain it }
            }
        }

        test("every OData list tool and collection subresource tool takes page_token and max_pages, and only read-only tools do") {
            val paged = setOf(
                "defender_list_investigations", "defender_list_machines", "defender_list_machine_actions", "defender_list_remediation_tasks",
                "defender_get_machine_logon_users", "defender_get_machine_alerts", "defender_get_machine_software",
                "defender_get_machine_vulnerabilities", "defender_get_machine_recommendations", "defender_get_machine_missing_kbs",
                "defender_get_domain_alerts", "defender_get_domain_machines", "defender_get_ip_alerts",
                "defender_get_remediation_task_machines", "defender_get_user_alerts", "defender_get_user_machines",
            )
            names(tools.filter { "page_token" in it.argNames }) shouldContainExactlyInAnyOrder paged
            tools.forEach { spec ->
                ("page_token" in spec.argNames) shouldBe ("max_pages" in spec.argNames)
                if ("top" in spec.argNames) spec.argNames shouldContainAll listOf("skip", "page_token", "max_pages")
                if ("page_token" in spec.argNames) {
                    spec.access shouldBe AccessLevel.READ_ONLY
                    val token = spec.definition().inputSchema.properties!!["page_token"]!!.jsonObject
                    token["pattern"]!!.jsonPrimitive.content shouldBe PageCursorStore.TOKEN_PATTERN
                    val maxPages = spec.definition().inputSchema.properties!!["max_pages"]!!.jsonObject
                    maxPages["minimum"]!!.jsonPrimitive.int shouldBe 1
                    maxPages["maximum"]!!.jsonPrimitive.int shouldBe 10
                }
            }
        }

        test("every non-read-only tool requires approval") {
            tools.filter { it.access != AccessLevel.READ_ONLY }.forEach { it.confirm shouldBe true }
        }
    }

    context("select") {
        test("access level filters the catalogue") {
            val ro = ToolRegistry.select(testConfig(access = AccessLevel.READ_ONLY))
            val w = ToolRegistry.select(testConfig(access = AccessLevel.WRITE))
            val d = ToolRegistry.select(testConfig(access = AccessLevel.DESTRUCTIVE))
            ro.all { it.access == AccessLevel.READ_ONLY } shouldBe true
            w.none { it.access == AccessLevel.DESTRUCTIVE } shouldBe true
            w.any { it.access == AccessLevel.WRITE } shouldBe true
            names(d) shouldContainExactly names(ToolRegistry.apiTools)
            names(ro) shouldContain "defender_list_machines"
            names(ro) shouldNotContain "defender_tag_machine"
            names(w) shouldContain "defender_tag_machine"
            names(w) shouldNotContain "defender_update_machine"
            names(d) shouldContain "defender_update_machine"
        }

        test("globs narrow the selection, case-insensitively") {
            val cfg = testConfig().copy(toolGlobs = listOf("DEFENDER_GET_MACHINE*", "defender_list_machine?"))
            names(ToolRegistry.select(cfg)) shouldContainExactlyInAnyOrder listOf(
                "defender_list_machines",
                "defender_get_machine",
                "defender_get_machine_logon_users",
                "defender_get_machine_alerts",
                "defender_get_machine_software",
                "defender_get_machine_vulnerabilities",
                "defender_get_machine_recommendations",
                "defender_get_machine_missing_kbs",
                "defender_get_machine_action",
            )
        }

        test("globs can never raise access above the configured level") {
            val ro = ToolRegistry.select(testConfig(access = AccessLevel.READ_ONLY).copy(toolGlobs = listOf("*")))
            ro.all { it.access == AccessLevel.READ_ONLY } shouldBe true
            ToolRegistry.select(testConfig(access = AccessLevel.READ_ONLY).copy(toolGlobs = listOf("defender_tag_machine*"))).shouldBeEmpty()
            val w = ToolRegistry.select(testConfig(access = AccessLevel.WRITE).copy(toolGlobs = listOf("defender_*tag*", "defender_update_machine")))
            names(w) shouldContain "defender_tag_machine"
            names(w) shouldNotContain "defender_tag_machines_bulk"
            names(w) shouldNotContain "defender_update_machine"
        }

        test("property: for any glob set, the selection is a subset of what the access level permits") {
            val pieces = listOf("*", "?", "defender_", "machine", "tag", "isolate", "_", "get", "list")
            checkAll(100, Arb.string(0, 6)) { seed ->
                val globs = seed.map { pieces[it.code % pieces.size] }.chunked(3).map { it.joinToString("") }
                AccessLevel.entries.forEach { level ->
                    val selected = ToolRegistry.select(testConfig(access = level).copy(toolGlobs = globs))
                    selected.all { level.permits(it.access) } shouldBe true
                    names(ToolRegistry.select(testConfig(access = level))) shouldContainAll names(selected)
                }
            }
        }
    }

    context("globToRegex") {
        test("* and ? wildcards; everything else is literal") {
            ToolRegistry.globToRegex("a*").matches("abc") shouldBe true
            ToolRegistry.globToRegex("a?c").matches("abc") shouldBe true
            ToolRegistry.globToRegex("a?c").matches("ac") shouldBe false
            ToolRegistry.globToRegex("a.c").matches("abc") shouldBe false
            ToolRegistry.globToRegex("a.c").matches("a.c") shouldBe true
            ToolRegistry.globToRegex("(a|b)[x]+").matches("(a|b)[x]+") shouldBe true
            ToolRegistry.globToRegex("(a|b)[x]+").matches("a") shouldBe false
            ToolRegistry.globToRegex("\\Q\\E").matches("\\Q\\E") shouldBe true
        }

        test("is anchored at both ends") {
            ToolRegistry.globToRegex("machine").matches("defender_list_machines") shouldBe false
            ToolRegistry.globToRegex("").matches("") shouldBe true
            ToolRegistry.globToRegex("").matches("x") shouldBe false
        }

        test("property: a glob without wildcards matches exactly itself, ignoring case") {
            checkAll(300, Arb.string(0, 30).filter { '*' !in it && '?' !in it }) { s ->
                val re = ToolRegistry.globToRegex(s)
                re.matches(s) shouldBe true
                re.matches(s + "x") shouldBe false
            }
        }

        test("property: * matches any string") {
            checkAll(200, Arb.string(0, 40)) { s ->
                ToolRegistry.globToRegex("*").matches(s.replace("\n", "")) shouldBe true
            }
        }
    }

    context("unmatchedGlobs") {
        test("reports only globs that match no tool") {
            ToolRegistry.unmatchedGlobs(listOf("defender_list_*", "defender_typo_x", "*", "nothing?")) shouldContainExactly
                listOf("defender_typo_x", "nothing?")
            ToolRegistry.unmatchedGlobs(emptyList()).shouldBeEmpty()
        }
    }

    context("serverInfoTool") {
        test("under ELICIT, needsApproval mirrors each tool's confirm flag; output is server-authored and unfenced") {
            val config = testConfig(access = AccessLevel.WRITE, confirmation = ConfirmationMode.ELICIT)
            val h = ToolHarness(config = config)
            val selected = ToolRegistry.select(config)
            val spec = ToolRegistry.serverInfoTool(config, selected, h.gate)
            spec.name shouldBe ToolRegistry.SERVER_INFO_TOOL
            spec.access shouldBe AccessLevel.READ_ONLY
            spec.argNames.shouldBeEmpty()

            val r = h.call(spec)
            r.failed shouldBe false
            r.text() shouldNotContain "UNTRUSTED_DEFENDER_DATA id="
            r.text() shouldNotContain TEST_SECRET
            val info = infoJson(r)
            info["server"]!!.jsonPrimitive.content shouldBe SERVER_NAME
            info["version"]!!.jsonPrimitive.content shouldBe SERVER_VERSION
            info["cloud"]!!.jsonPrimitive.content shouldBe "commercial"
            info["region"]!!.jsonPrimitive.content shouldBe "global"
            info["apiBaseUrl"]!!.jsonPrimitive.content shouldBe "https://api.security.microsoft.com"
            info["huntingApi"]!!.jsonPrimitive.content shouldBe "https://graph.microsoft.com/v1.0/security/runHuntingQuery"
            info["accessLevel"]!!.jsonPrimitive.content shouldBe "write"
            info["humanApproval"]!!.jsonPrimitive.content shouldBe "elicit"
            info["stateChangeBudget"]!!.jsonObject["perHour"]!!.jsonPrimitive.int shouldBe 20
            info["stateChangeBudget"]!!.jsonObject["usedThisHour"]!!.jsonPrimitive.int shouldBe 0
            info["securityNotes"]!!.jsonArray.size shouldBe 3

            val listed = info["tools"]!!.jsonArray.map { it.jsonObject }
            listed.map { it["name"]!!.jsonPrimitive.content } shouldContainExactly names(selected)
            listed.forEach { t ->
                val s = selected.single { it.name == t["name"]!!.jsonPrimitive.content }
                t["access"]!!.jsonPrimitive.content shouldBe s.access.name.lowercase()
                t["needsApproval"]!!.jsonPrimitive.boolean shouldBe s.confirm
            }
            listed.single { it["name"]!!.jsonPrimitive.content == "defender_tag_machine" }["needsApproval"]!!.jsonPrimitive.boolean shouldBe true
            listed.single { it["name"]!!.jsonPrimitive.content == "defender_list_machines" }["needsApproval"]!!.jsonPrimitive.boolean shouldBe false
        }

        test("under NONE no tool reports needing approval, and budget usage is live") {
            val config = testConfig(access = AccessLevel.DESTRUCTIVE, confirmation = ConfirmationMode.NONE, maxActionsPerHour = 7)
            val h = ToolHarness(config = config)
            val spec = ToolRegistry.serverInfoTool(config, ToolRegistry.select(config), h.gate)
            h.call(MachineTools.tagMachine, "machine_id" to MACHINE_ID, "tag" to "x", "action" to "Add").failed shouldBe false

            val info = infoJson(h.call(spec))
            info["humanApproval"]!!.jsonPrimitive.content shouldBe "none"
            info["accessLevel"]!!.jsonPrimitive.content shouldBe "destructive"
            info["stateChangeBudget"]!!.jsonObject["perHour"]!!.jsonPrimitive.int shouldBe 7
            info["stateChangeBudget"]!!.jsonObject["usedThisHour"]!!.jsonPrimitive.int shouldBe 1
            info["tools"]!!.jsonArray.none { it.jsonObject["needsApproval"]!!.jsonPrimitive.boolean } shouldBe true
        }

        test("rejects unexpected arguments") {
            val config = testConfig()
            val h = ToolHarness(config = config)
            h.call(ToolRegistry.serverInfoTool(config, emptyList(), h.gate), "x" to "y").failed shouldBe true
        }

        test("is exposed over MCP alongside the selected tools and lists only them") {
            val config = testConfig().copy(toolGlobs = listOf("defender_list_machines"))
            val h = mcpHarness(config = config, fake = FakeDefender())
            h.client.listTools().tools.map { it.name } shouldContainExactlyInAnyOrder listOf("defender_list_machines", ToolRegistry.SERVER_INFO_TOOL)
            val info = infoJson(h.call(ToolRegistry.SERVER_INFO_TOOL))
            info["tools"]!!.jsonArray.map { it.jsonObject["name"]!!.jsonPrimitive.content } shouldContainExactly listOf("defender_list_machines")
        }
    }
})
