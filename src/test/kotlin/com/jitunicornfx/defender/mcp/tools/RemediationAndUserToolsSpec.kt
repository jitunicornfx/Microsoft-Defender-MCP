package com.jitunicornfx.defender.mcp.tools

import com.jitunicornfx.defender.mcp.Args
import com.jitunicornfx.defender.mcp.PageCursorStore
import com.jitunicornfx.defender.mcp.ResponseRenderer
import com.jitunicornfx.defender.mcp.SchemaBuilder
import com.jitunicornfx.defender.mcp.ToolCall
import com.jitunicornfx.defender.mcp.Validators
import com.jitunicornfx.defender.mcp.testutil.Canned
import com.jitunicornfx.defender.mcp.testutil.FakeDefender
import com.jitunicornfx.defender.mcp.testutil.FixedApprover
import com.jitunicornfx.defender.mcp.testutil.ToolHarness
import com.jitunicornfx.defender.mcp.testutil.failed
import com.jitunicornfx.defender.mcp.testutil.jsonArgs
import com.jitunicornfx.defender.mcp.testutil.text
import com.jitunicornfx.defender.mcp.textResult
import com.jitunicornfx.defender.mcp.tool
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldContainExactly
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotContain
import io.kotest.property.Arb
import io.kotest.property.arbitrary.string
import io.kotest.property.arbitrary.stringPattern
import io.kotest.property.checkAll
import io.ktor.http.HttpMethod
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

private fun remHarness(body: String = """{"value":[]}""") = ToolHarness(fake = FakeDefender(api = { Canned(body = body) }))

private val ToolHarness.lastParams get() = fake.last.request.url.parameters

private fun callFor(vararg args: Pair<String, Any?>, fields: Set<String> = setOf("status", "createdOn")): ToolCall {
    val spec = tool(name = "defender_test_list", description = "test", params = { paging(fields) }) { textResult("") }
    return ToolCall(spec, Args(jsonArgs(*args), spec.argNames), ToolHarness().context, FixedApprover())
}

class RemediationAndUserToolsSpec : FunSpec({

    context("defender_list_remediation_tasks") {
        val tool = RemediationTools.listTasks

        test("no arguments: \$top=50 only") {
            val h = remHarness()
            h.call(tool).failed shouldBe false
            h.fake.last.request.method shouldBe HttpMethod.Get
            h.fake.last.path shouldBe "/api/remediationTasks"
            h.lastParams["\$top"] shouldBe "50"
            h.lastParams["\$filter"].shouldBeNull()
        }

        test("status and created_after build exact filters") {
            val h = remHarness()
            h.call(tool, "status" to " Active ")
            h.lastParams["\$filter"] shouldBe "status eq 'Active'"
            h.call(tool, "created_after" to "2026-03-01T12:30:00-05:00")
            h.lastParams["\$filter"] shouldBe "createdOn ge 2026-03-01T17:30:00Z"
            h.call(tool, "status" to "Completed", "created_after" to "2026-03-01T00:00:00Z", "filter" to "status ne 'Active'", "skip" to 5, "top" to 7)
            h.lastParams["\$filter"] shouldBe "status eq 'Completed' and createdOn ge 2026-03-01T00:00:00Z and (status ne 'Active')"
            h.lastParams["\$skip"] shouldBe "5"
            h.lastParams["\$top"] shouldBe "7"
        }

        test("raw filter fields are restricted to createdOn and status") {
            val h = remHarness()
            val r = h.call(tool, "filter" to "id eq '1'")
            r.failed shouldBe true
            r.text() shouldContain "Allowed fields: createdOn, status."
            h.call(tool, "filter" to "CREATEDON gt 2026-01-01T00:00:00Z").failed shouldBe false
        }

        test("invalid status or timestamp is refused before any call") {
            for ((args, msg) in listOf(
                ("status" to "Active' or 1 eq 1") to "status must be a single word",
                ("status" to "In progress") to "status must be a single word",
                ("created_after" to "last week") to "created_after must be an ISO-8601",
            )) {
                val h = remHarness()
                val r = h.call(tool, args)
                r.failed shouldBe true
                r.text() shouldContain msg
                h.fake.recorded.shouldBeEmpty()
            }
        }
    }

    context("remediation task by ID") {
        listOf(
            RemediationTools.getTask to "",
            RemediationTools.getTaskMachines to "/machineReferences",
        ).forEach { (tool, suffix) ->
            test("${tool.name}: GETs /api/remediationTasks/{id}$suffix with a trimmed ID") {
                val h = remHarness("""{"id":"abc-123","title":"Update Chrome"}""")
                val r = h.call(tool, "task_id" to "  abc-123 ")
                r.failed shouldBe false
                h.fake.last.path shouldBe "/api/remediationTasks/abc-123$suffix"
                r.text() shouldContain "Update Chrome"
            }

            test("${tool.name}: invalid task IDs are refused without an API call") {
                for (bad in listOf("a_b", "x".repeat(65), "../a", "a b", "a/b", "a.b", "a;b", "%41", "", "​abc")) {
                    val h = remHarness()
                    val r = h.call(tool, "task_id" to bad)
                    r.failed shouldBe true
                    r.text() shouldContain "task_id"
                    h.fake.recorded.shouldBeEmpty()
                }
            }

            test("${tool.name}: a 64-character ID is accepted") {
                val h = remHarness()
                h.call(tool, "task_id" to "a".repeat(64)).failed shouldBe false
            }
        }

        test("schema exposes the task-ID pattern") {
            val p = RemediationTools.getTask.definition().inputSchema.properties!!["task_id"]!!.jsonObject["pattern"]!!.jsonPrimitive.content
            p shouldBe "^[A-Za-z0-9-]{1,64}$"
            RemediationTools.all.size shouldBe 3
        }

        test("property: task IDs of the allowed alphabet always reach the expected path") {
            checkAll(50, Arb.stringPattern("[A-Za-z0-9-]{1,64}")) { id ->
                val h = remHarness()
                h.call(RemediationTools.getTask, "task_id" to id).failed shouldBe false
                h.fake.last.path shouldBe "/api/remediationTasks/$id"
            }
        }
    }

    context("user tools") {
        listOf(UserTools.getUserAlerts to "alerts", UserTools.getUserMachines to "machines").forEach { (tool, suffix) ->
            test("${tool.name}: account names and UPNs map to /api/users/{user}/$suffix") {
                for ((input, path) in listOf(
                    "jdoe" to "jdoe",
                    " jdoe@contoso.com " to "jdoe",
                    "first.last@sub.contoso.com" to "first.last",
                    "svc_backup\$" to Validators.seg("svc_backup\$"),
                    "j.doe-1" to "j.doe-1",
                    "jöhn" to Validators.seg("jöhn"),
                )) {
                    val h = remHarness()
                    h.call(tool, "user" to input).failed shouldBe false
                    h.fake.last.path shouldBe "/api/users/$path/$suffix"
                }
            }

            test("${tool.name}: hostile user values are refused without an API call") {
                for (bad in listOf("jdoe/../x", "a b", "jdoe?x=1", "jdoe#x", "x".repeat(105), "%2e%2e", "jdoe;x", "CONTOSO\\jdoe", "", "jdoe‮", "@contoso.com", "a/b@contoso.com")) {
                    val h = remHarness()
                    val r = h.call(tool, "user" to bad)
                    r.failed shouldBe true
                    r.text() shouldContain "user"
                    h.fake.recorded.shouldBeEmpty()
                }
            }

            test("${tool.name}: dot segments pass the validator but are stopped by path-segment encoding") {
                for (dots in listOf(".", "..")) {
                    val h = remHarness()
                    val r = h.call(tool, "user" to dots)
                    r.failed shouldBe true
                    r.text() shouldContain "Invalid path segment"
                    h.fake.recorded.shouldBeEmpty()
                }
            }
        }

        test("user tools are read-only") {
            UserTools.all.size shouldBe 2
            UserTools.all.forEach { it.readOnly shouldBe true }
        }

        test("property: random text never produces a request outside /api/users/{one segment}/") {
            checkAll(80, Arb.string(0, 40)) { s ->
                val h = remHarness()
                val r = h.call(UserTools.getUserAlerts, "user" to s)
                if (!r.failed) {
                    val path = h.fake.last.path
                    path.removePrefix("/api/users/").removeSuffix("/alerts").contains('/') shouldBe false
                    path.startsWith("/api/users/") shouldBe true
                }
            }
        }
    }

    context("Common.kt helpers") {
        test("stateName trims and accepts letters only") {
            stateName("  Running ", "state") shouldBe "Running"
            stateName("a".repeat(40), "state") shouldBe "a".repeat(40)
            for (bad in listOf("", "Run1", "Run ning", "Run'", "a".repeat(41), "Rünning", "Running​")) {
                shouldThrow<IllegalArgumentException> { stateName(bad, "my_field") }.message shouldContain "my_field must be a single word"
            }
        }

        test("property: stateName accepts exactly the STATE_NAME pattern") {
            val re = Regex(Patterns.STATE_NAME)
            checkAll(200, Arb.string(0, 45)) { s ->
                val ok = runCatching { stateName(s, "f") }.isSuccess
                ok shouldBe re.matches(s.trim())
            }
        }

        test("Patterns mirror the validators") {
            checkAll(100, Arb.stringPattern("[0-9a-fA-Fg]{39,41}")) { s ->
                Regex(Patterns.MACHINE_ID).matches(s) shouldBe runCatching { Validators.machineId(s) }.isSuccess
            }
            checkAll(100, Arb.stringPattern("[0-9a-f]{8}-[0-9a-fz]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{11,12}")) { s ->
                Regex(Patterns.GUID).matches(s) shouldBe runCatching { Validators.guid(s, "g") }.isSuccess
            }
            checkAll(100, Arb.stringPattern("[A-Za-z0-9_.-]{0,130}")) { s ->
                Regex(Patterns.OPAQUE_ID).matches(s) shouldBe runCatching { Validators.opaqueId(s, "o") }.isSuccess
            }
        }

        test("paging adds top, skip, a filter that lists sorted allowed fields, page_token and max_pages") {
            val schema = SchemaBuilder().apply { paging(setOf("zeta", "alpha"), defaultTop = 25) }.build()
            val props = schema.properties!!
            props.keys shouldContainExactly setOf("top", "skip", "filter", "page_token", "max_pages")
            props["page_token"]!!.jsonObject["pattern"]!!.jsonPrimitive.content shouldBe PageCursorStore.TOKEN_PATTERN
            props["page_token"]!!.jsonObject["maxLength"]!!.jsonPrimitive.content shouldBe "32"
            props["page_token"]!!.jsonObject["description"]!!.jsonPrimitive.content shouldContain "no other arguments except max_pages"
            props["max_pages"]!!.jsonObject["minimum"]!!.jsonPrimitive.content shouldBe "1"
            props["max_pages"]!!.jsonObject["maximum"]!!.jsonPrimitive.content shouldBe MAX_PAGES.toString()
            props["max_pages"]!!.jsonObject["default"]!!.jsonPrimitive.content shouldBe "1"
            props["top"]!!.jsonObject["minimum"]!!.jsonPrimitive.content shouldBe "1"
            props["top"]!!.jsonObject["maximum"]!!.jsonPrimitive.content shouldBe MAX_TOP.toString()
            props["top"]!!.jsonObject["default"]!!.jsonPrimitive.content shouldBe "25"
            props["skip"]!!.jsonObject["maximum"]!!.jsonPrimitive.content shouldBe MAX_SKIP.toString()
            props["skip"]!!.jsonObject["default"]!!.jsonPrimitive.content shouldBe "0"
            props["filter"]!!.jsonObject["maxLength"]!!.jsonPrimitive.content shouldBe "2000"
            props["filter"]!!.jsonObject["description"]!!.jsonPrimitive.content shouldContain "Allowed fields: alpha, zeta."
            schema.required.shouldBeNull()
            val defaultTop = SchemaBuilder().apply { paging(setOf("a")) }.build().properties!!["top"]!!.jsonObject["default"]!!
            defaultTop.jsonPrimitive.content shouldBe DEFAULT_TOP.toString()
        }

        test("listQuery: defaults, structured-only, raw-only, both, orderBy and skip options") {
            callFor().listQuery(null, setOf("status")).let { (q, o) ->
                q shouldContainExactly listOf("\$top" to "50")
                o shouldBe ResponseRenderer.Options()
            }
            callFor().listQuery("status eq 'A'", setOf("status"), defaultTop = 7, orderBy = "createdOn desc").first shouldContainExactly listOf(
                "\$top" to "7",
                "\$filter" to "status eq 'A'",
                "\$orderby" to "createdOn desc",
            )
            callFor("filter" to " status eq 'B' ").listQuery(null, setOf("status")).first shouldContainExactly listOf(
                "\$top" to "50",
                "\$filter" to "(status eq 'B')",
            )
            callFor("filter" to "status eq 'B' or status eq 'C'", "top" to 3, "skip" to 9).listQuery("createdOn ge 2026-01-01T00:00:00Z", setOf("status")).let { (q, o) ->
                q shouldContainExactly listOf(
                    "\$top" to "3",
                    "\$skip" to "9",
                    "\$filter" to "createdOn ge 2026-01-01T00:00:00Z and (status eq 'B' or status eq 'C')",
                )
                // Paging is server-side (page_token); the renderer options carry no skip any more.
                o shouldBe ResponseRenderer.Options()
            }
        }

        test("listQuery: a raw filter naming a field outside the allowed set is refused") {
            shouldThrow<IllegalArgumentException> {
                callFor("filter" to "createdOn gt 2026-01-01T00:00:00Z").listQuery(null, setOf("status"))
            }.message shouldContain "not filterable here"
            shouldThrow<IllegalArgumentException> {
                callFor("filter" to "status eq 'x') or (1 eq 1").listQuery(null, setOf("status"))
            }.message shouldContain "parentheses"
        }

        test("getAndRender passes query parameters and render options through") {
            val fake = FakeDefender(api = { Canned(body = """{"value":[{"id":"1"},{"id":"2"},{"id":"3"}]}""") })
            val h = ToolHarness(fake = fake)
            val spec = tool(name = "defender_test_get", description = "t") {
                getAndRender("/api/x", listOf("a" to "b c"), ResponseRenderer.Options(maxRecords = 1, hint = "Use a narrower id."))
            }
            val text = h.call(spec).text()
            fake.last.path shouldBe "/api/x"
            fake.last.request.url.parameters["a"] shouldBe "b c"
            text shouldContain "Showing 1 of 3 records (row cap)"
            text shouldContain "[Showing 1 of 3 records (row cap). Use a narrower id.]"
            text shouldNotContain "skip="
        }

        test("seg delegates to Validators.seg, escaping ';' and refusing dot segments") {
            seg("a;b") shouldBe "a%3Bb"
            seg("a b") shouldBe Validators.seg("a b")
            shouldThrow<IllegalArgumentException> { seg("..") }
            shouldThrow<IllegalArgumentException> { seg(".;x") }
        }

        test("jsonOf maps supported values, drops nulls and refuses anything else") {
            val obj = jsonOf(
                "s" to "text",
                "i" to 3,
                "d" to 1.5,
                "b" to true,
                "n" to null,
                "e" to JsonArray(listOf(JsonPrimitive("x"))),
                "o" to JsonNull,
            )
            obj shouldBe JsonObject(
                mapOf(
                    "s" to JsonPrimitive("text"),
                    "i" to JsonPrimitive(3),
                    "d" to JsonPrimitive(1.5),
                    "b" to JsonPrimitive(true),
                    "e" to JsonArray(listOf(JsonPrimitive("x"))),
                    "o" to JsonNull,
                ),
            )
            jsonOf() shouldBe JsonObject(emptyMap())
            shouldThrow<IllegalArgumentException> { jsonOf("list" to listOf("a")) }.message shouldBe "unsupported JSON value for list"
            shouldThrow<IllegalArgumentException> { jsonOf("obj" to Any()) }.message shouldContain "obj"
        }
    }
})
