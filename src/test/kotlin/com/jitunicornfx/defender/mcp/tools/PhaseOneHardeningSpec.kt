package com.jitunicornfx.defender.mcp.tools

import com.jitunicornfx.defender.mcp.AccessLevel
import com.jitunicornfx.defender.mcp.Config
import com.jitunicornfx.defender.mcp.ConfirmationMode
import com.jitunicornfx.defender.mcp.JsonCodec
import com.jitunicornfx.defender.mcp.testutil.Canned
import com.jitunicornfx.defender.mcp.testutil.FakeDefender
import com.jitunicornfx.defender.mcp.testutil.MACHINE_ID
import com.jitunicornfx.defender.mcp.testutil.ToolHarness
import com.jitunicornfx.defender.mcp.testutil.failed
import com.jitunicornfx.defender.mcp.testutil.testConfig
import com.jitunicornfx.defender.mcp.testutil.text
import io.kotest.core.spec.style.FunSpec
import io.kotest.datatest.withData
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.ktor.client.request.HttpRequestData
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/** Regression tests for the confirmed phase-1 review findings. */
class PhaseOneHardeningSpec : FunSpec({
    val sha1 = "a".repeat(40)

    fun machine(tags: String = """["Tier0","prod"]""") = Canned(body = """{"id":"$MACHINE_ID","computerDnsName":"dc01","machineTags":$tags}""")

    fun harness(
        protected: Set<String> = setOf("tier0"),
        access: AccessLevel = AccessLevel.DESTRUCTIVE,
        api: (HttpRequestData) -> Canned,
    ): ToolHarness {
        val config = testConfig(access = access, confirmation = ConfirmationMode.NONE).copy(protectedTags = protected)
        return ToolHarness(config = config, fake = FakeDefender(api = api))
    }

    fun ToolHarness.writes() = fake.apiRequests.filter { it.request.method != HttpMethod.Get }

    context("protected tags cannot be removed through this server") {
        withData("Tier0", " tier0 ", "TIER0") { tag ->
            val h = harness { machine() }
            val r = h.call(MachineTools.tagMachine, "machine_id" to MACHINE_ID, "tag" to tag, "action" to "Remove")
            r.failed shouldBe true
            r.text() shouldContain Config.ENV_PROTECTED_TAGS
            h.writes().shouldBeEmpty()
            h.audit.lines.any { "refused_protected_tag_removal" in it } shouldBe true
        }

        test("adding a protected tag, or removing an unprotected one, is still allowed") {
            val h = harness { Canned(body = "{}") }
            h.call(MachineTools.tagMachine, "machine_id" to MACHINE_ID, "tag" to "Tier0", "action" to "Add").failed shouldBe false
            h.call(MachineTools.tagMachine, "machine_id" to MACHINE_ID, "tag" to "prod", "action" to "Remove").failed shouldBe false
        }

        test("bulk removal of a protected tag is refused before any request") {
            val h = harness { Canned(body = "{}") }
            val r = h.call(MachineTools.tagMachinesBulk, "machine_ids" to listOf(MACHINE_ID), "tag" to "tier0", "action" to "Remove")
            r.failed shouldBe true
            h.fake.apiRequests.shouldBeEmpty()
        }

        test("update_machine refuses a replacement tag set that drops a protected tag the device carries") {
            val h = harness { machine() }
            val r = h.call(MachineTools.updateMachine, "machine_id" to MACHINE_ID, "machine_tags" to listOf("prod"))
            r.failed shouldBe true
            h.writes().shouldBeEmpty()
        }

        test("update_machine keeping the protected tag (any case) goes through") {
            val h = harness { req -> if (req.method == HttpMethod.Get) machine() else Canned(body = "{}") }
            h.call(MachineTools.updateMachine, "machine_id" to MACHINE_ID, "machine_tags" to listOf("TIER0", "new")).failed shouldBe false
            h.writes().single().request.method shouldBe HttpMethod.Patch
        }

        test("update_machine fails closed when the current tags cannot be read") {
            val h = harness { Canned(status = HttpStatusCode.NotFound, body = "{}") }
            val r = h.call(MachineTools.updateMachine, "machine_id" to MACHINE_ID, "machine_tags" to listOf("prod"))
            r.failed shouldBe true
            r.text() shouldContain "could not be read"
            h.writes().shouldBeEmpty()
        }

        test("without protected tags configured, update_machine does not look the device up") {
            val h = harness(protected = emptySet()) { Canned(body = "{}") }
            h.call(MachineTools.updateMachine, "machine_id" to MACHINE_ID, "machine_tags" to listOf("prod")).failed shouldBe false
            h.fake.apiRequests.map { it.request.method } shouldBe listOf(HttpMethod.Patch)
        }
    }

    context("protected-tag matching is normalized on both sides") {
        test("a Config built with mixed-case, padded tags still protects") {
            val h = harness(protected = setOf(" Tier0 ")) { machine("""["tier0"]""") }
            val r = h.call(ResponseTools.isolateMachine, "machine_id" to MACHINE_ID, "comment" to "Alert 1234: confirmed C2", "isolation_type" to "Full")
            r.failed shouldBe true
            h.writes().shouldBeEmpty()
            h.audit.lines.any { "refused_protected_tag" in it && MACHINE_ID in it } shouldBe true
        }
    }

    context("Microsoft-signer check uses exact signer names") {
        fun file(signer: String, valid: String = "true") =
            Canned(body = """{"sha1":"$sha1","signer":"$signer","isValidCertificate":$valid}""")

        fun quarantine(fileResponse: Canned): ToolHarness {
            val h = harness(protected = emptySet()) { req ->
                when {
                    req.url.encodedPath.startsWith("/api/files/") -> fileResponse
                    req.method == HttpMethod.Get -> machine("[]")
                    else -> Canned(body = """{"id":"x"}""")
                }
            }
            return h
        }

        withData("Microsoftware Solutions Ltd", "Not Microsoft LLC", "Microsoft-ish Tools Inc") { lookalike ->
            val h = quarantine(file(lookalike))
            val r = h.call(ResponseTools.stopAndQuarantineFile, "machine_id" to MACHINE_ID, "sha1" to sha1, "comment" to "Alert 1234: malicious binary")
            r.failed shouldBe false
            h.writes().single().path shouldBe "/api/machines/$MACHINE_ID/StopAndQuarantineFile"
        }

        withData("Microsoft Corporation", "  microsoft windows  ", "MICROSOFT WINDOWS PUBLISHER") { genuine ->
            val h = quarantine(file(genuine))
            val r = h.call(ResponseTools.stopAndQuarantineFile, "machine_id" to MACHINE_ID, "sha1" to sha1, "comment" to "Alert 1234: malicious binary")
            r.failed shouldBe true
            h.writes().shouldBeEmpty()
        }

        test("the certificate flag is read case-insensitively when sent as a string") {
            val h = quarantine(file("Microsoft Corporation", valid = "\"True\""))
            h.call(ResponseTools.stopAndQuarantineFile, "machine_id" to MACHINE_ID, "sha1" to sha1, "comment" to "Alert 1234: malicious binary")
                .failed shouldBe true
        }
    }

    context("audit records what the approver was shown") {
        test("an approved containment audits the Defender facts and the containment flag") {
            val h = harness(protected = emptySet()) { req -> if (req.method == HttpMethod.Get) machine("[]") else Canned(body = """{"id":"x"}""") }
            h.call(ResponseTools.isolateMachine, "machine_id" to MACHINE_ID, "comment" to "Alert 1234: confirmed C2", "isolation_type" to "Selective")
                .failed shouldBe false
            val line = h.audit.lines.single { "approved_unattended" in it }
            val json = JsonCodec.compact.parseToJsonElement(line.substringAfter("AUDIT ")).jsonObject
            json["containment"]!!.jsonPrimitive.content shouldBe "true"
            json["facts"]!!.jsonObject["Device name"]!!.jsonPrimitive.content shouldBe "dc01"
        }

        test("a non-containment action records no containment flag") {
            val h = harness(protected = emptySet(), access = AccessLevel.WRITE) { req ->
                if (req.method == HttpMethod.Get) machine("[]") else Canned(body = """{"id":"x"}""")
            }
            h.call(ResponseTools.unisolateMachine, "machine_id" to MACHINE_ID, "comment" to "false positive").failed shouldBe false
            val json = JsonCodec.compact.parseToJsonElement(h.audit.lines.single().substringAfter("AUDIT ")).jsonObject
            json.containsKey("containment") shouldBe false
        }
    }
})
