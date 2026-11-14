package com.jitunicornfx.defender.mcp.tools

import com.jitunicornfx.defender.mcp.AccessLevel
import com.jitunicornfx.defender.mcp.JsonCodec
import com.jitunicornfx.defender.mcp.ResponseRenderer
import com.jitunicornfx.defender.mcp.ToolCall
import com.jitunicornfx.defender.mcp.ToolSpec
import com.jitunicornfx.defender.mcp.Validators
import com.jitunicornfx.defender.mcp.errorResult
import com.jitunicornfx.defender.mcp.tool
import io.ktor.http.HttpMethod
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull

/**
 * Machine response actions: isolate/unisolate, restrict/unrestrict app execution, antivirus scan,
 * stop-and-quarantine a file, and cancel a pending action.
 *
 * Tiering is deliberately asymmetric. Actions that take a device or user out of service (isolate,
 * restrict, quarantine) are DESTRUCTIVE *containment*: they also draw on a separate, tighter hourly
 * budget, need a substantive comment, refuse devices carrying a protected tag, and show the human the
 * device (and file) as Defender reports it before approval. Their reversals (unisolate, unrestrict),
 * the AV scan and cancel are WRITE, so a recovery path is never locked behind the destructive tier;
 * they still need human approval.
 */
object ResponseTools {
    const val MIN_CONTAINMENT_COMMENT = 10
    val ISOLATION_TYPES = listOf("Full", "Selective", "UnManagedDevice")
    val SCAN_TYPES = listOf("Quick", "Full")

    /** Signer names Microsoft uses for its own binaries (compared trimmed and lowercased). */
    val MICROSOFT_SIGNERS = setOf(
        "microsoft corporation",
        "microsoft windows",
        "microsoft windows publisher",
        "microsoft windows hardware compatibility publisher",
        "microsoft windows production pca 2011",
        "microsoft code signing pca",
        "microsoft code signing pca 2011",
    )

    /** What the server learned about a target before asking for approval, or why it refused to ask at all. */
    internal sealed interface Preview {
        data class Ready(val facts: List<Pair<String, String>>) : Preview
        data class Refused(val result: CallToolResult) : Preview
    }

    private fun JsonObject.text(key: String): String? = (this[key] as? JsonPrimitive)?.contentOrNull?.takeIf { it.isNotBlank() }

    /**
     * Look the device up and turn it into approval facts. For containment ([enforce] = true) the lookup
     * must succeed (no preview, no action) and a device carrying a protected tag is refused outright.
     * For recovery actions a failed lookup only means no facts: undoing containment must stay possible.
     */
    internal suspend fun ToolCall.machinePreview(machineId: String, enforce: Boolean): Preview {
        val response = client.get("/api/machines/${seg(machineId)}")
        val machine = if (response.ok) runCatching { JsonCodec.compact.parseToJsonElement(response.text) as? JsonObject }.getOrNull() else null
        if (machine == null) {
            if (!enforce) return Preview.Ready(listOf("Device" to "(could not be looked up)"))
            if (!response.ok) {
                val shown = render(response)
                return Preview.Refused(
                    errorResult(
                        "Refused: the device could not be looked up before a containment action (HTTP ${response.status}), and this " +
                            "server never contains a device it cannot first show to the approver. Nothing was changed.\n\n" +
                            shown.content.filterIsInstance<io.modelcontextprotocol.kotlin.sdk.types.TextContent>().joinToString("\n") { it.text },
                    ),
                )
            }
            return Preview.Refused(errorResult("Refused: Defender's device record could not be read, so nothing was changed."))
        }
        val tags = (machine["machineTags"] as? JsonArray)?.mapNotNull { (it as? JsonPrimitive)?.contentOrNull } ?: emptyList()
        if (enforce) {
            val hit = tags.firstOrNull { ctx.config.isProtectedTag(it) }
            if (hit != null) {
                // Audited distinctly: tags can also be set on the endpoint itself (registry device tagging), so a
                // device that suddenly cannot be contained is something a SOC must be able to spot.
                ctx.gate.recordRefusal(spec.name, "refused_protected_tag", "Containment refused for protected device $machineId", listOf("Device ID" to machineId))
                return Preview.Refused(
                    errorResult(
                        "Refused: the device carries a protected tag listed in ${com.jitunicornfx.defender.mcp.Config.ENV_PROTECTED_TAGS}, " +
                            "so containment actions on it must be performed by a human in the Defender portal. Nothing was changed.",
                    ),
                )
            }
        }
        return Preview.Ready(
            listOfNotNull(
                machine.text("computerDnsName")?.let { "Device name" to it },
                machine.text("osPlatform")?.let { "OS" to (it + (machine.text("version")?.let { v -> " $v" } ?: "")) },
                machine.text("healthStatus")?.let { "Sensor health" to it },
                machine.text("deviceValue")?.let { "Device value" to it },
                machine.text("rbacGroupName")?.let { "Device group" to it },
                machine.text("lastSeen")?.let { "Last seen" to it },
                tags.takeIf { it.isNotEmpty() }?.let { "Tags" to it.joinToString(", ").take(200) },
            ),
        )
    }

    private fun containmentComment(raw: String): String {
        val comment = Validators.comment(raw)
        require(comment.length >= MIN_CONTAINMENT_COMMENT) {
            "comment must explain the containment in at least $MIN_CONTAINMENT_COMMENT characters (e.g. an alert or ticket reference)."
        }
        return comment
    }

    private fun com.jitunicornfx.defender.mcp.SchemaBuilder.machineAndComment(containment: Boolean) {
        string("machine_id", "Device ID (40 hex characters).", required = true, pattern = Patterns.MACHINE_ID)
        string(
            "comment",
            if (containment) {
                "Why (at least $MIN_CONTAINMENT_COMMENT characters; reference the alert or ticket). Recorded in Defender."
            } else {
                "Why. Recorded in Defender."
            },
            required = true,
            maxLength = Validators.MAX_COMMENT_LENGTH,
        )
    }

    /** POST a machine action and render the resulting MachineAction. */
    private suspend fun ToolCall.post(path: String, body: JsonObject): CallToolResult =
        render(client.request(HttpMethod.Post, path, body = body), ResponseRenderer.Options())

    private const val POLL_HINT = " Returns a machine action; poll it with defender_get_machine_action."

    val isolateMachine: ToolSpec = tool(
        name = "defender_isolate_machine",
        description = "Isolate a device from the network (Full, Selective — Outlook/Teams/Skype stay connected — or " +
            "UnManagedDevice containment). Disruptive: requires the destructive access level, human approval, a substantive " +
            "comment, and counts against the hourly containment budget. Devices with a protected tag are refused. Reverse with " +
            "defender_unisolate_machine.$POLL_HINT",
        access = AccessLevel.DESTRUCTIVE,
        destructive = true,
        params = {
            machineAndComment(containment = true)
            string("isolation_type", "Full, Selective or UnManagedDevice. Always explicit.", required = true, enum = ISOLATION_TYPES)
        },
    ) {
        val id = Validators.machineId(args.string("machine_id"))
        val comment = containmentComment(args.string("comment"))
        val type = args.enum("isolation_type", ISOLATION_TYPES)
        val preview = machinePreview(id, enforce = true)
        if (preview is Preview.Refused) return@tool preview.result
        authorize(
            "ISOLATE device $id from the network ($type isolation)",
            listOf("Device ID" to id, "Isolation type" to type, "Comment" to comment),
            facts = (preview as Preview.Ready).facts,
            containment = true,
        )?.let { return@tool it }
        post("/api/machines/${seg(id)}/isolate", jsonOf("Comment" to comment, "IsolationType" to type))
    }

    val unisolateMachine: ToolSpec = tool(
        name = "defender_unisolate_machine",
        description = "Release a device from network isolation. Requires the write access level and human approval.$POLL_HINT",
        access = AccessLevel.WRITE,
        params = { machineAndComment(containment = false) },
    ) {
        val id = Validators.machineId(args.string("machine_id"))
        val comment = Validators.comment(args.string("comment"))
        val facts = (machinePreview(id, enforce = false) as Preview.Ready).facts
        authorize("Release device $id from isolation", listOf("Device ID" to id, "Comment" to comment), facts = facts)
            ?.let { return@tool it }
        post("/api/machines/${seg(id)}/unisolate", jsonOf("Comment" to comment))
    }

    val restrictAppExecution: ToolSpec = tool(
        name = "defender_restrict_app_execution",
        description = "Restrict app execution on a device so only Microsoft-signed binaries can run (Windows 10 1709+, " +
            "Defender Antivirus required). Severely disruptive: destructive access level, human approval, substantive comment, " +
            "containment budget; protected devices are refused. Reverse with defender_unrestrict_app_execution.$POLL_HINT",
        access = AccessLevel.DESTRUCTIVE,
        destructive = true,
        params = { machineAndComment(containment = true) },
    ) {
        val id = Validators.machineId(args.string("machine_id"))
        val comment = containmentComment(args.string("comment"))
        val preview = machinePreview(id, enforce = true)
        if (preview is Preview.Refused) return@tool preview.result
        authorize(
            "RESTRICT app execution on device $id (only Microsoft-signed binaries will run)",
            listOf("Device ID" to id, "Comment" to comment),
            facts = (preview as Preview.Ready).facts,
            containment = true,
        )?.let { return@tool it }
        post("/api/machines/${seg(id)}/restrictCodeExecution", jsonOf("Comment" to comment))
    }

    val unrestrictAppExecution: ToolSpec = tool(
        name = "defender_unrestrict_app_execution",
        description = "Remove the app-execution restriction from a device. Requires the write access level and human approval.$POLL_HINT",
        access = AccessLevel.WRITE,
        params = { machineAndComment(containment = false) },
    ) {
        val id = Validators.machineId(args.string("machine_id"))
        val comment = Validators.comment(args.string("comment"))
        val facts = (machinePreview(id, enforce = false) as Preview.Ready).facts
        authorize("Remove the app-execution restriction from device $id", listOf("Device ID" to id, "Comment" to comment), facts = facts)
            ?.let { return@tool it }
        post("/api/machines/${seg(id)}/unrestrictCodeExecution", jsonOf("Comment" to comment))
    }

    val runAntivirusScan: ToolSpec = tool(
        name = "defender_run_av_scan",
        description = "Run a Microsoft Defender Antivirus scan (Quick or Full) on a device. A Full scan is heavy, and the scan may " +
            "remediate according to antivirus policy. Requires the write access level and human approval.$POLL_HINT",
        access = AccessLevel.WRITE,
        params = {
            machineAndComment(containment = false)
            string("scan_type", "Quick or Full. Always explicit.", required = true, enum = SCAN_TYPES)
        },
    ) {
        val id = Validators.machineId(args.string("machine_id"))
        val comment = Validators.comment(args.string("comment"))
        val type = args.enum("scan_type", SCAN_TYPES)
        val facts = (machinePreview(id, enforce = false) as Preview.Ready).facts
        authorize("Run a $type antivirus scan on device $id", listOf("Device ID" to id, "Scan type" to type, "Comment" to comment), facts = facts)
            ?.let { return@tool it }
        post("/api/machines/${seg(id)}/runAntiVirusScan", jsonOf("Comment" to comment, "ScanType" to type))
    }

    /**
     * File facts for the quarantine approval. A Microsoft-signed file with a valid certificate is refused
     * early (the API refuses it too). An unknown file is shown as such; any other lookup failure refuses.
     */
    internal suspend fun ToolCall.filePreview(sha1: String): Preview {
        val response = client.get("/api/files/${seg(sha1)}")
        if (response.status == 404) return Preview.Ready(listOf("File" to "not in Defender's file catalogue"))
        val parsed = if (response.ok) runCatching { JsonCodec.compact.parseToJsonElement(response.text) as? JsonObject }.getOrNull() else null
        val file = parsed
            ?: return Preview.Refused(
                errorResult(
                    "Refused: the file could not be looked up before quarantine (HTTP ${response.status}), and this server never " +
                        "quarantines a file it cannot first show to the approver. Nothing was changed.",
                ),
            )
        val signer = file.text("signer")
        val validCert = (file["isValidCertificate"] as? JsonPrimitive)?.contentOrNull.equals("true", ignoreCase = true)
        // Exact Microsoft signer names only: a substring match would let malware signed by "Microsoftware Ltd"
        // (a valid, non-Microsoft certificate) escape quarantine.
        if (validCert && signer != null && signer.trim().lowercase() in MICROSOFT_SIGNERS) {
            return Preview.Refused(
                errorResult(
                    "Refused: the file has a valid Microsoft signature, and Defender does not quarantine Microsoft-signed files. " +
                        "Nothing was changed. If it is being abused, investigate the process that runs it instead.",
                ),
            )
        }
        return Preview.Ready(
            listOfNotNull(
                file.text("fileProductName")?.let { "Product" to it },
                file.text("filePublisher")?.let { "Publisher" to it },
                signer?.let { "Signer" to (it + if (validCert) " (valid certificate)" else " (certificate not valid)") },
                file.text("globalPrevalence")?.let { "Global prevalence" to it },
                file.text("determinationType")?.let { "Determination" to (it + (file.text("determinationValue")?.let { v -> ": $v" } ?: "")) },
            ),
        )
    }

    val stopAndQuarantineFile: ToolSpec = tool(
        name = "defender_stop_and_quarantine_file",
        description = "Stop a file's running processes and quarantine (remove) it on one device, by SHA-1. There is no API to " +
            "restore it, and Microsoft-signed files are refused. Destructive access level, human approval, substantive comment, " +
            "containment budget; protected devices are refused. For fleet-wide blocking prefer a custom indicator.$POLL_HINT",
        access = AccessLevel.DESTRUCTIVE,
        destructive = true,
        params = {
            machineAndComment(containment = true)
            string("sha1", "SHA-1 of the file (40 hex characters).", required = true, pattern = "^[0-9a-fA-F]{40}$")
        },
    ) {
        val id = Validators.machineId(args.string("machine_id"))
        val sha1 = Validators.sha1(args.string("sha1"))
        val comment = containmentComment(args.string("comment"))
        val device = machinePreview(id, enforce = true)
        if (device is Preview.Refused) return@tool device.result
        val file = filePreview(sha1)
        if (file is Preview.Refused) return@tool file.result
        authorize(
            "STOP and QUARANTINE file $sha1 on device $id (not reversible through the API)",
            listOf("Device ID" to id, "SHA-1" to sha1, "Comment" to comment),
            facts = (device as Preview.Ready).facts + (file as Preview.Ready).facts,
            containment = true,
        )?.let { return@tool it }
        post("/api/machines/${seg(id)}/StopAndQuarantineFile", jsonOf("Comment" to comment, "Sha1" to sha1))
    }

    val cancelMachineAction: ToolSpec = tool(
        name = "defender_cancel_machine_action",
        description = "Cancel a machine action that has not finished yet (e.g. a pending isolation or quarantine). It cannot undo " +
            "an action that already completed. Requires the write access level and human approval. (Preview API.)",
        access = AccessLevel.WRITE,
        params = {
            string("action_id", "Machine action ID (GUID).", required = true, pattern = Patterns.GUID)
            string("comment", "Why the action is being cancelled.", required = true, maxLength = Validators.MAX_COMMENT_LENGTH)
        },
    ) {
        val actionId = Validators.guid(args.string("action_id"), "action_id")
        val comment = Validators.comment(args.string("comment"))
        val lookup = client.get("/api/machineactions/${seg(actionId)}")
        val action = if (lookup.ok) runCatching { JsonCodec.compact.parseToJsonElement(lookup.text) as? JsonObject }.getOrNull() else null
        val facts = action?.let {
            listOfNotNull(
                it.text("type")?.let { t -> "Action type" to t },
                it.text("status")?.let { s -> "Status" to s },
                it.text("computerDnsName")?.let { n -> "Device name" to n },
                it.text("requestor")?.let { r -> "Requested by" to r },
            )
        } ?: listOf("Action" to "(could not be looked up)")
        authorize("Cancel machine action $actionId", listOf("Action ID" to actionId, "Comment" to comment), facts = facts)
            ?.let { return@tool it }
        post("/api/machineactions/${seg(actionId)}/cancel", jsonOf("Comment" to comment))
    }

    val all: List<ToolSpec> = listOf(
        isolateMachine, unisolateMachine, restrictAppExecution, unrestrictAppExecution,
        runAntivirusScan, stopAndQuarantineFile, cancelMachineAction,
    )
}
