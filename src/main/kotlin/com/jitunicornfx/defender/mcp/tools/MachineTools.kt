package com.jitunicornfx.defender.mcp.tools

import com.jitunicornfx.defender.mcp.AccessLevel
import com.jitunicornfx.defender.mcp.OData
import com.jitunicornfx.defender.mcp.ToolSpec
import com.jitunicornfx.defender.mcp.Validators
import com.jitunicornfx.defender.mcp.tool
import io.ktor.http.HttpMethod
import com.jitunicornfx.defender.mcp.ToolCall
import com.jitunicornfx.defender.mcp.errorResult
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.JsonPrimitive
import java.time.Duration
import java.time.format.DateTimeFormatter

/** Machine (device) methods and properties, plus the machine-action reads needed to follow up on them. */
object MachineTools {
    val MACHINE_FILTER_FIELDS = setOf(
        "computerDnsName", "id", "version", "deviceValue", "aadDeviceId", "machineTags", "lastSeen",
        "exposureLevel", "onboardingStatus", "lastIpAddress", "healthStatus", "osPlatform", "riskScore", "rbacGroupId",
    )
    val ACTION_FILTER_FIELDS = setOf("id", "status", "machineId", "type", "requestor", "creationDateTimeUtc")
    val DEVICE_VALUES = listOf("Normal", "Low", "High")
    val TAG_ACTIONS = listOf("Add", "Remove")
    val HEALTH = listOf("Active", "Inactive", "ImpairedCommunication", "NoSensorData", "NoSensorDataImpairedCommunication", "Unknown")
    val RISK = listOf("None", "Informational", "Low", "Medium", "High")
    val EXPOSURE = listOf("None", "Low", "Medium", "High")

    private fun machineParam(builder: com.jitunicornfx.defender.mcp.SchemaBuilder, description: String = "Device ID (40 hex characters).") =
        builder.string("machine_id", description, required = true, pattern = Patterns.MACHINE_ID)

    /** A read of `/api/machines/{id}/<suffix>`. */
    private fun machineSubresource(name: String, suffix: String, description: String): ToolSpec = tool(
        name = name,
        description = description,
        params = {
            machineParam(this)
            cursorParams()
        },
    ) {
        val id = Validators.machineId(args.string("machine_id"))
        pagedList("/api/machines/${seg(id)}/$suffix")
    }

    val listMachines: ToolSpec = tool(
        name = "defender_list_machines",
        description = "List devices known to Defender (seen within the retention period). Filter by name prefix, " +
            "health, risk, exposure, OS platform, tag or last-seen time.",
        params = {
            string("name_prefix", "Only devices whose computerDnsName starts with this text.", maxLength = 253)
            string("health_status", "Sensor health.", enum = HEALTH)
            string("risk_score", "Defender risk score.", enum = RISK)
            string("exposure_level", "Vulnerability exposure level.", enum = EXPOSURE)
            string("os_platform", "OS platform, e.g. Windows11, Windows10, WindowsServer2022, Linux, macOS.", pattern = "^[A-Za-z0-9]{1,40}$")
            string("tag", "Only devices carrying this machine tag.", maxLength = Validators.MAX_TAG_LENGTH)
            string("seen_after", "Only devices last seen at or after this ISO-8601 time.", format = "date-time")
            paging(MACHINE_FILTER_FIELDS)
        },
    ) {
        val structured = OData.and(
            args.optString("name_prefix")?.let {
                val prefix = it.trim().lowercase()
                require(prefix.matches(Regex("^[a-z0-9.-]{1,253}$"))) { "name_prefix may contain only letters, digits, '.' and '-'." }
                "startswith(computerDnsName,${OData.quote(prefix)})"
            },
            args.optEnum("health_status", HEALTH)?.let { "healthStatus eq ${OData.quote(it)}" },
            args.optEnum("risk_score", RISK)?.let { "riskScore eq ${OData.quote(it)}" },
            args.optEnum("exposure_level", EXPOSURE)?.let { "exposureLevel eq ${OData.quote(it)}" },
            args.optString("os_platform")?.let {
                require(it.trim().matches(Regex("^[A-Za-z0-9]{1,40}$"))) { "os_platform must be letters and digits only." }
                "osPlatform eq ${OData.quote(it.trim())}"
            },
            args.optString("tag")?.let { "machineTags/any(t: t eq ${OData.quote(Validators.tag(it))})" },
            args.optString("seen_after")?.let { "lastSeen ge ${OData.datetime(Validators.timestamp(it, "seen_after"))}" },
        )
        val (query, _) = listQuery(structured, MACHINE_FILTER_FIELDS)
        pagedList("/api/machines", query)
    }

    val getMachine: ToolSpec = tool(
        name = "defender_get_machine",
        description = "Get one device by its 40-hex device ID or its computer DNS name.",
        params = { string("machine", "Device ID or computer DNS name.", required = true, maxLength = 253) },
    ) {
        val id = Validators.machineIdOrName(args.string("machine"))
        getAndRender("/api/machines/${seg(id)}")
    }

    val getLogonUsers = machineSubresource(
        "defender_get_machine_logon_users", "logonusers",
        "List the user accounts that have logged on to a device.",
    )
    val getMachineAlerts = machineSubresource(
        "defender_get_machine_alerts", "alerts",
        "List the alerts related to a device.",
    )
    val getSoftware = machineSubresource(
        "defender_get_machine_software", "software",
        "List the software inventory of a device (Defender Vulnerability Management).",
    )
    val getVulnerabilities = machineSubresource(
        "defender_get_machine_vulnerabilities", "vulnerabilities",
        "List the vulnerabilities (CVEs) discovered on a device.",
    )
    val getRecommendations = machineSubresource(
        "defender_get_machine_recommendations", "recommendations",
        "List the security recommendations for a device.",
    )
    val getMissingKbs = machineSubresource(
        "defender_get_machine_missing_kbs", "getmissingkbs",
        "List the security updates (KBs) missing on a device.",
    )

    val findByIp: ToolSpec = tool(
        name = "defender_find_machines_by_ip",
        description = "Find devices that reported a given internal IP address within 15 minutes of a timestamp " +
            "(timestamp must be within the last 30 days).",
        params = {
            string("ip", "IPv4 or IPv6 address.", required = true, maxLength = 45)
            string("timestamp", "ISO-8601 time to search around, e.g. 2026-01-31T13:45:00Z.", required = true, format = "date-time")
        },
    ) {
        val ip = Validators.ipAddress(args.string("ip"))
        val ts = Validators.recentTimestamp(args.string("timestamp"), "timestamp", Duration.ofDays(30))
        // OData function-call syntax; both values are validated, and the IP literal cannot contain a quote.
        getAndRender("/api/machines/findbyip(ip='$ip',timestamp=${DateTimeFormatter.ISO_INSTANT.format(ts)})")
    }

    val findByTag: ToolSpec = tool(
        name = "defender_find_machines_by_tag",
        description = "Find devices carrying a machine tag (exact match, or prefix match with starts_with=true).",
        params = {
            string("tag", "The tag to look for.", required = true, maxLength = Validators.MAX_TAG_LENGTH)
            boolean("starts_with", "Match tags that start with the text instead of exact match.", default = false)
        },
    ) {
        val tag = Validators.tag(args.string("tag"))
        val startsWith = args.boolean("starts_with", false)
        getAndRender("/api/machines/findbytag", listOf("tag" to tag, "useStartsWithFilter" to startsWith.toString()))
    }

    val tagMachine: ToolSpec = tool(
        name = "defender_tag_machine",
        description = "Add or remove one machine tag on a device. Requires the write access level and human approval.",
        access = AccessLevel.WRITE,
        destructive = true,
        idempotent = true,
        params = {
            machineParam(this)
            string("tag", "Tag text.", required = true, maxLength = Validators.MAX_TAG_LENGTH)
            string("action", "Add or Remove.", required = true, enum = TAG_ACTIONS)
        },
    ) {
        val id = Validators.machineId(args.string("machine_id"))
        val tag = Validators.tag(args.string("tag"))
        val action = args.enum("action", TAG_ACTIONS)
        refuseProtectedTagRemoval(action, tag)?.let { return@tool it }
        authorize("$action tag on device $id", listOf("Device ID" to id, "Tag" to tag))?.let { return@tool it }
        render(client.request(HttpMethod.Post, "/api/machines/${seg(id)}/tags", body = jsonOf("Value" to tag, "Action" to action)))
    }

    val tagMachinesBulk: ToolSpec = tool(
        name = "defender_tag_machines_bulk",
        description = "Add or remove one machine tag on up to 500 devices in a single call. Because of its reach this " +
            "requires the destructive access level and human approval.",
        access = AccessLevel.DESTRUCTIVE,
        destructive = true,
        idempotent = true,
        params = {
            stringArray("machine_ids", "Device IDs (40 hex characters each), at most 500.", Validators.MAX_BULK_MACHINES, required = true, itemPattern = Patterns.MACHINE_ID)
            string("tag", "Tag text.", required = true, maxLength = Validators.MAX_TAG_LENGTH)
            string("action", "Add or Remove.", required = true, enum = TAG_ACTIONS)
        },
    ) {
        val ids = (args.optStringList("machine_ids", Validators.MAX_BULK_MACHINES) ?: emptyList())
            .map { Validators.machineId(it, "machine_ids") }.distinct()
        require(ids.isNotEmpty()) { "machine_ids must list at least one device." }
        val tag = Validators.tag(args.string("tag"))
        val action = args.enum("action", TAG_ACTIONS)
        refuseProtectedTagRemoval(action, tag)?.let { return@tool it }
        authorize(
            "$action tag on ${ids.size} device(s)",
            listOf("Tag" to tag, "Devices" to ids.take(5).joinToString(", ") + if (ids.size > 5) " (+${ids.size - 5} more)" else ""),
        )?.let { return@tool it }
        render(
            client.request(
                HttpMethod.Post,
                "/api/machines/AddOrRemoveTagForMultipleMachines",
                body = jsonOf("Value" to tag, "Action" to action, "MachineIds" to JsonArray(ids.map { JsonPrimitive(it) })),
            ),
        )
    }

    val setDeviceValue: ToolSpec = tool(
        name = "defender_set_device_value",
        description = "Set a device's asset value (Normal, Low or High), which weights its exposure score. " +
            "Requires the write access level and human approval.",
        access = AccessLevel.WRITE,
        destructive = true,
        idempotent = true,
        params = {
            machineParam(this)
            string("device_value", "New device value.", required = true, enum = DEVICE_VALUES)
        },
    ) {
        val id = Validators.machineId(args.string("machine_id"))
        val value = args.enum("device_value", DEVICE_VALUES)
        authorize("Set device value of $id to $value", listOf("Device ID" to id, "Device value" to value))?.let { return@tool it }
        render(client.request(HttpMethod.Post, "/api/machines/${seg(id)}/setDeviceValue", body = jsonOf("DeviceValue" to value)))
    }

    val updateMachine: ToolSpec = tool(
        name = "defender_update_machine",
        description = "Update a device's tags and/or device value. machine_tags REPLACES the device's whole tag set " +
            "(include existing tags you want to keep), so this requires the destructive access level and human approval.",
        access = AccessLevel.DESTRUCTIVE,
        destructive = true,
        idempotent = true,
        params = {
            machineParam(this)
            stringArray("machine_tags", "The complete new tag set.", 100)
            string("device_value", "New device value.", enum = DEVICE_VALUES)
        },
    ) {
        val id = Validators.machineId(args.string("machine_id"))
        val tags = args.optStringList("machine_tags", 100)?.map { Validators.tag(it, "machine_tags") }?.distinct()
        val value = args.optEnum("device_value", DEVICE_VALUES)
        require(tags != null || value != null) { "Provide machine_tags and/or device_value." }
        if (tags != null && ctx.config.normalizedProtectedTags.isNotEmpty()) {
            // machine_tags REPLACES the tag set: refuse a set that would drop a protected tag the device carries.
            val current = currentTags(id) ?: return@tool errorResult(
                "Refused: protected tags are configured and the device's current tags could not be read, so replacing its tag " +
                    "set might remove one. Nothing was changed.",
            )
            val dropped = current.filter { ctx.config.isProtectedTag(it) && tags.none { t -> t.trim().equals(it.trim(), ignoreCase = true) } }
            if (dropped.isNotEmpty()) return@tool protectedTagRefusal()
        }
        authorize(
            "Update device $id" + (tags?.let { " (replace all tags with ${it.size} tag(s))" } ?: "") + (value?.let { " (device value $it)" } ?: ""),
            buildList {
                add("Device ID" to id)
                tags?.let { add("New tag set" to it.joinToString(", ").ifEmpty { "(no tags)" }) }
                value?.let { add("Device value" to it) }
            },
        )?.let { return@tool it }
        render(
            client.request(
                HttpMethod.Patch,
                "/api/machines/${seg(id)}",
                body = jsonOf("machineTags" to tags?.let { t -> JsonArray(t.map { JsonPrimitive(it) }) }, "deviceValue" to value),
            ),
        )
    }

    val listMachineActions: ToolSpec = tool(
        name = "defender_list_machine_actions",
        description = "List machine actions (investigation package collections, isolations, scans, ...) and their status.",
        params = {
            string("machine_id", "Only actions on this device.", pattern = Patterns.MACHINE_ID)
            string("status", "Action status, e.g. Pending, InProgress, Succeeded, Failed, Cancelled.", pattern = Patterns.STATE_NAME)
            string(
                "type",
                "Action type: Isolate, Unisolate, RestrictCodeExecution, UnrestrictCodeExecution, RunAntiVirusScan, " +
                    "StopAndQuarantineFile, CollectInvestigationPackage, Offboard, LiveResponse.",
                pattern = Patterns.STATE_NAME,
            )
            paging(ACTION_FILTER_FIELDS)
        },
    ) {
        val structured = OData.and(
            args.optString("machine_id")?.let { "machineId eq ${OData.quote(Validators.machineId(it))}" },
            args.optString("status")?.let { "status eq ${OData.quote(stateName(it, "status"))}" },
            args.optString("type")?.let { "type eq ${OData.quote(stateName(it, "type"))}" },
        )
        val (query, _) = listQuery(structured, ACTION_FILTER_FIELDS)
        pagedList("/api/machineactions", query)
    }

    val getMachineAction: ToolSpec = tool(
        name = "defender_get_machine_action",
        description = "Get one machine action by ID, e.g. to check whether an investigation package is ready.",
        params = { string("action_id", "Machine action ID (GUID).", required = true, pattern = Patterns.GUID) },
    ) {
        val id = Validators.guid(args.string("action_id"), "action_id")
        getAndRender("/api/machineactions/${seg(id)}")
    }

    /**
     * Protected tags (DEFENDER_PROTECTED_TAGS) shield devices from containment, so removing one would silently
     * re-enable it. This server never removes them; a human does that in the Defender portal.
     */
    private fun ToolCall.refuseProtectedTagRemoval(action: String, tag: String): CallToolResult? =
        if (action == "Remove" && ctx.config.isProtectedTag(tag)) protectedTagRefusal() else null

    private fun ToolCall.protectedTagRefusal(): CallToolResult {
        ctx.gate.recordRefusal(spec.name, "refused_protected_tag_removal", "Removal of a protected tag refused", emptyList())
        return errorResult(
            "Refused: that tag is listed in ${com.jitunicornfx.defender.mcp.Config.ENV_PROTECTED_TAGS} and protects devices from " +
                "containment actions. This server never removes protected tags; a human can do so in the Defender portal. Nothing was changed.",
        )
    }

    /** The device's current machine tags, or null when they cannot be read. */
    private suspend fun ToolCall.currentTags(id: String): List<String>? {
        val response = client.get("/api/machines/${seg(id)}")
        if (!response.ok) return null
        val machine = runCatching { com.jitunicornfx.defender.mcp.JsonCodec.compact.parseToJsonElement(response.text) as? JsonObject }.getOrNull()
            ?: return null
        return (machine["machineTags"] as? JsonArray)?.mapNotNull { (it as? JsonPrimitive)?.contentOrNull } ?: emptyList()
    }

    val all: List<ToolSpec> = listOf(
        listMachines, getMachine, getLogonUsers, getMachineAlerts, getSoftware, getVulnerabilities,
        getRecommendations, getMissingKbs, findByIp, findByTag, tagMachine, tagMachinesBulk, setDeviceValue,
        updateMachine, listMachineActions, getMachineAction,
    )
}
