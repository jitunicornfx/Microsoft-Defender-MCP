package com.jitunicornfx.defender.mcp.tools

import com.jitunicornfx.defender.mcp.AccessLevel
import com.jitunicornfx.defender.mcp.OData
import com.jitunicornfx.defender.mcp.RateBucket
import com.jitunicornfx.defender.mcp.ToolSpec
import com.jitunicornfx.defender.mcp.Validators
import com.jitunicornfx.defender.mcp.tool
import io.ktor.http.HttpMethod

/** Automated investigation and response (AIR): investigations and investigation packages. */
object InvestigationTools {
    val FILTER_FIELDS = setOf("startTime", "id", "state", "machineId", "triggeringAlertId")

    val listInvestigations: ToolSpec = tool(
        name = "defender_list_investigations",
        description = "List automated investigations, newest first by default filter order of the API. " +
            "Filter by state, machine, triggering alert or start time.",
        params = {
            string("state", "Investigation state, e.g. Running, PendingApproval, SuccessfullyRemediated, Benign, Failed.", pattern = Patterns.STATE_NAME)
            string("machine_id", "Only investigations on this device (40-hex device ID).", pattern = Patterns.MACHINE_ID)
            string("triggering_alert_id", "Only the investigation triggered by this alert ID.", pattern = Patterns.OPAQUE_ID)
            string("started_after", "Only investigations started at or after this ISO-8601 time.", format = "date-time")
            string("started_before", "Only investigations started before this ISO-8601 time.", format = "date-time")
            paging(FILTER_FIELDS)
        },
    ) {
        val structured = OData.and(
            args.optString("state")?.let { "state eq ${OData.quote(stateName(it, "state"))}" },
            args.optString("machine_id")?.let { "machineId eq ${OData.quote(Validators.machineId(it))}" },
            args.optString("triggering_alert_id")?.let { "triggeringAlertId eq ${OData.quote(Validators.opaqueId(it, "triggering_alert_id"))}" },
            args.optString("started_after")?.let { "startTime ge ${OData.datetime(Validators.timestamp(it, "started_after"))}" },
            args.optString("started_before")?.let { "startTime lt ${OData.datetime(Validators.timestamp(it, "started_before"))}" },
        )
        val (query, _) = listQuery(structured, FILTER_FIELDS)
        pagedList("/api/investigations", query)
    }

    val getInvestigation: ToolSpec = tool(
        name = "defender_get_investigation",
        description = "Get one automated investigation by its ID, or by the ID of the alert that triggered it.",
        params = { string("investigation_id", "Investigation ID or triggering alert ID.", required = true, pattern = Patterns.OPAQUE_ID) },
    ) {
        val id = Validators.opaqueId(args.string("investigation_id"), "investigation_id")
        getAndRender("/api/investigations/${seg(id)}")
    }

    val startInvestigation: ToolSpec = tool(
        name = "defender_start_investigation",
        description = "Start an automated investigation on a device (Windows 10 1803+/Windows Server 2019+). " +
            "Requires human approval. Limit: 50 per hour.",
        access = AccessLevel.WRITE,
        params = {
            string("machine_id", "Device to investigate (40-hex device ID).", required = true, pattern = Patterns.MACHINE_ID)
            string("comment", "Why the investigation is being started (recorded in Defender).", required = true, maxLength = Validators.MAX_COMMENT_LENGTH)
        },
    ) {
        val machineId = Validators.machineId(args.string("machine_id"))
        val comment = Validators.comment(args.string("comment"))
        authorize("Start an automated investigation on device $machineId", listOf("Device ID" to machineId, "Comment" to comment))
            ?.let { return@tool it }
        render(client.request(HttpMethod.Post, "/api/machines/${seg(machineId)}/startInvestigation", body = jsonOf("Comment" to comment)))
    }

    val collectInvestigationPackage: ToolSpec = tool(
        name = "defender_collect_investigation_package",
        description = "Collect a forensic investigation package (logs, autoruns, processes, network state) from a device. " +
            "This copies potentially sensitive data off the machine, so it requires the destructive access level " +
            "and human approval. Returns a machine action; poll it with defender_get_machine_action.",
        access = AccessLevel.DESTRUCTIVE,
        destructive = false,
        params = {
            string("machine_id", "Device to collect from (40-hex device ID).", required = true, pattern = Patterns.MACHINE_ID)
            string("comment", "Why the package is being collected (recorded in Defender).", required = true, maxLength = Validators.MAX_COMMENT_LENGTH)
        },
    ) {
        val machineId = Validators.machineId(args.string("machine_id"))
        val comment = Validators.comment(args.string("comment"))
        authorize(
            "Collect a forensic investigation package from device $machineId",
            listOf("Device ID" to machineId, "Comment" to comment),
        )?.let { return@tool it }
        render(client.request(HttpMethod.Post, "/api/machines/${seg(machineId)}/collectInvestigationPackage", body = jsonOf("Comment" to comment)))
    }

    val getInvestigationPackageUri: ToolSpec = tool(
        name = "defender_get_investigation_package_uri",
        description = "Get a short-lived download link for a collected investigation package. The link is a bearer " +
            "credential for forensic data: it requires the destructive access level and human approval, and must " +
            "only be given to the human operator, never placed in queries or other tools. Limit: 2 per minute.",
        access = AccessLevel.DESTRUCTIVE,
        confirm = true,
        readOnly = true,
        params = { string("action_id", "Machine action ID returned by defender_collect_investigation_package.", required = true, pattern = Patterns.GUID) },
    ) {
        val actionId = Validators.guid(args.string("action_id"), "action_id")
        authorize(
            "Reveal the download link for investigation package (machine action $actionId)",
            listOf("Machine action ID" to actionId),
        )?.let { return@tool it }
        render(client.get("/api/machineactions/${seg(actionId)}/getPackageUri", bucket = RateBucket.PACKAGE_URI))
    }

    val all: List<ToolSpec> = listOf(
        listInvestigations,
        getInvestigation,
        startInvestigation,
        collectInvestigationPackage,
        getInvestigationPackageUri,
    )
}
