package com.jitunicornfx.defender.mcp.tools

import com.jitunicornfx.defender.mcp.OData
import com.jitunicornfx.defender.mcp.ToolSpec
import com.jitunicornfx.defender.mcp.Validators
import com.jitunicornfx.defender.mcp.tool

/** Remediation activities (Defender Vulnerability Management remediation tasks). */
object RemediationTools {
    val FILTER_FIELDS = setOf("createdOn", "status")
    private const val TASK_ID = "^[A-Za-z0-9-]{1,64}$"
    private val TASK_ID_REGEX = Regex(TASK_ID)

    private fun taskId(value: String): String {
        val v = value.trim()
        require(TASK_ID_REGEX.matches(v)) { "task_id must be 1-64 letters, digits or '-'." }
        return v
    }

    val listTasks: ToolSpec = tool(
        name = "defender_list_remediation_tasks",
        description = "List vulnerability-management remediation activities (requested fixes, their status, due dates and progress).",
        params = {
            string("status", "Remediation status, e.g. Active or Completed.", pattern = Patterns.STATE_NAME)
            string("created_after", "Only activities created at or after this ISO-8601 time.", format = "date-time")
            paging(FILTER_FIELDS)
        },
    ) {
        val structured = OData.and(
            args.optString("status")?.let { "status eq ${OData.quote(stateName(it, "status"))}" },
            args.optString("created_after")?.let { "createdOn ge ${OData.datetime(Validators.timestamp(it, "created_after"))}" },
        )
        val (query, _) = listQuery(structured, FILTER_FIELDS)
        pagedList("/api/remediationTasks", query)
    }

    val getTask: ToolSpec = tool(
        name = "defender_get_remediation_task",
        description = "Get one remediation activity by ID.",
        params = { string("task_id", "Remediation activity ID.", required = true, pattern = TASK_ID) },
    ) {
        getAndRender("/api/remediationTasks/${seg(taskId(args.string("task_id")))}")
    }

    val getTaskMachines: ToolSpec = tool(
        name = "defender_get_remediation_task_machines",
        description = "List the exposed devices of one remediation activity.",
        params = {
            string("task_id", "Remediation activity ID.", required = true, pattern = TASK_ID)
            cursorParams()
        },
    ) {
        pagedList("/api/remediationTasks/${seg(taskId(args.string("task_id")))}/machineReferences")
    }

    val all: List<ToolSpec> = listOf(listTasks, getTask, getTaskMachines)
}

/** User methods: alerts and devices related to a user account. */
object UserTools {
    val getUserAlerts: ToolSpec = tool(
        name = "defender_get_user_alerts",
        description = "List alerts related to a user account (by account name, e.g. jdoe).",
        params = {
            string("user", "Account name (UPN prefix), e.g. jdoe.", required = true, maxLength = 104)
            cursorParams()
        },
    ) {
        pagedList("/api/users/${seg(Validators.userId(args.string("user")))}/alerts")
    }

    val getUserMachines: ToolSpec = tool(
        name = "defender_get_user_machines",
        description = "List devices a user account has logged on to.",
        params = {
            string("user", "Account name (UPN prefix), e.g. jdoe.", required = true, maxLength = 104)
            cursorParams()
        },
    ) {
        pagedList("/api/users/${seg(Validators.userId(args.string("user")))}/machines")
    }

    val all: List<ToolSpec> = listOf(getUserAlerts, getUserMachines)
}
