package com.jitunicornfx.defender.mcp.tools

import com.jitunicornfx.defender.mcp.ToolSpec
import com.jitunicornfx.defender.mcp.Validators
import com.jitunicornfx.defender.mcp.tool

/** Domain-related and IP-related alerts and statistics. */
object IndicatorTools {
    const val MAX_LOOKBACK_HOURS = 720

    private fun lookback(call: com.jitunicornfx.defender.mcp.ToolCall): List<Pair<String, String>> =
        call.args.optInt("look_back_hours", 1, MAX_LOOKBACK_HOURS)?.let { listOf("lookBackHours" to it.toString()) } ?: emptyList()

    val getDomainAlerts: ToolSpec = tool(
        name = "defender_get_domain_alerts",
        description = "List alerts related to a domain (communication with it was observed by a device).",
        params = {
            string("domain", "DNS domain, e.g. example.com.", required = true, maxLength = 253)
            cursorParams()
        },
    ) {
        pagedList("/api/domains/${seg(Validators.domain(args.string("domain")))}/alerts")
    }

    val getDomainMachines: ToolSpec = tool(
        name = "defender_get_domain_machines",
        description = "List devices that communicated with a domain (at most 500).",
        params = {
            string("domain", "DNS domain, e.g. example.com.", required = true, maxLength = 253)
            cursorParams()
        },
    ) {
        pagedList("/api/domains/${seg(Validators.domain(args.string("domain")))}/machines")
    }

    val getDomainStats: ToolSpec = tool(
        name = "defender_get_domain_stats",
        description = "Get prevalence statistics for a domain in the organization (first/last seen, device count).",
        params = {
            string("domain", "DNS domain, e.g. example.com.", required = true, maxLength = 253)
            integer("look_back_hours", "Hours to look back (default 720 = 30 days).", 1, MAX_LOOKBACK_HOURS)
        },
    ) {
        getAndRender("/api/domains/${seg(Validators.domain(args.string("domain")))}/stats", lookback(this))
    }

    val getIpAlerts: ToolSpec = tool(
        name = "defender_get_ip_alerts",
        description = "List alerts related to an IP address.",
        params = {
            string("ip", "IPv4 or IPv6 address.", required = true, maxLength = 45)
            cursorParams()
        },
    ) {
        pagedList("/api/ips/${seg(Validators.ipAddress(args.string("ip")))}/alerts")
    }

    val getIpStats: ToolSpec = tool(
        name = "defender_get_ip_stats",
        description = "Get prevalence statistics for an IP address in the organization (first/last seen, device count).",
        params = {
            string("ip", "IPv4 or IPv6 address.", required = true, maxLength = 45)
            integer("look_back_hours", "Hours to look back (default 720 = 30 days).", 1, MAX_LOOKBACK_HOURS)
        },
    ) {
        getAndRender("/api/ips/${seg(Validators.ipAddress(args.string("ip")))}/stats", lookback(this))
    }

    val all: List<ToolSpec> = listOf(getDomainAlerts, getDomainMachines, getDomainStats, getIpAlerts, getIpStats)
}
