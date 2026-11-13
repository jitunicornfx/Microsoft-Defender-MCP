package com.jitunicornfx.defender.mcp.tools

import com.jitunicornfx.defender.mcp.DefenderClient
import com.jitunicornfx.defender.mcp.JsonCodec
import com.jitunicornfx.defender.mcp.ResponseRenderer
import com.jitunicornfx.defender.mcp.ToolSpec
import com.jitunicornfx.defender.mcp.Validators
import com.jitunicornfx.defender.mcp.tool
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * Composite tools that fan out several independent reads concurrently and merge them into one
 * result. This is where coroutines pay off: four sequential round-trips to Defender become one
 * round-trip's latency, the shared [kotlinx.coroutines.sync.Semaphore] in [DefenderClient] still
 * bounds concurrency, and structured concurrency (`coroutineScope`) cancels the siblings if the
 * caller cancels. A section that fails reports its own error without sinking the others.
 */
object TriageTools {
    const val DEFAULT_ITEMS = 25
    const val MAX_ITEMS = 200

    /** One labelled read; [path] and [query] are fully validated before this is built. */
    internal data class Section(val key: String, val path: String, val query: List<Pair<String, String>> = emptyList())

    /** Fetch all [sections] concurrently and merge them, each list capped at [maxItems]. */
    internal suspend fun fanOut(client: DefenderClient, sections: List<Section>, maxItems: Int): JsonObject = coroutineScope {
        val results = sections.map { section ->
            async { section.key to fetchSection(client, section, maxItems) }
        }.awaitAll()
        JsonObject(results.toMap())
    }

    private suspend fun fetchSection(client: DefenderClient, section: Section, maxItems: Int): JsonElement {
        val response = try {
            client.get(section.path, section.query)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            return JsonObject(mapOf("error" to JsonPrimitive("request failed (${e::class.simpleName})")))
        }
        if (!response.ok) {
            val hint = ResponseRenderer.statusHint(response.status)
            return JsonObject(mapOf("error" to JsonPrimitive("HTTP ${response.status}" + (hint?.let { ": $it" } ?: ""))))
        }
        val parsed = runCatching { JsonCodec.compact.parseToJsonElement(response.text) }.getOrNull()
            ?: return JsonObject(mapOf("error" to JsonPrimitive("response was not JSON")))
        return capLists(parsed, maxItems)
    }

    /** Drop OData annotations and keep the first [maxItems] of a `value` list, noting how many there were. */
    internal fun capLists(element: JsonElement, maxItems: Int): JsonElement {
        if (element !is JsonObject) return element
        val cleaned = element.filterKeys { !it.startsWith("@odata.") }
        val list = cleaned["value"] as? JsonArray ?: return JsonObject(cleaned)
        if (list.size <= maxItems) return JsonArray(list)
        return JsonObject(
            mapOf(
                "items" to JsonArray(list.take(maxItems)),
                "totalReturned" to JsonPrimitive(list.size),
                "note" to JsonPrimitive("Only the first $maxItems items are shown; use the dedicated tool for the full list."),
            ),
        )
    }

    val machineTriage: ToolSpec = tool(
        name = "defender_machine_triage",
        description = "One-call triage of a device: its properties, related alerts, logged-on users, recent machine " +
            "actions and missing security updates, fetched concurrently. Use it as the starting point when a device is suspect.",
        params = {
            string("machine_id", "Device ID (40 hex characters).", required = true, pattern = Patterns.MACHINE_ID)
            integer("max_items", "Items kept per list section.", 1, MAX_ITEMS, DEFAULT_ITEMS)
        },
    ) {
        val id = Validators.machineId(args.string("machine_id"))
        val maxItems = args.int("max_items", 1, MAX_ITEMS, DEFAULT_ITEMS)
        val base = "/api/machines/${seg(id)}"
        val tree = fanOut(
            client,
            listOf(
                Section("machine", base),
                Section("alerts", "$base/alerts"),
                Section("logonUsers", "$base/logonusers"),
                Section("recentActions", "/api/machineactions", listOf("\$filter" to "machineId eq '$id'", "\$top" to maxItems.toString())),
                Section("missingKbs", "$base/getmissingkbs"),
            ),
            maxItems,
        )
        ctx.renderer.renderTree(tree)
    }

    val indicatorLookup: ToolSpec = tool(
        name = "defender_indicator_lookup",
        description = "Look up an IP address or domain in one call: related alerts and organizational prevalence " +
            "(and, for domains, the devices that contacted it), fetched concurrently.",
        params = {
            string("indicator", "An IPv4/IPv6 address or a DNS domain.", required = true, maxLength = 253)
            integer("look_back_hours", "Hours of statistics to consider (default 720 = 30 days).", 1, IndicatorTools.MAX_LOOKBACK_HOURS)
            integer("max_items", "Items kept per list section.", 1, MAX_ITEMS, DEFAULT_ITEMS)
        },
    ) {
        val raw = args.string("indicator").trim()
        val maxItems = args.int("max_items", 1, MAX_ITEMS, DEFAULT_ITEMS)
        val lookback = args.optInt("look_back_hours", 1, IndicatorTools.MAX_LOOKBACK_HOURS)
            ?.let { listOf("lookBackHours" to it.toString()) } ?: emptyList()
        val isIp = runCatching { Validators.ipAddress(raw) }.isSuccess
        val sections = if (isIp) {
            val ip = Validators.ipAddress(raw)
            listOf(
                Section("alerts", "/api/ips/${seg(ip)}/alerts"),
                Section("stats", "/api/ips/${seg(ip)}/stats", lookback),
            )
        } else {
            val domain = Validators.domain(raw, "indicator")
            listOf(
                Section("alerts", "/api/domains/${seg(domain)}/alerts"),
                Section("stats", "/api/domains/${seg(domain)}/stats", lookback),
                Section("machines", "/api/domains/${seg(domain)}/machines"),
            )
        }
        val tree = fanOut(client, sections, maxItems)
        ctx.renderer.renderTree(JsonObject(mapOf("indicatorType" to JsonPrimitive(if (isIp) "ip" else "domain")) + tree))
    }

    val all: List<ToolSpec> = listOf(machineTriage, indicatorLookup)
}
