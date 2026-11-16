package com.jitunicornfx.defender.mcp.tools

import com.jitunicornfx.defender.mcp.AccessLevel
import com.jitunicornfx.defender.mcp.JsonCodec
import com.jitunicornfx.defender.mcp.RateBucket
import com.jitunicornfx.defender.mcp.ToolSpec
import com.jitunicornfx.defender.mcp.Validators
import com.jitunicornfx.defender.mcp.errorResult
import com.jitunicornfx.defender.mcp.tool
import com.jitunicornfx.defender.mcp.tools.ResponseTools.machinePreview
import io.ktor.http.HttpMethod
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull

/**
 * File-sample collection through live response, restricted to its read-only `GetFile` command.
 *
 * Live response can also push files and run scripts (arbitrary code execution on the endpoint); this
 * server never builds those commands. Even GetFile copies data off a device, so it is DESTRUCTIVE-tier,
 * needs a substantive comment and human approval, shows the approver the device first (failing closed
 * if it cannot), refuses protected devices, and refuses credential and secret stores.
 *
 * Paths are validated in a strict canonical form (one separator style, no empty or dot segments, no
 * alternate data streams, 8.3 short names or trailing dots/spaces), because the OS resolves many
 * spellings to the same file and a deny-list only works on one spelling.
 */
object FileCollectionTools {
    const val MAX_PATH = 1_024
    const val MIN_COMMENT = ResponseTools.MIN_CONTAINMENT_COMMENT

    enum class PathStyle { WINDOWS, POSIX }

    private val WINDOWS_ROOT = Regex("^[A-Za-z]:\\\\")

    /** macOS: /etc, /var and /tmp are symlinks into /private. */
    private val PRIVATE_ALIAS = Regex("^/private(?=/(etc|var|tmp)/)")
    private val FORBIDDEN_CHARS = setOf('*', '?', '"', '<', '>', '|', '%', '$')

    /** Windows credential and secret stores, matched on the canonical lowercased path (`\` separators). */
    private val WINDOWS_DENIED = listOf(
        Regex("\\\\windows\\\\system32\\\\config\\\\"), // SAM, SECURITY, SYSTEM, SOFTWARE hives and their backups
        Regex("\\\\(repair|regback)\\\\"),
        Regex("\\\\ntds\\\\|ntds\\.dit$"),
        Regex("\\\\microsoft\\\\(protect|credentials|crypto|vault)\\\\"), // DPAPI master keys, credential manager, vaults
        Regex("\\\\(google\\\\chrome|microsoft\\\\edge|bravesoftware\\\\brave-browser)\\\\user data\\\\"),
        Regex("\\\\mozilla\\\\firefox\\\\profiles\\\\"),
        Regex("\\\\(ntuser|usrclass)\\.dat($|\\.)"),
        Regex("\\\\panther\\\\|\\\\sysprep\\\\|unattend(ed)?\\.xml$|sysprep\\.(xml|inf)$"),
        Regex("\\\\policies\\\\.*\\\\(groups|services|scheduledtasks|datasources|drives|printers)\\.xml$"), // GPP cpasswords
        Regex("^[a-z]:\\\\(pagefile|hiberfil|swapfile)\\.sys$"),
        Regex("\\.(dmp|vhd|vhdx|vmrs|vmem|vmsn|avhdx)$"),
        Regex("\\\\\\.(ssh|aws|azure|kube|docker|gnupg)\\\\"),
        Regex("\\.(kdbx|pfx|p12|pem|key|keytab|ppk|jks|keystore)$"),
    )

    /** POSIX credential and secret stores, matched on the canonical path. */
    private val POSIX_DENIED = listOf(
        Regex("^/proc/"),
        Regex("^/root/"),
        Regex("^/etc/(shadow|gshadow|sudoers|master\\.passwd|security/opasswd)-?$"), // incl. shadow-utils backups (shadow-)
        Regex("^/etc/sudoers\\.d/"),
        Regex("^/etc/ssl/private/"),
        Regex("^/etc/[^/]*\\.keytab$|^/etc/krb5\\.keytab$"),
        Regex("^/var/lib/(sss|samba/private)/"),
        Regex("^/var/db/(dslocal|shadow)/"), // macOS directory services and password hashes
        Regex("/library/keychains/", RegexOption.IGNORE_CASE),
        Regex("/\\.(ssh|aws|azure|kube|docker|gnupg|password-store)/"),
        Regex("\\.(kdbx|pfx|p12|pem|key|keytab|ppk|jks|keystore)$"),
    )

    /**
     * Validate [raw] as a canonical absolute path in [style]; returns it unchanged when acceptable.
     * Refusing non-canonical spellings is what makes the deny-list reliable.
     */
    internal fun validatePath(raw: String, style: PathStyle): String {
        val p = raw.trim()
        require(p.isNotEmpty() && p.length <= MAX_PATH) { "path must be 1-$MAX_PATH characters." }
        require(p.none { it.isISOControl() } && !Validators.INVISIBLE.containsMatchIn(p)) { "path must not contain control or invisible characters." }
        require(p.none { it in FORBIDDEN_CHARS }) { "path must not contain wildcards, quotes, pipes or environment variables." }
        when (style) {
            PathStyle.WINDOWS -> {
                require(WINDOWS_ROOT.containsMatchIn(p)) { "path must be an absolute Windows path such as C:\\Users\\Public\\file.exe." }
                require('/' !in p) { "path must use only backslashes." }
                require(p.indexOf(':', startIndex = 2) < 0) { "path must not contain ':' after the drive (no alternate data streams)." }
                val segments = p.substring(3).split('\\')
                require(segments.none { it.isEmpty() }) { "path must not contain empty segments (doubled backslashes)." }
                require(segments.none { it == "." || it == ".." }) { "path must not contain '.' or '..' segments." }
                require(segments.none { it.endsWith('.') || it.endsWith(' ') }) { "path segments must not end with '.' or a space." }
                require(segments.none { '~' in it }) { "path must not use 8.3 short names (segments containing '~')." }
                val lower = p.lowercase()
                require(WINDOWS_DENIED.none { it.containsMatchIn(lower) }) { DENIED_MESSAGE }
            }
            PathStyle.POSIX -> {
                require(p.startsWith('/')) { "path must be an absolute path such as /tmp/payload." }
                require('\\' !in p) { "path must use only forward slashes." }
                val segments = p.substring(1).split('/')
                require(segments.none { it.isEmpty() }) { "path must not contain empty segments ('//') or end with '/'." }
                require(segments.none { it == "." || it == ".." }) { "path must not contain '.' or '..' segments." }
                // Match case-insensitively (macOS file systems are case-insensitive), with macOS's /private aliases
                // folded (/private/etc is /etc), and also against the Windows deny-list: Windows resolves a '/'-rooted
                // path on the system drive, so the same text must be safe in both readings.
                val canonical = p.lowercase().replaceFirst(PRIVATE_ALIAS, "")
                require(POSIX_DENIED.none { it.containsMatchIn(canonical) }) { DENIED_MESSAGE }
                val asWindows = "c:" + canonical.replace('/', '\\')
                require(WINDOWS_DENIED.none { it.containsMatchIn(asWindows) }) { DENIED_MESSAGE }
            }
        }
        return p
    }

    private const val DENIED_MESSAGE =
        "path names a credential or secret store (registry hives, NTDS, DPAPI/credential stores, browser profiles, memory or " +
            "disk images, keys, shadow files, /proc, /root, keychains), which this server never collects. Use the Defender portal if it is truly needed."

    /** Path style for a device, from the OS fact its preview reported; Windows unless clearly not. */
    internal fun styleFor(facts: List<Pair<String, String>>): PathStyle {
        val os = facts.firstOrNull { it.first == "OS" }?.second?.lowercase() ?: return PathStyle.WINDOWS
        return if (os.startsWith("windows")) PathStyle.WINDOWS else PathStyle.POSIX
    }

    /** A path that is valid in at least one style (cheap pre-check before any request). */
    private fun precheck(raw: String) {
        val windows = runCatching { validatePath(raw, PathStyle.WINDOWS) }
        val posix = runCatching { validatePath(raw, PathStyle.POSIX) }
        if (windows.isFailure && posix.isFailure) {
            // Report the error of the style the path looks like.
            throw (if (raw.trim().startsWith('/')) posix else windows).exceptionOrNull()!!
        }
    }

    val collectFile: ToolSpec = tool(
        name = "defender_collect_file",
        description = "Collect a copy of one file from a device for analysis (live response GetFile; no scripts are ever run). " +
            "Copies data off the device, so it needs the destructive access level, human approval and a substantive comment; " +
            "credential and secret stores are refused. Returns a machine action: poll defender_get_machine_action until it " +
            "Succeeded, then use defender_get_collected_file_link. Requires Machine.LiveResponse and a device group with an " +
            "automated remediation level.",
        access = AccessLevel.DESTRUCTIVE,
        destructive = false,
        params = {
            string("machine_id", "Device ID (40 hex characters).", required = true, pattern = Patterns.MACHINE_ID)
            string("path", "Absolute canonical path of the file, e.g. C:\\Users\\Public\\payload.exe or /tmp/payload.", required = true, maxLength = MAX_PATH)
            string("comment", "Why (at least $MIN_COMMENT characters; reference the alert or ticket).", required = true, maxLength = Validators.MAX_COMMENT_LENGTH)
        },
    ) {
        val id = Validators.machineId(args.string("machine_id"))
        val rawPath = args.string("path")
        precheck(rawPath)
        val comment = Validators.comment(args.string("comment"))
        require(comment.length >= MIN_COMMENT) { "comment must explain the collection in at least $MIN_COMMENT characters." }
        val preview = machinePreview(id, enforce = true)
        if (preview is ResponseTools.Preview.Refused) return@tool preview.result
        val facts = (preview as ResponseTools.Preview.Ready).facts
        // The device's own OS decides which spelling rules apply: a '/'-rooted path on Windows resolves on the system drive.
        val path = validatePath(rawPath, styleFor(facts))
        authorize(
            "COLLECT a copy of file '$path' from device $id",
            listOf("Device ID" to id, "Path" to path, "Comment" to comment),
            facts = facts,
        )?.let { return@tool it }
        val command = jsonOf(
            "type" to "GetFile",
            "params" to JsonArray(listOf(jsonOf("key" to "Path", "value" to path))),
        )
        render(
            client.request(
                HttpMethod.Post,
                "/api/machines/${seg(id)}/runliveresponse",
                body = jsonOf("Commands" to JsonArray(listOf(command)), "Comment" to comment),
                bucket = RateBucket.LIVE_RESPONSE,
                idempotent = false,
            ),
        )
    }

    private fun JsonObject.text(key: String): String? = (this[key] as? JsonPrimitive)?.contentOrNull?.takeIf { it.isNotBlank() }

    /**
     * The GetFile path of a live-response machine action, when (and only when) it is exactly the shape
     * defender_collect_file creates: type LiveResponse, one GetFile command. Null otherwise.
     */
    internal fun getFilePath(action: JsonObject): String? {
        if (!action.text("type").equals("LiveResponse", ignoreCase = true)) return null
        val commands = action["commands"] as? JsonArray ?: return null
        if (commands.size != 1) return null
        val entry = commands.single() as? JsonObject ?: return null
        val command = (entry["command"] as? JsonObject) ?: entry
        if (!command.text("type").equals("GetFile", ignoreCase = true)) return null
        val params = command["params"] as? JsonArray ?: return null
        return params.mapNotNull { it as? JsonObject }
            .firstOrNull { it.text("key").equals("Path", ignoreCase = true) }
            ?.text("value")
    }

    val getCollectedFileLink: ToolSpec = tool(
        name = "defender_get_collected_file_link",
        description = "Get a 30-minute download link for a file collected with defender_collect_file (after its machine action " +
            "Succeeded). Only single-GetFile live-response actions on non-sensitive paths qualify. The call changes nothing, but " +
            "the link is a bearer credential for the file, so it needs the write access level and human approval, and must only " +
            "be given to the human operator.",
        access = AccessLevel.WRITE,
        confirm = true,
        readOnly = true,
        params = { string("action_id", "Machine action ID returned by defender_collect_file.", required = true, pattern = Patterns.GUID) },
    ) {
        val actionId = Validators.guid(args.string("action_id"), "action_id")
        // Look the action up first and fail closed: the link must never expose a portal-collected SAM hive or a
        // RunScript transcript that this server's own rules would have refused to collect.
        val lookup = client.get("/api/machineactions/${seg(actionId)}")
        val parsed = if (lookup.ok) runCatching { JsonCodec.compact.parseToJsonElement(lookup.text) as? JsonObject }.getOrNull() else null
        val action = parsed ?: return@tool errorResult("Refused: machine action $actionId could not be looked up, so nothing is revealed.")
        val path = getFilePath(action) ?: return@tool errorResult(
            "Refused: machine action $actionId is not a single-file collection (live response GetFile), so this tool does not reveal its results.",
        )
        // Valid in the reading its shape implies; POSIX validation also applies the Windows deny-list, so a
        // '/'-rooted path collected from a Windows device (resolved on the system drive) cannot slip through.
        val pathOk = runCatching { validatePath(path, if (path.startsWith('/')) PathStyle.POSIX else PathStyle.WINDOWS) }.isSuccess
        if (!pathOk) {
            return@tool errorResult(
                "Refused: the collected path is a credential or secret store, or not in canonical form, so this server does not reveal it. " +
                    "Retrieve it in the Defender portal if it is truly needed.",
            )
        }
        if (!action.text("status").equals("Succeeded", ignoreCase = true)) {
            return@tool errorResult("The collection has not succeeded yet (status: ${action.text("status")?.take(20) ?: "unknown"}); poll defender_get_machine_action.")
        }
        authorize(
            "Reveal the download link for file '$path' collected by machine action $actionId",
            listOf("Machine action ID" to actionId),
            facts = listOfNotNull(
                "Path" to path,
                action.text("computerDnsName")?.let { "Device name" to it },
                action.text("requestor")?.let { "Collected by" to it },
                action.text("creationDateTimeUtc")?.let { "Collected at" to it },
            ),
        )?.let { return@tool it }
        // Index 0: a qualifying action has exactly one command.
        getAndRender("/api/machineactions/${seg(actionId)}/GetLiveResponseResultDownloadLink(index=0)")
    }

    val all: List<ToolSpec> = listOf(collectFile, getCollectedFileLink)
}
