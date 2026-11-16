package com.jitunicornfx.defender.mcp.tools

import com.jitunicornfx.defender.mcp.AccessLevel
import com.jitunicornfx.defender.mcp.ActionBudget
import com.jitunicornfx.defender.mcp.ActionGate
import com.jitunicornfx.defender.mcp.ApprovalOutcome
import com.jitunicornfx.defender.mcp.Config
import com.jitunicornfx.defender.mcp.DefenderClient
import com.jitunicornfx.defender.mcp.RateBucket
import com.jitunicornfx.defender.mcp.ResponseRenderer
import com.jitunicornfx.defender.mcp.ToolContext
import com.jitunicornfx.defender.mcp.ToolRegistry
import com.jitunicornfx.defender.mcp.ToolSpec
import com.jitunicornfx.defender.mcp.invokeTool
import com.jitunicornfx.defender.mcp.testutil.ACTION_ID
import com.jitunicornfx.defender.mcp.testutil.Canned
import com.jitunicornfx.defender.mcp.testutil.FakeDefender
import com.jitunicornfx.defender.mcp.testutil.FixedApprover
import com.jitunicornfx.defender.mcp.testutil.ListAudit
import com.jitunicornfx.defender.mcp.testutil.MACHINE_ID
import com.jitunicornfx.defender.mcp.testutil.Recorded
import com.jitunicornfx.defender.mcp.testutil.failed
import com.jitunicornfx.defender.mcp.testutil.jsonArgs
import com.jitunicornfx.defender.mcp.testutil.testConfig
import com.jitunicornfx.defender.mcp.testutil.text
import io.kotest.assertions.withClue
import io.kotest.core.spec.style.FunSpec
import io.kotest.datatest.withData
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.collections.shouldContainExactly
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.collections.shouldNotContain
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotContain
import io.ktor.client.request.HttpRequestData
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.util.Collections
import java.util.concurrent.atomic.AtomicLong

private const val COMMENT = "Alert da638 - sample for sandbox, INC-4411"
private const val WIN_PATH = "C:\\Users\\Public\\payload.exe"

private const val MACHINE_JSON = """{"id":"$MACHINE_ID","computerDnsName":"ws-042.contoso.local","osPlatform":"Windows11",
    "version":"23H2","healthStatus":"Active","deviceValue":"High","rbacGroupName":"Finance workstations",
    "lastSeen":"2026-11-12T10:00:00Z","machineTags":["finance","VIP"]}"""

private const val LINUX_MACHINE_JSON = """{"id":"$MACHINE_ID","computerDnsName":"web-07.contoso.local","osPlatform":"Ubuntu",
    "version":"22.04","healthStatus":"Active","machineTags":[]}"""

private const val MAC_MACHINE_JSON = """{"id":"$MACHINE_ID","computerDnsName":"mbp-alice","osPlatform":"macOS",
    "version":"14.5","healthStatus":"Active","machineTags":[]}"""

private const val ACTION_JSON = """{"id":"$ACTION_ID","type":"LiveResponse","status":"Pending"}"""

/** A machine action exactly as defender_collect_file creates it, in Defender's documented shape. */
private fun getFileAction(
    path: String = WIN_PATH,
    status: String = "Succeeded",
    type: String = "LiveResponse",
    commandType: String = "GetFile",
): String {
    val escaped = path.replace("\\", "\\\\")
    return """{"id":"$ACTION_ID","type":"$type","status":"$status","computerDnsName":"ws-042.contoso.local",
        "requestor":"analyst@contoso.com","creationDateTimeUtc":"2026-11-12T10:00:00Z",
        "commands":[{"index":0,"commandStatus":"Completed",
        "command":{"type":"$commandType","params":[{"key":"Path","value":"$escaped"}]}}]}"""
}

/** A rig whose client can run on a virtual clock, so live-response pacing is observable. */
private class FileRig(
    access: AccessLevel = AccessLevel.DESTRUCTIVE,
    outcome: ApprovalOutcome = ApprovalOutcome.APPROVED,
    protectedTags: Set<String> = emptySet(),
    maxActions: Int = Config.DEFAULT_MAX_ACTIONS_PER_HOUR,
    clock: (() -> Long)? = null,
    sleep: suspend (Long) -> Unit = {},
) {
    var machine: () -> Canned = { Canned(body = MACHINE_JSON) }
    var post: (HttpRequestData) -> Canned = { Canned(HttpStatusCode.Created, ACTION_JSON) }
    var linkResponse: () -> Canned = { Canned(body = """{"value":"https://blob.example/file.zip?sig=abc"}""") }
    var action: () -> Canned = { Canned(body = getFileAction()) }

    val config: Config = testConfig(access = access, maxActionsPerHour = maxActions).copy(protectedTags = protectedTags)
    val fake: FakeDefender = FakeDefender(
        api = { req ->
            when {
                req.method == HttpMethod.Post -> post(req)
                req.url.encodedPath.startsWith("/api/machines/") -> machine()
                req.url.toString().contains("GetLiveResponseResultDownloadLink") -> linkResponse()
                req.url.encodedPath.startsWith("/api/machineactions/") -> action()
                else -> Canned(HttpStatusCode.NotFound)
            }
        },
    )
    val approver = FixedApprover(outcome)
    val audit = ListAudit()
    val gate = ActionGate(config.confirmation, ActionBudget(config.maxActionsPerHour), audit)
    val client: DefenderClient = if (clock != null) DefenderClient(config, fake.engine, clock = clock, sleep = sleep) else fake.client(config, sleep)
    val context = ToolContext(config, client, ResponseRenderer(config.maxResultChars), gate)

    suspend fun call(spec: ToolSpec, vararg args: Pair<String, Any?>) = invokeTool(spec, jsonArgs(*args), context, approver)

    suspend fun collect(path: String = WIN_PATH, comment: String = COMMENT, id: String = MACHINE_ID) =
        call(FileCollectionTools.collectFile, "machine_id" to id, "path" to path, "comment" to comment)

    suspend fun link(id: String = ACTION_ID) = call(FileCollectionTools.getCollectedFileLink, "action_id" to id)

    val posts: List<Recorded> get() = fake.apiRequests.filter { it.request.method == HttpMethod.Post }
    val linkRequests: List<Recorded> get() = fake.apiRequests.filter { it.url.contains("GetLiveResponseResultDownloadLink") }
    val message: String get() = approver.lastMessage.shouldNotBeNull()
}

private val DENIED_PATHS = listOf(
    "C:\\Windows\\System32\\config\\SAM",
    "c:\\windows\\system32\\config\\sam",
    "C:\\WINDOWS\\SYSTEM32\\CONFIG\\SECURITY",
    "D:\\Windows\\System32\\config\\SYSTEM",
    "C:\\Windows\\System32\\config\\SAM.LOG1",
    "C:\\Windows\\System32\\config\\system.sav",
    "C:\\Windows\\repair\\SAM",
    "C:\\Windows\\System32\\config\\RegBack\\SYSTEM",
    "C:\\Windows\\System32\\config\\regback\\security",
    "C:\\Windows\\NTDS\\ntds.dit",
    "E:\\backup\\NTDS.DIT",
    "C:\\Temp\\lsass.dmp",
    "C:\\Temp\\LSASS_1234.DMP",
    "C:\\Users\\bob\\AppData\\Roaming\\Microsoft\\Protect\\S-1-5-21\\key",
    "C:\\Users\\bob\\AppData\\Roaming\\Microsoft\\Credentials\\ABCDEF",
    "C:\\ProgramData\\Microsoft\\Crypto\\RSA\\MachineKeys\\x",
    "C:\\Users\\bob\\.ssh\\id_ed25519",
    "C:\\Users\\bob\\Documents\\vault.KDBX",
    "C:\\certs\\server.pfx",
    "C:\\certs\\client.p12",
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/sudoers",
    "/root/.ssh/id_rsa",
    "/opt/app/tls/server.pem",
    "/opt/app/tls/server.key",
    "/Users/alice/Library/vault.kdbx",
)

/** One or more paths per deny-list category added with the canonical-path rules (category to path). */
private val WINDOWS_DENIED_CATEGORIES = listOf(
    "SOFTWARE hive" to "C:\\Windows\\System32\\config\\SOFTWARE",
    "DPAPI vault (Local)" to "C:\\Users\\bob\\AppData\\Local\\Microsoft\\Vault\\4BF4C442\\Policy.vpol",
    "DPAPI credentials (Local)" to "C:\\Users\\bob\\AppData\\Local\\Microsoft\\Credentials\\DFBE70A7",
    "Chrome profile" to "C:\\Users\\bob\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data",
    "Chrome Local State" to "C:\\Users\\bob\\AppData\\Local\\Google\\Chrome\\User Data\\Local State",
    "Edge profile" to "C:\\Users\\bob\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Cookies",
    "Brave profile" to "C:\\Users\\bob\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Login Data",
    "Firefox profile" to "C:\\Users\\bob\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\x1y2.default-release\\logins.json",
    "NTUSER.DAT" to "C:\\Users\\bob\\NTUSER.DAT",
    "NTUSER.DAT log" to "C:\\Users\\bob\\ntuser.dat.LOG1",
    "UsrClass.dat" to "C:\\Users\\bob\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat",
    "Panther" to "C:\\Windows\\Panther\\setupact.log",
    "Sysprep folder" to "C:\\Windows\\System32\\Sysprep\\Panther\\x.log",
    "unattend.xml" to "C:\\unattend.xml",
    "autounattend.xml" to "D:\\Deploy\\Autounattend.xml",
    "unattended.xml" to "C:\\Deploy\\unattended.xml",
    "sysprep.inf" to "C:\\sysprep.inf",
    "GPP Groups.xml" to "C:\\Windows\\SYSVOL\\domain\\Policies\\{31B2F340-016D-11D2-945F-00C04FB984F9}\\Machine\\Preferences\\Groups\\Groups.xml",
    "GPP ScheduledTasks.xml" to "C:\\Windows\\SYSVOL\\sysvol\\corp\\Policies\\{A}\\User\\Preferences\\ScheduledTasks\\ScheduledTasks.xml",
    "GPP Services.xml" to "C:\\Windows\\SYSVOL\\domain\\Policies\\{A}\\Machine\\Preferences\\Services\\Services.xml",
    "GPP DataSources.xml" to "C:\\Windows\\SYSVOL\\domain\\Policies\\{A}\\User\\Preferences\\DataSources\\DataSources.xml",
    "GPP Drives.xml" to "C:\\Windows\\SYSVOL\\domain\\Policies\\{A}\\User\\Preferences\\Drives\\Drives.xml",
    "GPP Printers.xml" to "C:\\Windows\\SYSVOL\\domain\\Policies\\{A}\\User\\Preferences\\Printers\\Printers.xml",
    "pagefile.sys" to "C:\\pagefile.sys",
    "hiberfil.sys" to "D:\\HIBERFIL.SYS",
    "swapfile.sys" to "C:\\swapfile.sys",
    "memory dump" to "C:\\Windows\\MEMORY.DMP",
    "VHD" to "C:\\VMs\\dc01.vhd",
    "VHDX" to "C:\\VMs\\dc01.VHDX",
    "AVHDX" to "C:\\VMs\\dc01_1234.avhdx",
    "VMRS" to "C:\\ProgramData\\Microsoft\\Windows\\Hyper-V\\x.vmrs",
    "VMEM" to "C:\\VMs\\snap.vmem",
    "VMSN" to "C:\\VMs\\snap.vmsn",
    ".aws" to "C:\\Users\\bob\\.aws\\credentials",
    ".azure" to "C:\\Users\\bob\\.azure\\msal_token_cache.json",
    ".kube" to "C:\\Users\\bob\\.kube\\config",
    ".docker" to "C:\\Users\\bob\\.docker\\config.json",
    ".gnupg" to "C:\\Users\\bob\\.gnupg\\pubring.kbx",
    ".pem" to "C:\\certs\\ca.pem",
    ".key" to "C:\\certs\\server.key",
    ".keytab" to "C:\\krb\\svc.keytab",
    ".ppk" to "C:\\Users\\bob\\Documents\\putty.ppk",
    ".jks" to "C:\\app\\trust.jks",
    ".keystore" to "C:\\app\\release.keystore",
)

private val POSIX_DENIED_CATEGORIES = listOf(
    "/proc environ" to "/proc/1/environ",
    "/proc mem" to "/proc/self/mem",
    "/root" to "/root/.bash_history",
    "master.passwd" to "/etc/master.passwd",
    "opasswd" to "/etc/security/opasswd",
    "sudoers.d" to "/etc/sudoers.d/90-cloud-init-users",
    "ssl private" to "/etc/ssl/private/ssl-cert-snakeoil",
    "krb5.keytab" to "/etc/krb5.keytab",
    "other /etc keytab" to "/etc/http.keytab",
    "keytab elsewhere" to "/opt/svc/svc.keytab",
    "sssd cache" to "/var/lib/sss/db/cache_corp.ldb",
    "samba private" to "/var/lib/samba/private/secrets.tdb",
    "macOS dslocal" to "/var/db/dslocal/nodes/Default/users/alice.plist",
    "macOS shadow hash" to "/var/db/shadow/hash/ABCDEF",
    "macOS keychain" to "/Users/alice/Library/Keychains/login.keychain-db",
    "macOS keychain (case)" to "/Users/alice/library/KEYCHAINS/login.keychain-db",
    ".ssh" to "/home/alice/.ssh/authorized_keys",
    ".aws" to "/home/alice/.aws/credentials",
    ".azure" to "/home/alice/.azure/accessTokens.json",
    ".kube" to "/home/alice/.kube/config",
    ".docker" to "/home/alice/.docker/config.json",
    ".gnupg" to "/home/alice/.gnupg/private-keys-v1.d/x.key",
    ".password-store" to "/home/alice/.password-store/bank.gpg",
    ".pfx" to "/srv/certs/site.pfx",
    ".p12" to "/srv/certs/site.p12",
    ".ppk" to "/home/alice/putty.ppk",
    ".jks" to "/opt/app/trust.jks",
    ".keystore" to "/opt/app/release.keystore",
    ".kdbx" to "/home/alice/vault.kdbx",
)

private val MALFORMED_PATHS = listOf(
    "payload.exe" to "relative",
    "Users\\Public\\payload.exe" to "relative Windows",
    "./payload" to "relative POSIX",
    "~/payload" to "home-relative",
    "\\\\fileserver\\share\\payload.exe" to "UNC",
    "C:payload.exe" to "drive-relative",
    "C:\\" to "drive root",
    "C:\\Temp\\" to "Windows directory",
    "/tmp/" to "POSIX directory",
    "/" to "POSIX root",
    "C:\\Temp\\..\\Windows\\System32\\config\\SAM" to "Windows traversal",
    "/var/../etc/shadow" to "POSIX traversal",
    "/var/./log/x" to "dot segment",
    "C:\\Temp\\.\\x" to "Windows dot segment",
    "C:\\Temp\\*.exe" to "star wildcard",
    "/tmp/payload?.sh" to "question wildcard",
    "C:\\Temp\\\"x\".exe" to "quotes",
    "C:\\Temp\\a<b" to "angle bracket",
    "C:\\Temp\\a|b" to "pipe",
    "C:\\Temp\\a\u0000b" to "NUL",
    "/tmp/a\nb" to "newline",
    "/tmp/a\u200Bb" to "zero-width",
    "/" + "a".repeat(FileCollectionTools.MAX_PATH) to "too long",
    "   " to "blank",
)

class FileCollectionToolsSpec : FunSpec({

    context("tool definitions and registration") {
        test("collect_file is destructive-tier, approved, not idempotent; the link tool is write-tier and read-only") {
            FileCollectionTools.all.map { it.name } shouldContainExactly listOf("defender_collect_file", "defender_get_collected_file_link")
            with(FileCollectionTools.collectFile) {
                access shouldBe AccessLevel.DESTRUCTIVE
                confirm shouldBe true
                readOnly shouldBe false
                idempotent shouldBe false
                definition().annotations?.idempotentHint shouldBe false
                definition().inputSchema.required!!.toSet() shouldBe setOf("machine_id", "path", "comment")
                definition().inputSchema.properties!!["machine_id"]!!.jsonObject["pattern"]!!.jsonPrimitive.content shouldBe Patterns.MACHINE_ID
            }
            with(FileCollectionTools.getCollectedFileLink) {
                access shouldBe AccessLevel.WRITE
                confirm shouldBe true
                readOnly shouldBe true
                definition().annotations?.readOnlyHint shouldBe true
                description shouldContain "bearer credential"
                definition().inputSchema.properties!!["action_id"]!!.jsonObject["pattern"]!!.jsonPrimitive.content shouldBe Patterns.GUID
            }
            FileCollectionTools.MIN_COMMENT shouldBe 10
        }

        test("read-only exposes neither tool; write adds the link; destructive adds collection") {
            val ro = ToolRegistry.select(testConfig()).map { it.name }
            ro shouldNotContain "defender_collect_file"
            ro shouldNotContain "defender_get_collected_file_link"
            val w = ToolRegistry.select(testConfig(access = AccessLevel.WRITE)).map { it.name }
            w shouldContain "defender_get_collected_file_link"
            w shouldNotContain "defender_collect_file"
            val d = ToolRegistry.select(testConfig(access = AccessLevel.DESTRUCTIVE)).map { it.name }
            d shouldContain "defender_collect_file"
            d shouldContain "defender_get_collected_file_link"
        }

        test("the server never offers a live response tool that pushes files or runs scripts") {
            ToolRegistry.apiTools.map { it.name }.forEach {
                it shouldNotContain "run_script"
                it shouldNotContain "put_file"
                it shouldNotContain "live_response"
            }
        }
    }

    context("defender_collect_file: the request") {
        test("approved: device lookup, then exactly one GetFile command with the path and comment") {
            val r = FileRig()
            val res = r.collect(id = MACHINE_ID.uppercase())
            res.failed shouldBe false
            r.fake.apiRequests.first().request.method shouldBe HttpMethod.Get
            r.fake.apiRequests.first().path shouldBe "/api/machines/$MACHINE_ID"
            r.posts shouldHaveSize 1
            val post = r.posts.single()
            post.path shouldBe "/api/machines/$MACHINE_ID/runliveresponse"
            val body = post.bodyJson().jsonObject
            body.keys shouldBe setOf("Commands", "Comment")
            body["Comment"]!!.jsonPrimitive.content shouldBe COMMENT
            val commands = body["Commands"]!!.jsonArray
            commands shouldHaveSize 1
            val command = commands.single().jsonObject
            command.keys shouldBe setOf("type", "params")
            command["type"]!!.jsonPrimitive.content shouldBe "GetFile"
            val params = command["params"]!!.jsonArray
            params shouldHaveSize 1
            params.single().jsonObject["key"]!!.jsonPrimitive.content shouldBe "Path"
            params.single().jsonObject["value"]!!.jsonPrimitive.content shouldBe WIN_PATH
            r.approver.asked shouldBe 1
            r.message shouldContain "Action: COLLECT a copy of file '$WIN_PATH' from device $MACHINE_ID"
            r.message shouldContain "- Path (supplied by the AI): \"$WIN_PATH\""
            r.message shouldContain "- Device name: \"ws-042.contoso.local\""
            r.message shouldContain "- Device group: \"Finance workstations\""
            r.message shouldContain "- Tags: \"finance, VIP\""
            r.audit.lines.single() shouldContain "defender_collect_file"
            res.text() shouldContain "UNTRUSTED_DEFENDER_DATA"
        }

        test("POSIX paths are accepted for a non-Windows device and the path is trimmed") {
            for (json in listOf(LINUX_MACHINE_JSON, MAC_MACHINE_JSON)) {
                val r = FileRig()
                r.machine = { Canned(body = json) }
                r.collect(path = "  /tmp/.hidden/dropper.sh ").failed shouldBe false
                r.posts.single().bodyJson().jsonObject["Commands"]!!.jsonArray.single().jsonObject["params"]!!
                    .jsonArray.single().jsonObject["value"]!!.jsonPrimitive.content shouldBe "/tmp/.hidden/dropper.sh"
            }
        }

        test("a device with no OS fact is treated as Windows, so a POSIX path is refused after the lookup") {
            val r = FileRig()
            r.machine = { Canned(body = """{"computerDnsName":"mystery","machineTags":[]}""") }
            val res = r.collect(path = "/tmp/dropper.sh")
            res.failed shouldBe true
            res.text() shouldContain "absolute Windows path"
            r.approver.asked shouldBe 0
            r.posts.shouldBeEmpty()
        }

        test("a Windows path is refused for a Linux device") {
            val r = FileRig()
            r.machine = { Canned(body = LINUX_MACHINE_JSON) }
            val res = r.collect(path = WIN_PATH)
            res.failed shouldBe true
            res.text() shouldContain "path"
            r.approver.asked shouldBe 0
            r.posts.shouldBeEmpty()
        }

        test("styleFor: Windows when the OS starts with 'windows' (any case) or is unknown; POSIX otherwise") {
            FileCollectionTools.styleFor(listOf("OS" to "Windows11 23H2")) shouldBe FileCollectionTools.PathStyle.WINDOWS
            FileCollectionTools.styleFor(listOf("OS" to "WindowsServer2022")) shouldBe FileCollectionTools.PathStyle.WINDOWS
            FileCollectionTools.styleFor(listOf("OS" to "windows10")) shouldBe FileCollectionTools.PathStyle.WINDOWS
            FileCollectionTools.styleFor(emptyList()) shouldBe FileCollectionTools.PathStyle.WINDOWS
            FileCollectionTools.styleFor(listOf("Device name" to "x")) shouldBe FileCollectionTools.PathStyle.WINDOWS
            FileCollectionTools.styleFor(listOf("OS" to "Linux")) shouldBe FileCollectionTools.PathStyle.POSIX
            FileCollectionTools.styleFor(listOf("OS" to "macOS 14.5")) shouldBe FileCollectionTools.PathStyle.POSIX
            FileCollectionTools.styleFor(listOf("OS" to "Ubuntu 22.04")) shouldBe FileCollectionTools.PathStyle.POSIX
        }

        test("a comment of exactly the minimum length is accepted") {
            val r = FileRig()
            r.collect(comment = "INC-123456").failed shouldBe false
            r.posts shouldHaveSize 1
        }

        test("the POST is never retried on a transient error (not idempotent)") {
            val r = FileRig()
            r.post = { Canned(HttpStatusCode.ServiceUnavailable, """{"error":{"code":"ServiceUnavailable"}}""") }
            r.collect().failed shouldBe true
            r.posts shouldHaveSize 1
        }
    }

    context("defender_collect_file: refusals send no POST") {
        withData(nameFn = { "denied: $it" }, DENIED_PATHS) { path ->
            val r = FileRig()
            val res = r.collect(path = path)
            res.failed shouldBe true
            res.text() shouldContain "credential or secret store"
            r.approver.asked shouldBe 0
            r.fake.recorded.shouldBeEmpty()
        }

        withData(nameFn = { "malformed: ${it.second}" }, MALFORMED_PATHS) { (path, _) ->
            val r = FileRig()
            val res = r.collect(path = path)
            res.failed shouldBe true
            res.text() shouldContain "path"
            r.approver.asked shouldBe 0
            r.fake.recorded.shouldBeEmpty()
        }

        withData(nameFn = { "denied Windows ${it.first}" }, WINDOWS_DENIED_CATEGORIES) { (_, path) ->
            val e = runCatching { FileCollectionTools.validatePath(path, FileCollectionTools.PathStyle.WINDOWS) }.exceptionOrNull()
            (e is IllegalArgumentException) shouldBe true
            e!!.message!! shouldContain "credential or secret store"
            val r = FileRig()
            val res = r.collect(path = path)
            res.failed shouldBe true
            res.text() shouldContain "credential or secret store"
            r.approver.asked shouldBe 0
            r.fake.recorded.shouldBeEmpty()
        }

        withData(nameFn = { "denied POSIX ${it.first}" }, POSIX_DENIED_CATEGORIES) { (_, path) ->
            val e = runCatching { FileCollectionTools.validatePath(path, FileCollectionTools.PathStyle.POSIX) }.exceptionOrNull()
            (e is IllegalArgumentException) shouldBe true
            e!!.message!! shouldContain "credential or secret store"
            val r = FileRig()
            r.machine = { Canned(body = LINUX_MACHINE_JSON) }
            val res = r.collect(path = path)
            res.failed shouldBe true
            res.text() shouldContain "credential or secret store"
            r.approver.asked shouldBe 0
            r.fake.recorded.shouldBeEmpty()
        }

        test("validatePath returns the trimmed path for ordinary files in their own style") {
            val win = FileCollectionTools.PathStyle.WINDOWS
            val posix = FileCollectionTools.PathStyle.POSIX
            FileCollectionTools.validatePath(" C:\\Users\\Public\\Downloads\\invoice.pdf.exe ", win) shouldBe "C:\\Users\\Public\\Downloads\\invoice.pdf.exe"
            FileCollectionTools.validatePath("C:\\Program Files (x86)\\Vendor App\\agent.exe", win) shouldBe "C:\\Program Files (x86)\\Vendor App\\agent.exe"
            FileCollectionTools.validatePath("C:\\Windows\\System32\\drivers\\etc\\hosts", win) shouldBe "C:\\Windows\\System32\\drivers\\etc\\hosts"
            FileCollectionTools.validatePath("C:\\Users\\bob\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\x.lnk", win) shouldBe
                "C:\\Users\\bob\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\x.lnk"
            FileCollectionTools.validatePath("C:\\Users\\bob\\.vscode\\argv.json", win) shouldBe "C:\\Users\\bob\\.vscode\\argv.json"
            FileCollectionTools.validatePath("/var/log/auth.log", posix) shouldBe "/var/log/auth.log"
            FileCollectionTools.validatePath("/home/alice/sshd_config", posix) shouldBe "/home/alice/sshd_config"
            FileCollectionTools.validatePath("/etc/passwd", posix) shouldBe "/etc/passwd"
            FileCollectionTools.validatePath("/tmp/.hidden/dropper.sh", posix) shouldBe "/tmp/.hidden/dropper.sh"
        }

        test("validatePath refuses a path in the other style") {
            for ((path, style) in listOf(
                WIN_PATH to FileCollectionTools.PathStyle.POSIX,
                "/tmp/payload" to FileCollectionTools.PathStyle.WINDOWS,
            )) {
                runCatching { FileCollectionTools.validatePath(path, style) }.isFailure shouldBe true
            }
        }

        withData(
            nameFn = { "non-canonical Windows: ${it.first}" },
            "forward slashes" to "C:/Windows/System32/config/SAM",
            "mixed separators" to "C:\\Windows/System32/config/SAM",
            "mixed separators, hive only" to "C:\\Windows\\System32\\config/SAM",
            "doubled backslash" to "C:\\Windows\\System32\\config\\\\SAM",
            "doubled backslash after root" to "C:\\\\Windows\\System32\\config\\SAM",
            "::\$DATA stream" to "C:\\Windows\\System32\\config\\SAM::\$DATA",
            "named stream" to "C:\\Users\\Public\\payload.exe:hidden",
            "NTDS ::\$DATA" to "C:\\Windows\\NTDS\\ntds.dit::\$DATA",
            "trailing dot on folder" to "C:\\Windows\\System32\\config.\\SAM",
            "trailing dot on file" to "C:\\Windows\\System32\\config\\SAM.",
            "trailing space on folder" to "C:\\Windows\\System32\\config \\SAM",
            "8.3 folder" to "C:\\WINDOW~1\\SYSTEM~1\\config\\SAM",
            "8.3 file" to "C:\\Users\\bob\\NTUSER~1.DAT",
            "8.3 browser folder" to "C:\\Users\\bob\\AppData\\Local\\Google\\Chrome\\USERDA~1\\Default\\Login Data",
            "environment variable" to "C:\\Users\\%USERNAME%\\NTUSER.DAT",
            "PowerShell variable" to "C:\\Users\\\$env\\x",
        ) { (_, path) ->
            runCatching { FileCollectionTools.validatePath(path, FileCollectionTools.PathStyle.WINDOWS) }.isFailure shouldBe true
            val r = FileRig()
            val res = r.collect(path = path)
            res.failed shouldBe true
            res.text() shouldContain "path"
            r.approver.asked shouldBe 0
            r.posts.shouldBeEmpty()
            r.fake.recorded.shouldBeEmpty()
        }

        withData(
            nameFn = { "non-canonical POSIX: ${it.first}" },
            "leading //" to "//etc/shadow",
            "doubled slash" to "/etc//shadow",
            "trailing slash" to "/etc/shadow/",
            "backslash" to "/etc\\shadow",
            "dot segment" to "/etc/./shadow",
            "dot-dot segment" to "/tmp/../etc/shadow",
        ) { (_, path) ->
            runCatching { FileCollectionTools.validatePath(path, FileCollectionTools.PathStyle.POSIX) }.isFailure shouldBe true
            val r = FileRig()
            r.machine = { Canned(body = LINUX_MACHINE_JSON) }
            val res = r.collect(path = path)
            res.failed shouldBe true
            res.text() shouldContain "path"
            r.approver.asked shouldBe 0
            r.posts.shouldBeEmpty()
            r.fake.recorded.shouldBeEmpty()
        }

        // Regression: the deny-list used to match only the canonical spelling of a path, while Windows and Linux both
        // normalise other spellings to the same file (forward slashes, doubled separators, ::$DATA, trailing dots).
        test("regression: alternative spellings of credential stores are refused before any request") {
            val variants = listOf(
                "C:/Windows/System32/config/SAM",
                "C:\\Windows/System32/config/SAM",
                "C:\\Windows\\System32\\config\\\\SAM",
                "C:\\Windows\\System32\\config\\SAM::\$DATA",
                "C:\\Windows\\NTDS\\ntds.dit::\$DATA",
                "C:\\Windows\\System32\\config.\\SAM",
                "C:\\WINDOW~1\\SYSTEM~1\\config\\SAM",
                "/etc//shadow",
                "//etc/shadow",
            )
            for (path in variants) {
                val r = FileRig()
                val res = r.collect(path = path)
                withClue(path) {
                    res.failed shouldBe true
                    r.approver.asked shouldBe 0
                    r.posts.shouldBeEmpty()
                    r.fake.recorded.shouldBeEmpty()
                }
            }
        }

        // Regression: '/Windows/System32/config/SAM' is a valid POSIX path, but a Windows device resolves it on the
        // system drive, so the device's OS (not the path's look) decides which rules apply.
        test("regression: a '/'-rooted path to a Windows credential store is refused before any request, for any device") {
            // Windows resolves '/'-rooted paths on the system drive, so these must be refused in both readings.
            for (path in listOf("/Windows/System32/config/SAM", "/Windows/NTDS/ntds.dit", "/Users/bob/NTUSER.DAT")) {
                val r = FileRig()
                val res = r.collect(path = path)
                withClue(path) {
                    res.failed shouldBe true
                    res.text() shouldContain "credential or secret store"
                    r.approver.asked shouldBe 0
                    r.posts.shouldBeEmpty()
                    r.fake.apiRequests.shouldBeEmpty()
                }
            }
        }

        test("a harmless '/'-rooted path is refused for a Windows device after the OS lookup") {
            val r = FileRig()
            val res = r.collect(path = "/tmp/payload.exe")
            res.failed shouldBe true
            res.text() shouldContain "absolute Windows path"
            r.posts.shouldBeEmpty()
            r.fake.apiRequests.map { it.path } shouldContainExactly listOf("/api/machines/$MACHINE_ID")
        }

        test("the same harmless '/'-rooted path is collected from a Linux device") {
            val r = FileRig()
            r.machine = { Canned(body = LINUX_MACHINE_JSON) }
            r.collect(path = "/tmp/payload.exe").failed shouldBe false
            r.posts shouldHaveSize 1
        }

        // BUG: macOS file systems are case-insensitive by default and /etc and /var are symlinks to /private/etc and
        // /private/var there, but the POSIX deny-list (FileCollectionTools.kt:56-68) is case-sensitive (except
        // Library/Keychains) and anchored at /etc and /var. Each path below reaches a secret store on a Mac.
        test("regression: macOS case-insensitive and /private spellings of secret stores are refused") {
            for (path in listOf(
                "/Users/alice/.SSH/id_rsa",
                "/Users/alice/.AWS/credentials",
                "/private/etc/master.passwd",
                "/private/var/db/dslocal/nodes/Default/users/alice.plist",
                "/private/var/db/shadow/hash/ABCDEF",
                "/ETC/MASTER.PASSWD",
            )) {
                val r = FileRig()
                r.machine = { Canned(body = MAC_MACHINE_JSON) }
                withClue(path) {
                    r.collect(path = path).failed shouldBe true
                    r.posts.shouldBeEmpty()
                }
            }
        }

        // BUG: shadow-utils keeps the previous /etc/shadow and /etc/gshadow as /etc/shadow- and /etc/gshadow-
        // (same hashes, root-only), but the deny-list (FileCollectionTools.kt:59) only matches the exact names.
        test("regression: the shadow backups /etc/shadow- and /etc/gshadow- are refused") {
            for (path in listOf("/etc/shadow-", "/etc/gshadow-")) {
                val r = FileRig()
                r.machine = { Canned(body = LINUX_MACHINE_JSON) }
                withClue(path) {
                    r.collect(path = path).failed shouldBe true
                    r.posts.shouldBeEmpty()
                }
            }
        }

        test("a comment shorter than 10 characters is refused before any request") {
            for (short in listOf("too short", "  abc     ", "abc\u200B\u200B\u200B\u200B\u200B\u200B\u200B", " ")) {
                val r = FileRig()
                r.collect(comment = short).failed shouldBe true
                r.fake.recorded.shouldBeEmpty()
            }
        }

        test("a malformed machine ID is refused before any request") {
            for (bad in listOf("not-a-machine", "$MACHINE_ID/../x", MACHINE_ID.dropLast(1))) {
                val r = FileRig()
                r.collect(id = bad).failed shouldBe true
                r.fake.recorded.shouldBeEmpty()
            }
        }

        test("a device carrying a protected tag is refused and the refusal is audited") {
            val r = FileRig(protectedTags = setOf("tier0"))
            r.machine = { Canned(body = """{"computerDnsName":"dc01","machineTags":["Finance"," TIER0 "]}""") }
            val res = r.collect()
            res.failed shouldBe true
            res.text() shouldContain "protected tag"
            r.approver.asked shouldBe 0
            r.posts.shouldBeEmpty()
            r.audit.lines.single() shouldContain "refused_protected_tag"
        }

        withData(
            nameFn = { it.first },
            "device not found" to Canned(HttpStatusCode.NotFound, """{"error":{"code":"ResourceNotFound"}}"""),
            "device lookup forbidden" to Canned(HttpStatusCode.Forbidden, """{"error":{"code":"Forbidden"}}"""),
            "device record unreadable" to Canned(body = "<html/>", contentType = "text/html"),
        ) { (_, canned) ->
            val r = FileRig()
            r.machine = { canned }
            val res = r.collect()
            res.failed shouldBe true
            res.text() shouldContain "Refused"
            r.approver.asked shouldBe 0
            r.posts.shouldBeEmpty()
        }

        test("declined: no POST") {
            val r = FileRig(outcome = ApprovalOutcome.DECLINED)
            val res = r.collect()
            res.failed shouldBe true
            res.text() shouldContain "declined"
            r.approver.asked shouldBe 1
            r.posts.shouldBeEmpty()
        }

        test("the write level cannot collect files") {
            val r = FileRig(access = AccessLevel.WRITE)
            r.collect().text() shouldContain "not permitted"
            r.fake.recorded.shouldBeEmpty()
        }
    }

    context("live response rate bucket") {
        test("collect_file paces its POSTs at 10 per minute, separately from the device lookups") {
            val now = AtomicLong(0)
            val sleeps = Collections.synchronizedList(mutableListOf<Long>())
            val r = FileRig(maxActions = 50, clock = { now.get() }, sleep = { sleeps += it; now.addAndGet(it) })
            repeat(10) { r.collect().failed shouldBe false }
            sleeps.shouldBeEmpty()
            r.collect().failed shouldBe false
            sleeps shouldContainExactly listOf(60_000L)
            r.posts shouldHaveSize 11
        }

        test("LIVE_RESPONSE allows ten calls a minute, independent of DEFAULT and PACKAGE_URI") {
            val now = AtomicLong(0)
            val sleeps = Collections.synchronizedList(mutableListOf<Long>())
            val fake: FakeDefender = FakeDefender()
            val client = DefenderClient(testConfig(), fake.engine, clock = { now.get() }, sleep = { sleeps += it; now.addAndGet(it) })
            repeat(10) { client.request(HttpMethod.Post, "/api/machines/$MACHINE_ID/runliveresponse", bucket = RateBucket.LIVE_RESPONSE) }
            repeat(2) { client.get("/api/machineactions/$ACTION_ID/getPackageUri", bucket = RateBucket.PACKAGE_URI) }
            repeat(20) { client.get("/api/machines") }
            sleeps.shouldBeEmpty()
            client.request(HttpMethod.Post, "/api/machines/$MACHINE_ID/runliveresponse", bucket = RateBucket.LIVE_RESPONSE)
            sleeps shouldContainExactly listOf(60_000L)
            // A minute later the window has room again.
            repeat(9) { client.request(HttpMethod.Post, "/api/machines/$MACHINE_ID/runliveresponse", bucket = RateBucket.LIVE_RESPONSE) }
            sleeps shouldHaveSize 1
            RateBucket.entries shouldContain RateBucket.LIVE_RESPONSE
        }
    }

    context("defender_get_collected_file_link") {
        test("approved: looks the action up, shows its facts, then GETs GetLiveResponseResultDownloadLink(index=0); the link is fenced") {
            val r = FileRig(access = AccessLevel.WRITE)
            val res = r.link(ACTION_ID.uppercase())
            res.failed shouldBe false
            r.approver.asked shouldBe 1
            r.message shouldContain "Action: Reveal the download link for file '$WIN_PATH' collected by machine action $ACTION_ID"
            r.message shouldContain "- Machine action ID (supplied by the AI): \"$ACTION_ID\""
            r.message shouldContain "- Path: \"$WIN_PATH\""
            r.message shouldContain "- Device name: \"ws-042.contoso.local\""
            r.message shouldContain "- Collected by: \"analyst@contoso.com\""
            r.message shouldContain "- Collected at: \"2026-11-12T10:00:00Z\""
            r.fake.apiRequests shouldHaveSize 2
            r.fake.apiRequests.first().request.method shouldBe HttpMethod.Get
            r.fake.apiRequests.first().path shouldBe "/api/machineactions/$ACTION_ID"
            r.fake.last.request.method shouldBe HttpMethod.Get
            r.fake.last.request.url.toString() shouldContain "/api/machineactions/$ACTION_ID/GetLiveResponseResultDownloadLink(index=0)"
            r.fake.last.body.shouldBeNull()
            res.text() shouldContain "UNTRUSTED_DEFENDER_DATA"
            res.text() shouldContain "blob.example"
            r.audit.lines.single() shouldContain "defender_get_collected_file_link"
        }

        test("a POSIX collection, the flat command shape and case-insensitive type/status/key all qualify") {
            val r = FileRig(access = AccessLevel.WRITE)
            r.action = {
                Canned(
                    body = """{"id":"$ACTION_ID","type":"liveresponse","status":"succeeded",
                    "commands":[{"type":"getfile","params":[{"key":"path","value":"/tmp/.x/dropper.sh"}]}]}""",
                )
            }
            r.link().failed shouldBe false
            r.message shouldContain "file '/tmp/.x/dropper.sh'"
            r.message shouldNotContain "Device name"
            r.linkRequests shouldHaveSize 1
        }

        test("declined: only the lookup is sent, so no link is revealed") {
            val r = FileRig(access = AccessLevel.WRITE, outcome = ApprovalOutcome.DECLINED)
            val res = r.link()
            res.failed shouldBe true
            res.text() shouldNotContain "blob.example"
            r.approver.asked shouldBe 1
            r.fake.apiRequests.map { it.path } shouldContainExactly listOf("/api/machineactions/$ACTION_ID")
            r.linkRequests.shouldBeEmpty()
        }

        withData(
            nameFn = { "lookup fails closed: ${it.first}" },
            "HTTP 404" to Canned(HttpStatusCode.NotFound, """{"error":{"code":"ResourceNotFound"}}"""),
            "HTTP 403" to Canned(HttpStatusCode.Forbidden, """{"error":{"code":"Forbidden"}}"""),
            "HTTP 500" to Canned(HttpStatusCode.InternalServerError, """{"error":{"code":"InternalError"}}"""),
            "not JSON" to Canned(body = "<html/>", contentType = "text/html"),
            "a JSON array" to Canned(body = """[${getFileAction()}]"""),
            "an empty object" to Canned(body = "{}"),
        ) { (_, canned) ->
            val r = FileRig(access = AccessLevel.WRITE)
            r.action = { canned }
            val res = r.link()
            res.failed shouldBe true
            res.text() shouldContain "Refused"
            res.text() shouldNotContain "blob.example"
            r.approver.asked shouldBe 0
            r.linkRequests.shouldBeEmpty()
        }

        test("a lookup that fails is reported as such") {
            val r = FileRig(access = AccessLevel.WRITE)
            r.action = { Canned(HttpStatusCode.NotFound, "{}") }
            r.link().text() shouldContain "could not be looked up"
        }

        withData(
            nameFn = { "not a single GetFile: ${it.first}" },
            "type Isolate" to getFileAction(type = "Isolate"),
            "type RunAntiVirusScan" to getFileAction(type = "RunAntiVirusScan"),
            "no type" to """{"id":"$ACTION_ID","status":"Succeeded","commands":[{"command":{"type":"GetFile","params":[{"key":"Path","value":"C:\\Temp\\a.exe"}]}}]}""",
            "a RunScript command" to getFileAction(commandType = "RunScript"),
            "a PutFile command" to getFileAction(commandType = "PutFile"),
            "two GetFile commands" to """{"id":"$ACTION_ID","type":"LiveResponse","status":"Succeeded","commands":[
                {"command":{"type":"GetFile","params":[{"key":"Path","value":"C:\\Temp\\a.exe"}]}},
                {"command":{"type":"GetFile","params":[{"key":"Path","value":"C:\\Temp\\b.exe"}]}}]}""",
            "GetFile then RunScript" to """{"id":"$ACTION_ID","type":"LiveResponse","status":"Succeeded","commands":[
                {"command":{"type":"GetFile","params":[{"key":"Path","value":"C:\\Temp\\a.exe"}]}},
                {"command":{"type":"RunScript","params":[{"key":"ScriptName","value":"dump.ps1"}]}}]}""",
            "no commands" to """{"id":"$ACTION_ID","type":"LiveResponse","status":"Succeeded","commands":[]}""",
            "commands missing" to """{"id":"$ACTION_ID","type":"LiveResponse","status":"Succeeded"}""",
            "commands not an array" to """{"id":"$ACTION_ID","type":"LiveResponse","status":"Succeeded","commands":"GetFile"}""",
            "command entry not an object" to """{"id":"$ACTION_ID","type":"LiveResponse","status":"Succeeded","commands":["GetFile"]}""",
            "no Path param" to """{"id":"$ACTION_ID","type":"LiveResponse","status":"Succeeded","commands":[
                {"command":{"type":"GetFile","params":[{"key":"Other","value":"C:\\Temp\\a.exe"}]}}]}""",
            "params missing" to """{"id":"$ACTION_ID","type":"LiveResponse","status":"Succeeded","commands":[{"command":{"type":"GetFile"}}]}""",
            "blank Path" to getFileAction(path = "  "),
        ) { (_, body) ->
            val r = FileRig(access = AccessLevel.WRITE)
            r.action = { Canned(body = body) }
            val res = r.link()
            res.failed shouldBe true
            res.text() shouldContain "Refused"
            res.text() shouldNotContain "blob.example"
            r.approver.asked shouldBe 0
            r.linkRequests.shouldBeEmpty()
        }

        withData(
            nameFn = { "collected path refused: $it" },
            "C:\\Windows\\System32\\config\\SAM",
            "C:\\Windows\\NTDS\\ntds.dit",
            "C:\\Users\\bob\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data",
            "C:/Windows/System32/config/SAM",
            "C:\\Windows\\System32\\config\\SAM::\$DATA",
            "C:\\WINDOW~1\\SYSTEM~1\\config\\SAM",
            "C:\\Windows\\System32\\config.\\SAM",
            "/etc/shadow",
            "//etc/shadow",
            "/etc//shadow",
            "/root/.ssh/id_rsa",
            "payload.exe",
        ) { path ->
            val r = FileRig(access = AccessLevel.WRITE)
            r.action = { Canned(body = getFileAction(path = path)) }
            val res = r.link()
            res.failed shouldBe true
            res.text() shouldContain "Refused"
            res.text() shouldNotContain "blob.example"
            r.approver.asked shouldBe 0
            r.linkRequests.shouldBeEmpty()
        }

        withData(nameFn = { "status '$it' is not Succeeded" }, "Pending", "InProgress", "Failed", "Cancelled", "TimeOut", "") { status ->
            val r = FileRig(access = AccessLevel.WRITE)
            r.action = { Canned(body = getFileAction(status = status)) }
            val res = r.link()
            res.failed shouldBe true
            res.text() shouldContain "has not succeeded yet"
            r.approver.asked shouldBe 0
            r.linkRequests.shouldBeEmpty()
        }

        test("getFilePath extracts the path only from the exact shape collect_file creates") {
            fun parse(s: String) = kotlinx.serialization.json.Json.parseToJsonElement(s).jsonObject
            FileCollectionTools.getFilePath(parse(getFileAction())) shouldBe WIN_PATH
            FileCollectionTools.getFilePath(
                parse("""{"type":"LiveResponse","commands":[{"type":"GetFile","params":[{"key":"Other","value":"x"},{"key":"Path","value":"/tmp/a"}]}]}"""),
            ) shouldBe "/tmp/a"
            FileCollectionTools.getFilePath(parse(getFileAction(commandType = "RunScript"))).shouldBeNull()
            FileCollectionTools.getFilePath(parse(getFileAction(type = "Isolate"))).shouldBeNull()
            FileCollectionTools.getFilePath(parse("""{"type":"LiveResponse"}""")).shouldBeNull()
            FileCollectionTools.getFilePath(parse("""{"type":"LiveResponse","commands":[{"type":"GetFile","params":"x"}]}""")).shouldBeNull()
        }

        // BUG: get_collected_file_link picks the path style from the path's first character
        // (FileCollectionTools.kt:208), not from the device's OS as collect_file does. A '/'-rooted path collected from a
        // Windows device in the portal ('/Windows/System32/config/SAM' resolves to C:\Windows\...\SAM there) passes the
        // POSIX rules, so the link to the SAM hive is revealed.
        test("regression: a '/'-rooted Windows hive collected from a Windows device is not revealed") {
            val r = FileRig(access = AccessLevel.WRITE)
            r.action = {
                Canned(
                    body = """{"id":"$ACTION_ID","type":"LiveResponse","status":"Succeeded","machineId":"$MACHINE_ID",
                    "commands":[{"command":{"type":"GetFile","params":[{"key":"Path","value":"/Windows/System32/config/SAM"}]}}]}""",
                )
            }
            r.link().failed shouldBe true
            r.linkRequests.shouldBeEmpty()
        }

        test("a non-GUID action ID is refused before approval") {
            for (bad in listOf("123", "$ACTION_ID/../x", "zzzzzzzz-8b36-4c0c-9b8b-0f6b1f0f4c11", "")) {
                val r = FileRig(access = AccessLevel.WRITE)
                r.link(bad).failed shouldBe true
                r.approver.asked shouldBe 0
                r.fake.recorded.shouldBeEmpty()
            }
        }

        test("read-only servers refuse it") {
            val r = FileRig(access = AccessLevel.READ_ONLY)
            r.link().text() shouldContain "not permitted"
            r.approver.asked shouldBe 0
            r.fake.recorded.shouldBeEmpty()
        }
    }
})
