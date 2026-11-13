package com.jitunicornfx.defender.mcp

import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.datatest.withData
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldContainExactly
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotContain
import io.kotest.matchers.string.shouldStartWith
import io.kotest.property.Arb
import io.kotest.property.arbitrary.Codepoint
import io.kotest.property.arbitrary.alphanumeric
import io.kotest.property.arbitrary.arbitrary
import io.kotest.property.arbitrary.az
import io.kotest.property.arbitrary.element
import io.kotest.property.arbitrary.enum
import io.kotest.property.arbitrary.int
import io.kotest.property.arbitrary.list
import io.kotest.property.arbitrary.long
import io.kotest.property.arbitrary.string
import io.kotest.property.checkAll

private const val TENANT = "11111111-2222-3333-4444-555555555555"
private const val CLIENT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
private const val SECRET = "s3cr3t-Value~with.chars"

private fun creds(secret: String = SECRET) = EntraCredentials(TENANT, CLIENT, secret)

private fun baseEnv(): MutableMap<String, String> = mutableMapOf(
    Config.ENV_TENANT_ID to TENANT,
    Config.ENV_CLIENT_ID to CLIENT,
    Config.ENV_CLIENT_SECRET to SECRET,
)

private fun env(vararg extra: Pair<String, String>): Map<String, String> = baseEnv().apply { putAll(extra) }

private fun hexChars() = ('0'..'9') + ('a'..'f') + ('A'..'F')

private fun guidArbSimple(): Arb<String> = arbitrary { rs ->
    val chars = hexChars()
    fun block(n: Int) = (1..n).joinToString("") { chars[rs.random.nextInt(chars.size)].toString() }
    "${block(8)}-${block(4)}-${block(4)}-${block(4)}-${block(12)}"
}

class ConfigSpec : FunSpec({

    context("CloudEnvironment") {
        test("each environment pins login, api, scope and graph hosts consistently") {
            CloudEnvironment.COMMERCIAL.loginBaseUrl shouldBe "https://login.microsoftonline.com"
            CloudEnvironment.COMMERCIAL.apiBaseUrl shouldBe "https://api.security.microsoft.com"
            CloudEnvironment.COMMERCIAL.scope shouldBe "https://api.securitycenter.microsoft.com/.default"
            CloudEnvironment.COMMERCIAL.graphScope shouldBe "https://graph.microsoft.com/.default"
            CloudEnvironment.GCC.graphScope shouldBe "https://graph.microsoft.com/.default"
            CloudEnvironment.GCC_HIGH.loginBaseUrl shouldBe "https://login.microsoftonline.us"
            CloudEnvironment.GCC_HIGH.graphScope shouldBe "https://graph.microsoft.us/.default"
            CloudEnvironment.DOD.graphScope shouldBe "https://dod-graph.microsoft.us/.default"
            CloudEnvironment.DOD.scope shouldBe "https://api-gov.securitycenter.microsoft.us/.default"
        }

        test("every environment's api base is https on a Microsoft host") {
            CloudEnvironment.entries.forEach { it.apiBaseUrl shouldStartWith "https://api" }
        }

        test("government clouds never use the commercial login authority") {
            listOf(CloudEnvironment.GCC_HIGH, CloudEnvironment.DOD).forEach {
                it.loginBaseUrl shouldNotContain ".com"
                it.apiBaseUrl shouldNotContain ".com"
                it.scope shouldNotContain ".com"
            }
        }

        withData(
            nameFn = { "fromCode(${it.first})" },
            "commercial" to CloudEnvironment.COMMERCIAL,
            "GCC" to CloudEnvironment.GCC,
            "  gcc-high  " to CloudEnvironment.GCC_HIGH,
            "DoD" to CloudEnvironment.DOD,
        ) { (code, expected) -> CloudEnvironment.fromCode(code) shouldBe expected }

        test("fromCode rejects unknown codes listing valid values") {
            val e = shouldThrow<IllegalArgumentException> { CloudEnvironment.fromCode("gcc_high") }
            e.message shouldContain "Unknown cloud 'gcc_high'"
            e.message shouldContain "commercial, gcc, gcc-high, dod"
        }
    }

    context("AccessLevel.permits") {
        test("explicit matrix") {
            AccessLevel.READ_ONLY.permits(AccessLevel.READ_ONLY) shouldBe true
            AccessLevel.READ_ONLY.permits(AccessLevel.WRITE) shouldBe false
            AccessLevel.READ_ONLY.permits(AccessLevel.DESTRUCTIVE) shouldBe false
            AccessLevel.WRITE.permits(AccessLevel.READ_ONLY) shouldBe true
            AccessLevel.WRITE.permits(AccessLevel.WRITE) shouldBe true
            AccessLevel.WRITE.permits(AccessLevel.DESTRUCTIVE) shouldBe false
            AccessLevel.DESTRUCTIVE.permits(AccessLevel.DESTRUCTIVE) shouldBe true
            AccessLevel.DESTRUCTIVE.permits(AccessLevel.READ_ONLY) shouldBe true
        }

        test("property: permits is reflexive and matches ordering") {
            checkAll(Arb.enum<AccessLevel>(), Arb.enum<AccessLevel>()) { a, b ->
                a.permits(a) shouldBe true
                a.permits(b) shouldBe (a.ordinal >= b.ordinal)
                if (a != b) (a.permits(b) && b.permits(a)) shouldBe false
            }
        }
    }

    test("enum value sets") {
        ConfirmationMode.entries.map { it.name } shouldContainExactly listOf("ELICIT", "NONE")
    }

    context("EntraCredentials") {
        test("toString redacts the secret") {
            val c = creds("SuperSecretValue123")
            c.toString() shouldBe "EntraCredentials(tenantId=$TENANT, clientId=$CLIENT, clientSecret=***)"
            c.toString() shouldNotContain "SuperSecretValue123"
        }

        test("data class semantics still use the secret") {
            creds("a") shouldBe creds("a")
            (creds("a") == creds("b")) shouldBe false
            creds("a").copy(clientSecret = "z").clientSecret shouldBe "z"
        }

        test("property: secret never appears in toString") {
            checkAll(Arb.string(8..40, Codepoint.alphanumeric())) { s ->
                val str = EntraCredentials("contoso.com", CLIENT, "X$s").toString()
                str shouldNotContain "X$s"
            }
        }
    }

    context("Config construction") {
        test("defaults") {
            val c = Config(creds())
            c.cloud shouldBe CloudEnvironment.COMMERCIAL
            c.apiBaseUrl shouldBe CloudEnvironment.COMMERCIAL.apiBaseUrl
            c.accessLevel shouldBe AccessLevel.READ_ONLY
            c.confirmation shouldBe ConfirmationMode.ELICIT
            c.requestTimeoutMillis shouldBe Config.DEFAULT_TIMEOUT_MS
            c.maxResponseBytes shouldBe Config.DEFAULT_MAX_RESPONSE_BYTES
            c.maxResultChars shouldBe Config.DEFAULT_MAX_RESULT_CHARS
            c.maxActionsPerHour shouldBe Config.DEFAULT_MAX_ACTIONS_PER_HOUR
            c.maxConcurrentRequests shouldBe Config.DEFAULT_MAX_CONCURRENT_REQUESTS
            c.httpAuthToken shouldBe null
            c.httpAllowedOrigins.shouldBeEmpty()
            c.toolGlobs.shouldBeEmpty()
        }

        test("apiBaseUrl defaults to the chosen cloud's host") {
            Config(creds(), cloud = CloudEnvironment.GCC_HIGH).apiBaseUrl shouldBe CloudEnvironment.GCC_HIGH.apiBaseUrl
        }

        test("boundary values accepted") {
            shouldNotThrowAny {
                Config(creds(), maxResultChars = Config.MIN_RESULT_CHARS, maxResponseBytes = 1024,
                    requestTimeoutMillis = 1_000, maxActionsPerHour = 0, maxConcurrentRequests = 1)
                Config(creds(), requestTimeoutMillis = 600_000, maxActionsPerHour = 10_000, maxConcurrentRequests = 64)
            }
        }

        withData(
            nameFn = { it.first.first },
            "maxResultChars too small" to { Config(creds(), maxResultChars = Config.MIN_RESULT_CHARS - 1) } to "max result chars",
            "maxResponseBytes too small" to { Config(creds(), maxResponseBytes = 1023) } to "max response bytes",
            "timeout too small" to { Config(creds(), requestTimeoutMillis = 999) } to "timeout",
            "timeout too large" to { Config(creds(), requestTimeoutMillis = 600_001) } to "timeout",
            "actions negative" to { Config(creds(), maxActionsPerHour = -1) } to "max actions per hour",
            "actions too large" to { Config(creds(), maxActionsPerHour = 10_001) } to "max actions per hour",
            "concurrency zero" to { Config(creds(), maxConcurrentRequests = 0) } to "max concurrent requests",
            "concurrency too large" to { Config(creds(), maxConcurrentRequests = 65) } to "max concurrent requests",
            "region on a government cloud" to { Config(creds(), cloud = CloudEnvironment.DOD, region = DefenderRegion.EU) } to Config.ENV_REGION,
        ) { (pair, msg) ->
            val e = shouldThrow<IllegalArgumentException> { pair.second() }
            e.message shouldContain msg
        }

        test("property: timeouts outside range rejected, inside accepted") {
            checkAll(Arb.long(-1_000_000L..2_000_000L)) { t ->
                val r = runCatching { Config(creds(), requestTimeoutMillis = t) }
                r.isSuccess shouldBe (t in 1_000..600_000)
            }
        }

        test("toString redacts auth token and secret but shows other fields") {
            val c = Config(creds("TopSecretClientValue"), httpAuthToken = "BearerTokenValueXYZ",
                httpAllowedOrigins = listOf("https://a.example"), toolGlobs = listOf("defender_*"))
            val s = c.toString()
            s shouldNotContain "BearerTokenValueXYZ"
            s shouldNotContain "TopSecretClientValue"
            s shouldContain "httpAuthToken=***"
            s shouldContain "clientSecret=***"
            s shouldContain "cloud=commercial"
            s shouldContain "region=global, apiBaseUrl=https://api.security.microsoft.com"
            s shouldContain "httpAllowedOrigins=[https://a.example]"
            s shouldContain "toolGlobs=[defender_*]"
            s shouldStartWith "Config(credentials=EntraCredentials("
        }

        test("toString shows unset when no auth token") {
            Config(creds()).toString() shouldContain "httpAuthToken=unset"
        }

        test("tokenUrl is built from cloud login authority and tenant") {
            Config(creds()).tokenUrl shouldBe "https://login.microsoftonline.com/$TENANT/oauth2/v2.0/token"
            Config(EntraCredentials("contoso.onmicrosoft.us", CLIENT, SECRET), cloud = CloudEnvironment.DOD).tokenUrl shouldBe
                "https://login.microsoftonline.us/contoso.onmicrosoft.us/oauth2/v2.0/token"
        }
    }

    context("DefenderRegion") {
        withData(
            nameFn = { "region ${it.first}" },
            "us" to "https://us.api.security.microsoft.com",
            "eu" to "https://eu.api.security.microsoft.com",
            "uk" to "https://uk.api.security.microsoft.com",
            "au" to "https://au.api.security.microsoft.com",
            "swa" to "https://swa.api.security.microsoft.com",
            "ina" to "https://ina.api.security.microsoft.com",
            "aea" to "https://aea.api.security.microsoft.com",
        ) { (code, url) ->
            val region = DefenderRegion.fromCode(code)
            region.baseUrl shouldBe url
            Config(creds(), region = region).apiBaseUrl shouldBe url
            DefenderRegion.fromCode(" ${code.uppercase()} ") shouldBe region
        }

        test("exactly the seven documented regions exist, all on api.security.microsoft.com") {
            DefenderRegion.entries.map { it.code } shouldContainExactly listOf("us", "eu", "uk", "au", "swa", "ina", "aea")
            DefenderRegion.entries.forEach { it.host shouldBe "${it.code}.api.security.microsoft.com" }
        }

        test("unknown region codes are refused, listing the valid ones") {
            listOf("", "xx", "us-east", "api", "evil.com", "us.evil").forEach { code ->
                shouldThrow<IllegalArgumentException> { DefenderRegion.fromCode(code) }.message shouldContain "us, eu, uk, au, swa, ina, aea"
            }
        }

        test("no region uses the global https://api.security.microsoft.com") {
            Config(creds()).apiBaseUrl shouldBe "https://api.security.microsoft.com"
        }

        test("a region is refused for government clouds") {
            listOf(CloudEnvironment.GCC, CloudEnvironment.GCC_HIGH, CloudEnvironment.DOD).forEach { cloud ->
                shouldThrow<IllegalArgumentException> { Config(creds(), cloud = cloud, region = DefenderRegion.US) }
                    .message shouldContain Config.ENV_REGION
            }
        }
    }

    context("validateTenantId") {
        withData(TENANT, TENANT.uppercase(), "contoso.onmicrosoft.com", "contoso.com", "a-b.c-d.example", "x1.io") {
            Config.validateTenantId(it) shouldBe it
        }
        withData(
            nameFn = { "reject '$it'" },
            "", "contoso", "contoso.com/../evil", "contoso.com?x=1", "contoso.com#a", "a/b.com",
            "-contoso.com", "contoso-.com", "contoso..com", ".contoso.com", "contoso.com.", "con toso.com",
            "common/oauth2", "user@contoso.com", "11111111-2222-3333-4444-55555555555", "conto\nso.com",
            "a".repeat(65) + ".com",
        ) {
            val e = shouldThrow<IllegalArgumentException> { Config.validateTenantId(it) }
            e.message shouldContain Config.ENV_TENANT_ID
        }

        test("property: random GUIDs are valid tenants") {
            checkAll(guidArbSimple()) { Config.validateTenantId(it) shouldBe it }
        }

        test("property: strings containing path or query metacharacters are rejected") {
            checkAll(
                Arb.string(0..10, Codepoint.az()),
                Arb.element("/", "?", "#", "%", "\\", "@", ":", " ", "\u0000"),
            ) { s, bad ->
                shouldThrow<IllegalArgumentException> { Config.validateTenantId("$s$bad.example.com") }
            }
        }
    }

    context("validateClientId") {
        test("accepts GUID") { Config.validateClientId(CLIENT) shouldBe CLIENT }
        withData(nameFn = { "reject '$it'" }, "", "not-a-guid", "contoso.com", "$CLIENT ", "{$CLIENT}", CLIENT.replace('a', 'g')) {
            val e = shouldThrow<IllegalArgumentException> { Config.validateClientId(it) }
            e.message shouldContain Config.ENV_CLIENT_ID
        }
        test("property: random GUIDs accepted") {
            checkAll(guidArbSimple()) { Config.validateClientId(it) shouldBe it }
        }
    }

    context("validateSecret") {
        test("accepts and returns value verbatim including spaces") {
            Config.validateSecret(" pad ") shouldBe " pad "
        }
        test("rejects blank") {
            listOf("", "   ", "\t").forEach {
                shouldThrow<IllegalArgumentException> { Config.validateSecret(it) }.message shouldContain
                    if (it == "\t") "must not be blank" else "must not be blank"
            }
        }
        test("rejects control characters without echoing the secret") {
            val e = shouldThrow<IllegalArgumentException> { Config.validateSecret("abc\u0007defSECRET") }
            e.message shouldContain "control characters"
            e.message shouldNotContain "HUNTER2"
            shouldThrow<IllegalArgumentException> { Config.validateSecret("abc\n") }
        }
    }

    context("csv") {
        test("null and empty") {
            Config.csv(null).shouldBeEmpty()
            Config.csv("").shouldBeEmpty()
            Config.csv(" , ,, ").shouldBeEmpty()
        }
        test("trims and drops empty entries") {
            Config.csv(" a , b,,c ") shouldContainExactly listOf("a", "b", "c")
        }
        test("property: joining trimmed tokens round-trips") {
            checkAll(Arb.list(Arb.string(1..8, Codepoint.alphanumeric()), 0..6)) { items ->
                Config.csv(items.joinToString(" , ")) shouldContainExactly items
            }
        }
    }

    context("parsers") {
        withData(
            nameFn = { "access '${it.first}'" },
            "read" to AccessLevel.READ_ONLY, "read-only" to AccessLevel.READ_ONLY, "READONLY" to AccessLevel.READ_ONLY,
            " read_only " to AccessLevel.READ_ONLY, "Write" to AccessLevel.WRITE, "destructive" to AccessLevel.DESTRUCTIVE,
            "FULL" to AccessLevel.DESTRUCTIVE,
        ) { (v, e) -> Config.parseAccessLevel(v) shouldBe e }

        test("access level rejects unknown") {
            shouldThrow<IllegalArgumentException> { Config.parseAccessLevel("admin") }.message shouldContain "Unknown access level 'admin'"
        }

        withData(
            nameFn = { "confirmation '${it.first}'" },
            "elicit" to ConfirmationMode.ELICIT, "HUMAN" to ConfirmationMode.ELICIT, " on " to ConfirmationMode.ELICIT,
            "none" to ConfirmationMode.NONE, "OFF" to ConfirmationMode.NONE,
        ) { (v, e) -> Config.parseConfirmation(v) shouldBe e }

        test("confirmation rejects unknown (e.g. 'false', 'no')") {
            listOf("false", "no", "0", "").forEach {
                shouldThrow<IllegalArgumentException> { Config.parseConfirmation(it) }.message shouldContain "Unknown confirmation mode"
            }
        }

        test("property: random words outside the vocabulary are rejected by all parsers") {
            val known = setOf("read", "readonly", "write", "destructive", "full", "elicit", "human", "on", "none", "off")
            checkAll(Arb.string(1..10, Codepoint.az())) { w ->
                if (w.lowercase() !in known) {
                    runCatching { Config.parseAccessLevel(w) }.isFailure shouldBe true
                    runCatching { Config.parseConfirmation(w) }.isFailure shouldBe true
                }
            }
        }
    }

    context("fromEnv") {
        test("minimal env yields defaults") {
            val c = Config.fromEnv(baseEnv())
            c shouldBe Config(creds())
            c.httpAuthToken shouldBe null
        }

        test("every variable is honoured") {
            val c = Config.fromEnv(env(
                Config.ENV_CLOUD to "gcc-high",
                Config.ENV_ACCESS_LEVEL to "destructive",
                Config.ENV_CONFIRMATION to "none",
                Config.ENV_TIMEOUT_MS to "30000",
                Config.ENV_MAX_RESPONSE_BYTES to "2048",
                Config.ENV_MAX_RESULT_CHARS to "5000",
                Config.ENV_MAX_ACTIONS_PER_HOUR to "7",
                Config.ENV_MAX_CONCURRENT_REQUESTS to "8",
                Config.ENV_MCP_AUTH_TOKEN to "tok-ABC_123",
                Config.ENV_HTTP_ALLOWED_ORIGINS to "https://a.example, https://b.example",
                Config.ENV_TOOLS to "defender_list_*, defender_get_machine",
            ))
            c.cloud shouldBe CloudEnvironment.GCC_HIGH
            c.apiBaseUrl shouldBe "https://api-gov.securitycenter.microsoft.us"
            c.accessLevel shouldBe AccessLevel.DESTRUCTIVE
            c.confirmation shouldBe ConfirmationMode.NONE
            c.requestTimeoutMillis shouldBe 30_000
            c.maxResponseBytes shouldBe 2048
            c.maxResultChars shouldBe 5000
            c.maxActionsPerHour shouldBe 7
            c.maxConcurrentRequests shouldBe 8
            c.httpAuthToken shouldBe "tok-ABC_123"
            c.httpAllowedOrigins shouldContainExactly listOf("https://a.example", "https://b.example")
            c.toolGlobs shouldContainExactly listOf("defender_list_*", "defender_get_machine")
            c.toString() shouldNotContain "tok-ABC_123"
            c.toString() shouldNotContain SECRET
        }

        test("cloud selection drives default api base url") {
            Config.fromEnv(env(Config.ENV_CLOUD to "dod")).apiBaseUrl shouldBe CloudEnvironment.DOD.apiBaseUrl
            Config.fromEnv(env(Config.ENV_CLOUD to "   ")).cloud shouldBe CloudEnvironment.COMMERCIAL
        }

        test("whitespace is trimmed on non-secret values") {
            val c = Config.fromEnv(mapOf(
                Config.ENV_TENANT_ID to "  $TENANT \n",
                Config.ENV_CLIENT_ID to "\t$CLIENT ",
                Config.ENV_CLIENT_SECRET to SECRET,
                Config.ENV_CLOUD to " GCC ",
                Config.ENV_ACCESS_LEVEL to " write ",
                Config.ENV_TIMEOUT_MS to " 5000 ",
                Config.ENV_MAX_RESULT_CHARS to " 3000 ",
            ))
            c.credentials.tenantId shouldBe TENANT
            c.credentials.clientId shouldBe CLIENT
            c.cloud shouldBe CloudEnvironment.GCC
            c.apiBaseUrl shouldBe "https://api-gcc.securitycenter.microsoft.us"
            c.accessLevel shouldBe AccessLevel.WRITE
            c.requestTimeoutMillis shouldBe 5000
            c.maxResultChars shouldBe 3000
        }

        test("blank optional values fall back to defaults") {
            val c = Config.fromEnv(env(
                Config.ENV_REGION to " ", Config.ENV_ACCESS_LEVEL to "", Config.ENV_CONFIRMATION to " ",
                Config.ENV_TIMEOUT_MS to "  ", Config.ENV_MAX_RESPONSE_BYTES to "",
                Config.ENV_MAX_RESULT_CHARS to "", Config.ENV_MAX_ACTIONS_PER_HOUR to " ", Config.ENV_MAX_CONCURRENT_REQUESTS to "",
                Config.ENV_MCP_AUTH_TOKEN to "", Config.ENV_HTTP_ALLOWED_ORIGINS to "", Config.ENV_TOOLS to " , ",
            ))
            c shouldBe Config(creds())
        }

        test("secret is taken verbatim, not trimmed") {
            Config.fromEnv(env(Config.ENV_CLIENT_SECRET to "  padded secret  ")).credentials.clientSecret shouldBe "  padded secret  "
        }

        test("whitespace-only secret is rejected as blank") {
            shouldThrow<IllegalArgumentException> { Config.fromEnv(env(Config.ENV_CLIENT_SECRET to "   ")) }
                .message shouldContain "must not be blank"
        }

        test("secret with control characters rejected") {
            shouldThrow<IllegalArgumentException> { Config.fromEnv(env(Config.ENV_CLIENT_SECRET to "abc\r\n")) }
                .message shouldContain "control characters"
        }

        withData(
            nameFn = { "missing ${it}" },
            Config.ENV_TENANT_ID, Config.ENV_CLIENT_ID, Config.ENV_CLIENT_SECRET,
        ) { key ->
            val absent = baseEnv().apply { remove(key) }
            shouldThrow<IllegalArgumentException> { Config.fromEnv(absent) }.message shouldBe "$key is required."
            val empty = baseEnv().apply { put(key, "") }
            shouldThrow<IllegalArgumentException> { Config.fromEnv(empty) }.message shouldBe "$key is required."
        }

        test("blank tenant and client id count as missing") {
            shouldThrow<IllegalArgumentException> { Config.fromEnv(env(Config.ENV_TENANT_ID to "   ")) }
                .message shouldBe "${Config.ENV_TENANT_ID} is required."
            shouldThrow<IllegalArgumentException> { Config.fromEnv(env(Config.ENV_CLIENT_ID to "\t")) }
                .message shouldBe "${Config.ENV_CLIENT_ID} is required."
        }

        test("invalid tenant / client id rejected") {
            shouldThrow<IllegalArgumentException> { Config.fromEnv(env(Config.ENV_TENANT_ID to "evil.com/../x")) }
                .message shouldContain Config.ENV_TENANT_ID
            shouldThrow<IllegalArgumentException> { Config.fromEnv(env(Config.ENV_CLIENT_ID to "nope")) }
                .message shouldContain Config.ENV_CLIENT_ID
        }

        withData(
            nameFn = { "non-numeric $it" },
            Config.ENV_TIMEOUT_MS, Config.ENV_MAX_RESPONSE_BYTES, Config.ENV_MAX_RESULT_CHARS,
            Config.ENV_MAX_ACTIONS_PER_HOUR, Config.ENV_MAX_CONCURRENT_REQUESTS,
        ) { key ->
            listOf("abc", "1.5", "10k", "99999999999999999999").forEach { v ->
                shouldThrow<IllegalArgumentException> { Config.fromEnv(env(key to v)) }.message shouldBe "$key must be a whole number."
            }
        }

        test("int fields reject values that only fit a Long") {
            shouldThrow<IllegalArgumentException> { Config.fromEnv(env(Config.ENV_MAX_RESULT_CHARS to "3000000000")) }
                .message shouldBe "${Config.ENV_MAX_RESULT_CHARS} must be a whole number."
        }

        test("out-of-range numbers are rejected by init checks") {
            shouldThrow<IllegalArgumentException> { Config.fromEnv(env(Config.ENV_TIMEOUT_MS to "10")) }.message shouldContain "timeout"
            shouldThrow<IllegalArgumentException> { Config.fromEnv(env(Config.ENV_MAX_CONCURRENT_REQUESTS to "-1")) }
                .message shouldContain "concurrent"
        }

        test("invalid enums and cloud rejected") {
            shouldThrow<IllegalArgumentException> { Config.fromEnv(env(Config.ENV_CLOUD to "mars")) }.message shouldContain "Unknown cloud"
            shouldThrow<IllegalArgumentException> { Config.fromEnv(env(Config.ENV_ACCESS_LEVEL to "root")) }
            shouldThrow<IllegalArgumentException> { Config.fromEnv(env(Config.ENV_CONFIRMATION to "maybe")) }
        }

        test("DEFENDER_REGION selects a regional host; a URL or unknown code is refused") {
            Config.fromEnv(env(Config.ENV_REGION to " EU ")).apiBaseUrl shouldBe "https://eu.api.security.microsoft.com"
            Config.fromEnv(env()).apiBaseUrl shouldBe "https://api.security.microsoft.com"
            shouldThrow<IllegalArgumentException> { Config.fromEnv(env(Config.ENV_REGION to "https://attacker.example/")) }
                .message shouldContain "Unknown region"
            shouldThrow<IllegalArgumentException> { Config.fromEnv(env(Config.ENV_REGION to "us", Config.ENV_CLOUD to "gcc")) }
                .message shouldContain "commercial"
        }

        test("the removed DEFENDER_API_BASE_URL is ignored, so the host cannot be overridden") {
            Config.fromEnv(env("DEFENDER_API_BASE_URL" to "https://attacker.example")).apiBaseUrl shouldBe
                "https://api.security.microsoft.com"
        }

        withData(
            nameFn = { "auth token with ${it.replace("\n", "\\n").replace("\t", "\\t")}" },
            "abc def", " leading", "trailing ", "tab\there", "line\nbreak", "nul\u0000x", "nbsp\u2003x",
        ) { tok ->
            val e = shouldThrow<IllegalArgumentException> { Config.fromEnv(env(Config.ENV_MCP_AUTH_TOKEN to tok)) }
            e.message shouldBe "${Config.ENV_MCP_AUTH_TOKEN} must not contain whitespace or control characters."
            e.message shouldNotContain tok
        }

        test("property: tokens of visible ASCII are accepted verbatim and redacted in toString") {
            checkAll(Arb.string(8..40, Codepoint.alphanumeric())) { t ->
                val c = Config.fromEnv(env(Config.ENV_MCP_AUTH_TOKEN to "T$t"))
                c.httpAuthToken shouldBe "T$t"
                c.toString() shouldNotContain "T$t"
            }
        }

        test("default parameter reads System.getenv without crashing on missing vars") {
            val r = runCatching { Config.fromEnv() }
            r.exceptionOrNull()?.let { (it is IllegalArgumentException) shouldBe true }
            if (System.getenv(Config.ENV_TENANT_ID) == null) r.exceptionOrNull()!!.message shouldContain "is required"
        }
    }
})
