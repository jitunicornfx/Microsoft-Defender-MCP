package com.jitunicornfx.defender.mcp

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldContainExactly
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotContain

private const val MT_TENANT_A = "aaaaaaaa-1111-2222-3333-444444444444"
private const val MT_CLIENT_A = "aaaaaaaa-5555-6666-7777-888888888888"
private const val MT_SECRET_A = "secret-A~contoso-only"
private const val MT_TENANT_B = "fabrikam.onmicrosoft.com"
private const val MT_CLIENT_B = "bbbbbbbb-5555-6666-7777-888888888888"
private const val MT_SECRET_B = "secret-B~fabrikam-only "

/** Environment for two named tenants, `contoso` and `fabrikam-lab`. */
private fun namedEnv(vararg extra: Pair<String, String>): Map<String, String> = mapOf(
    "DEFENDER_TENANTS" to "contoso,fabrikam-lab",
    "DEFENDER_CONTOSO_TENANT_ID" to MT_TENANT_A,
    "DEFENDER_CONTOSO_CLIENT_ID" to MT_CLIENT_A,
    "DEFENDER_CONTOSO_CLIENT_SECRET" to MT_SECRET_A,
    "DEFENDER_FABRIKAM_LAB_TENANT_ID" to MT_TENANT_B,
    "DEFENDER_FABRIKAM_LAB_CLIENT_ID" to MT_CLIENT_B,
    "DEFENDER_FABRIKAM_LAB_CLIENT_SECRET" to MT_SECRET_B,
) + extra

private fun classicEnv(vararg extra: Pair<String, String>): Map<String, String> = mapOf(
    "DEFENDER_TENANT_ID" to MT_TENANT_A,
    "DEFENDER_CLIENT_ID" to MT_CLIENT_A,
    "DEFENDER_CLIENT_SECRET" to MT_SECRET_A,
) + extra

private fun failure(env: Map<String, String>): String =
    shouldThrow<IllegalArgumentException> { Config.fromEnv(env) }.message!!

private fun mtProfile(name: String, cloud: CloudEnvironment = CloudEnvironment.COMMERCIAL, region: DefenderRegion? = null, access: AccessLevel? = null) =
    TenantProfile(name, EntraCredentials(MT_TENANT_B, MT_CLIENT_B, MT_SECRET_B), cloud, region, access)

private fun twoTenantConfig(
    access: AccessLevel = AccessLevel.WRITE,
    primaryAccess: AccessLevel? = null,
    other: TenantProfile = mtProfile("fabrikam", CloudEnvironment.GCC, access = AccessLevel.READ_ONLY),
    defaultTenant: String? = null,
) = Config(
    credentials = EntraCredentials(MT_TENANT_A, MT_CLIENT_A, MT_SECRET_A),
    region = DefenderRegion.EU,
    accessLevel = access,
    maxActionsPerHour = 7,
    tenantName = "contoso",
    tenantAccessLevel = primaryAccess,
    additionalTenants = listOf(other),
    defaultTenant = defaultTenant,
    toolGlobs = listOf("defender_*"),
)

class MultiTenantConfigSpec : FunSpec({

    context("fromEnv with DEFENDER_TENANTS") {
        test("named tenants read every per-tenant variable; '-' in a name becomes '_' in its variables") {
            val c = Config.fromEnv(
                namedEnv(
                    "DEFENDER_CONTOSO_CLOUD" to "commercial",
                    "DEFENDER_CONTOSO_REGION" to "UK",
                    "DEFENDER_CONTOSO_ACCESS_LEVEL" to "read-only",
                    "DEFENDER_FABRIKAM_LAB_CLOUD" to "GCC-High",
                    "DEFENDER_FABRIKAM_LAB_ACCESS_LEVEL" to "write",
                    "DEFENDER_ACCESS_LEVEL" to "destructive",
                ),
            )
            c.isMultiTenant shouldBe true
            c.tenants.map { it.name } shouldContainExactly listOf("contoso", "fabrikam-lab")
            c.tenantName shouldBe "contoso"
            val (a, b) = c.tenants
            a.credentials shouldBe EntraCredentials(MT_TENANT_A, MT_CLIENT_A, MT_SECRET_A)
            a.cloud shouldBe CloudEnvironment.COMMERCIAL
            a.region shouldBe DefenderRegion.UK
            a.accessLevel shouldBe AccessLevel.READ_ONLY
            a.apiBaseUrl shouldBe "https://uk.api.security.microsoft.com"
            // The primary tenant is mirrored onto the classic fields.
            c.credentials shouldBe a.credentials
            c.region shouldBe DefenderRegion.UK
            c.tenantAccessLevel shouldBe AccessLevel.READ_ONLY

            b.credentials.tenantId shouldBe MT_TENANT_B
            b.credentials.clientId shouldBe MT_CLIENT_B
            // Secrets are taken verbatim: the trailing space is kept.
            b.credentials.clientSecret shouldBe MT_SECRET_B
            b.cloud shouldBe CloudEnvironment.GCC_HIGH
            b.region.shouldBeNull()
            b.accessLevel shouldBe AccessLevel.WRITE
            b.apiBaseUrl shouldBe CloudEnvironment.GCC_HIGH.apiBaseUrl

            c.accessLevel shouldBe AccessLevel.DESTRUCTIVE
            c.accessFor(a) shouldBe AccessLevel.READ_ONLY
            c.accessFor(b) shouldBe AccessLevel.WRITE
            c.defaultTenant.shouldBeNull()
        }

        test("tenant names are case-folded and trimmed, and their variables use the upper-case prefix") {
            val c = Config.fromEnv(namedEnv("DEFENDER_TENANTS" to " Contoso , FABRIKAM-LAB "))
            c.tenants.map { it.name } shouldContainExactly listOf("contoso", "fabrikam-lab")
            Config.tenantPrefix("fabrikam-lab") shouldBe "DEFENDER_FABRIKAM_LAB_"
            Config.tenantPrefix("a1-b2-c3") shouldBe "DEFENDER_A1_B2_C3_"
        }

        test("a single named tenant is not multi-tenant, but keeps its name") {
            val env = namedEnv("DEFENDER_TENANTS" to "contoso").filterKeys { !it.startsWith("DEFENDER_FABRIKAM") }
            val c = Config.fromEnv(env)
            c.isMultiTenant shouldBe false
            c.tenantName shouldBe "contoso"
            c.tenants.single().name shouldBe "contoso"
        }

        test("the global cloud and region are defaults; the region only reaches commercial tenants") {
            val c = Config.fromEnv(
                namedEnv(
                    "DEFENDER_REGION" to "eu",
                    "DEFENDER_FABRIKAM_LAB_CLOUD" to "gcc",
                ),
            )
            c.tenants[0].cloud shouldBe CloudEnvironment.COMMERCIAL
            c.tenants[0].region shouldBe DefenderRegion.EU
            c.tenants[0].apiBaseUrl shouldBe "https://eu.api.security.microsoft.com"
            // A government tenant never inherits a commercial region (it would be refused, and it is meaningless).
            c.tenants[1].cloud shouldBe CloudEnvironment.GCC
            c.tenants[1].region.shouldBeNull()
            c.tenants[1].apiBaseUrl shouldBe "https://api-gcc.securitycenter.microsoft.us"
        }

        test("a global government cloud is inherited; a tenant overriding to commercial picks up the global region") {
            val c = Config.fromEnv(
                namedEnv(
                    "DEFENDER_CLOUD" to "dod",
                    "DEFENDER_REGION" to "au",
                    "DEFENDER_CONTOSO_CLOUD" to "commercial",
                ),
            )
            c.tenants[0].cloud shouldBe CloudEnvironment.COMMERCIAL
            c.tenants[0].region shouldBe DefenderRegion.AU
            c.tenants[1].cloud shouldBe CloudEnvironment.DOD
            c.tenants[1].region.shouldBeNull()
        }

        test("a per-tenant region overrides the global one") {
            val c = Config.fromEnv(namedEnv("DEFENDER_REGION" to "eu", "DEFENDER_FABRIKAM_LAB_REGION" to "swa"))
            c.tenants[0].region shouldBe DefenderRegion.EU
            c.tenants[1].region shouldBe DefenderRegion.SWA
        }

        test("a per-tenant region on a government cloud is refused, naming the tenant") {
            val msg = failure(namedEnv("DEFENDER_FABRIKAM_LAB_CLOUD" to "gcc", "DEFENDER_FABRIKAM_LAB_REGION" to "us"))
            msg shouldContain "fabrikam-lab"
            msg shouldContain "commercial cloud"
        }

        test("bad per-tenant cloud, region or access level values are refused") {
            failure(namedEnv("DEFENDER_CONTOSO_CLOUD" to "mars")) shouldContain "Unknown cloud 'mars'"
            failure(namedEnv("DEFENDER_CONTOSO_REGION" to "atlantis")) shouldContain "Unknown region 'atlantis'"
            failure(namedEnv("DEFENDER_FABRIKAM_LAB_ACCESS_LEVEL" to "god")) shouldContain "Unknown access level 'god'"
        }

        test("blank per-tenant optional variables fall back to the defaults") {
            val c = Config.fromEnv(
                namedEnv("DEFENDER_CONTOSO_CLOUD" to "  ", "DEFENDER_CONTOSO_REGION" to "", "DEFENDER_CONTOSO_ACCESS_LEVEL" to " "),
            )
            c.tenants[0].cloud shouldBe CloudEnvironment.COMMERCIAL
            c.tenants[0].region.shouldBeNull()
            c.tenants[0].accessLevel.shouldBeNull()
        }

        test("invalid tenant names are refused") {
            listOf("1contoso", "con_toso", "con toso", "c".repeat(33), "-lab", "con.toso", "contoso/../x").forEach { bad ->
                failure(namedEnv("DEFENDER_TENANTS" to bad)) shouldContain "is invalid"
            }
            // 32 characters is the limit.
            Config.validateTenantName("c".repeat(32)) shouldBe "c".repeat(32)
        }

        test("a tenant listed twice (even in different case) is refused") {
            failure(namedEnv("DEFENDER_TENANTS" to "contoso,fabrikam-lab,CONTOSO")) shouldContain "more than once"
        }

        test("a list with no names is refused") {
            failure(mapOf("DEFENDER_TENANTS" to " , ,")) shouldContain "at least one tenant name"
        }

        test("a blank DEFENDER_TENANTS means classic mode") {
            val c = Config.fromEnv(classicEnv("DEFENDER_TENANTS" to "   "))
            c.tenantName shouldBe Config.DEFAULT_TENANT_NAME
            c.isMultiTenant shouldBe false
        }

        test("mixing DEFENDER_TENANTS with the classic variables is refused, naming the variables but never the secret") {
            val msg = failure(namedEnv("DEFENDER_CLIENT_SECRET" to "classic-secret-value-123", "DEFENDER_TENANT_ID" to MT_TENANT_A))
            msg shouldContain "DEFENDER_TENANT_ID"
            msg shouldContain "DEFENDER_CLIENT_SECRET"
            msg shouldNotContain "DEFENDER_CLIENT_ID,"
            msg shouldNotContain "classic-secret-value-123"
            msg shouldNotContain MT_TENANT_A
            msg shouldNotContain MT_SECRET_A
            failure(namedEnv("DEFENDER_CLIENT_ID" to MT_CLIENT_A)) shouldContain "DEFENDER_CLIENT_ID must not be"
        }

        test("an empty classic variable alongside DEFENDER_TENANTS is tolerated") {
            Config.fromEnv(namedEnv("DEFENDER_CLIENT_SECRET" to "")).isMultiTenant shouldBe true
        }

        test("a missing per-tenant variable is named in the error") {
            listOf("TENANT_ID", "CLIENT_ID", "CLIENT_SECRET").forEach { suffix ->
                val variable = "DEFENDER_FABRIKAM_LAB_$suffix"
                val msg = failure(namedEnv().filterKeys { it != variable })
                msg shouldBe "$variable is required."
            }
            // Blank counts as missing.
            failure(namedEnv("DEFENDER_CONTOSO_TENANT_ID" to "  ")) shouldBe "DEFENDER_CONTOSO_TENANT_ID is required."
            failure(namedEnv("DEFENDER_CONTOSO_CLIENT_SECRET" to "")) shouldBe "DEFENDER_CONTOSO_CLIENT_SECRET is required."
        }

        test("a bad per-tenant tenant id, client id or secret names its own variable") {
            val tenantMsg = failure(namedEnv("DEFENDER_FABRIKAM_LAB_TENANT_ID" to "evil/../path"))
            tenantMsg shouldContain "DEFENDER_FABRIKAM_LAB_TENANT_ID"
            tenantMsg shouldNotContain "evil"
            failure(namedEnv("DEFENDER_CONTOSO_CLIENT_ID" to "not-a-guid")) shouldContain "DEFENDER_CONTOSO_CLIENT_ID must be the application"
            val secretMsg = failure(namedEnv("DEFENDER_CONTOSO_CLIENT_SECRET" to "abc\u0000def"))
            secretMsg shouldContain "DEFENDER_CONTOSO_CLIENT_SECRET contains control characters"
            secretMsg shouldNotContain "abc"
            failure(namedEnv("DEFENDER_CONTOSO_CLIENT_SECRET" to "   ")) shouldContain "DEFENDER_CONTOSO_CLIENT_SECRET must not be blank"
        }

        test("one tenant's credentials never leak into another's") {
            val c = Config.fromEnv(namedEnv())
            c.tenants[0].credentials.clientSecret shouldBe MT_SECRET_A
            c.tenants[1].credentials.clientSecret shouldBe MT_SECRET_B
            c.forTenant(c.tenants[1]).tokenUrl shouldBe "https://login.microsoftonline.com/$MT_TENANT_B/oauth2/v2.0/token"
            c.forTenant(c.tenants[0]).tokenUrl shouldBe "https://login.microsoftonline.com/$MT_TENANT_A/oauth2/v2.0/token"
        }
    }

    context("DEFENDER_DEFAULT_TENANT") {
        test("a configured name is accepted, case-folded and trimmed") {
            Config.fromEnv(namedEnv("DEFENDER_DEFAULT_TENANT" to " Fabrikam-Lab ")).defaultTenant shouldBe "fabrikam-lab"
            Config.fromEnv(namedEnv("DEFENDER_DEFAULT_TENANT" to "contoso")).defaultTenant shouldBe "contoso"
        }

        test("blank means none") {
            Config.fromEnv(namedEnv("DEFENDER_DEFAULT_TENANT" to "  ")).defaultTenant.shouldBeNull()
        }

        test("an unknown name is refused and the configured names are listed") {
            val msg = failure(namedEnv("DEFENDER_DEFAULT_TENANT" to "northwind"))
            msg shouldContain "DEFENDER_DEFAULT_TENANT"
            msg shouldContain "'northwind'"
            msg shouldContain "contoso, fabrikam-lab"
        }

        test("in classic mode only 'default' is a valid default tenant") {
            Config.fromEnv(classicEnv("DEFENDER_DEFAULT_TENANT" to "DEFAULT")).defaultTenant shouldBe "default"
            failure(classicEnv("DEFENDER_DEFAULT_TENANT" to "contoso")) shouldContain "not a configured tenant"
        }
    }

    context("classic single tenant") {
        test("the classic variables give one tenant named 'default'") {
            val c = Config.fromEnv(classicEnv("DEFENDER_REGION" to "us"))
            c.tenantName shouldBe "default"
            c.isMultiTenant shouldBe false
            c.additionalTenants.shouldBeEmpty()
            c.tenants.single().name shouldBe "default"
            c.tenants.single().credentials shouldBe EntraCredentials(MT_TENANT_A, MT_CLIENT_A, MT_SECRET_A)
            c.tenants.single().region shouldBe DefenderRegion.US
            c.tenantAccessLevel.shouldBeNull()
            c.primaryTenant shouldBe c.tenants.single()
            c.forTenant(c.primaryTenant) shouldBe c
        }

        test("classic mode with a government cloud and a region is refused") {
            failure(classicEnv("DEFENDER_CLOUD" to "gcc", "DEFENDER_REGION" to "eu")) shouldContain "commercial cloud"
        }

        test("classic missing variables are named") {
            failure(classicEnv().filterKeys { it != "DEFENDER_CLIENT_SECRET" }) shouldBe "DEFENDER_CLIENT_SECRET is required."
        }
    }

    context("Config") {
        test("toString lists the tenant names and the default, and never any secret or other tenant's ids") {
            val c = twoTenantConfig(defaultTenant = "fabrikam")
            val s = c.toString()
            s shouldContain "tenants=[contoso, fabrikam]"
            s shouldContain "defaultTenant=fabrikam"
            s shouldNotContain MT_SECRET_A
            s shouldNotContain MT_SECRET_B
            s shouldNotContain MT_TENANT_B
            s shouldNotContain MT_CLIENT_B
            twoTenantConfig().toString() shouldContain "defaultTenant=none"
            // Data-class rendering of a profile still masks the secret.
            c.additionalTenants.single().toString() shouldNotContain MT_SECRET_B
        }

        test("tenants and primaryTenant reflect the primary fields first") {
            val c = twoTenantConfig(primaryAccess = AccessLevel.READ_ONLY)
            c.isMultiTenant shouldBe true
            c.primaryTenant shouldBe TenantProfile("contoso", EntraCredentials(MT_TENANT_A, MT_CLIENT_A, MT_SECRET_A), CloudEnvironment.COMMERCIAL, DefenderRegion.EU, AccessLevel.READ_ONLY)
            c.tenants.map { it.name } shouldContainExactly listOf("contoso", "fabrikam")
        }

        test("forTenant gives a single-tenant view with the tenant's credentials and host, keeping server-wide settings") {
            val c = twoTenantConfig(defaultTenant = "contoso")
            val view = c.forTenant(c.tenants[1])
            view.credentials.tenantId shouldBe MT_TENANT_B
            view.credentials.clientSecret shouldBe MT_SECRET_B
            view.cloud shouldBe CloudEnvironment.GCC
            view.region.shouldBeNull()
            view.apiBaseUrl shouldBe "https://api-gcc.securitycenter.microsoft.us"
            view.tenantName shouldBe "fabrikam"
            view.tenantAccessLevel shouldBe AccessLevel.READ_ONLY
            view.additionalTenants.shouldBeEmpty()
            view.defaultTenant.shouldBeNull()
            view.isMultiTenant shouldBe false
            // Server-wide settings are shared.
            view.accessLevel shouldBe AccessLevel.WRITE
            view.maxActionsPerHour shouldBe 7
            view.toolGlobs shouldContainExactly listOf("defender_*")
            view.confirmation shouldBe c.confirmation
        }

        test("accessFor: a tenant can narrow the server-wide level but never widen it") {
            AccessLevel.entries.forEach { server ->
                val base = twoTenantConfig(access = server)
                base.accessFor(mtProfile("x")) shouldBe server
                AccessLevel.entries.forEach { tenantLevel ->
                    val expected = if (tenantLevel.ordinal < server.ordinal) tenantLevel else server
                    base.accessFor(mtProfile("x", access = tenantLevel)) shouldBe expected
                }
            }
            val readOnlyServer = twoTenantConfig(access = AccessLevel.READ_ONLY)
            readOnlyServer.accessFor(mtProfile("x", access = AccessLevel.DESTRUCTIVE)) shouldBe AccessLevel.READ_ONLY
        }

        test("duplicate tenant names are refused by the constructor") {
            shouldThrow<IllegalArgumentException> {
                twoTenantConfig(other = mtProfile("contoso"))
            }.message shouldContain "repeated: contoso"
        }

        test("a default tenant that is not configured is refused by the constructor") {
            shouldThrow<IllegalArgumentException> { twoTenantConfig(defaultTenant = "northwind") }
                .message shouldContain "'northwind', which is not a configured tenant (contoso, fabrikam)"
        }

        test("an invalid primary tenant name is refused") {
            shouldThrow<IllegalArgumentException> {
                Config(credentials = EntraCredentials(MT_TENANT_A, MT_CLIENT_A, MT_SECRET_A), tenantName = "Contoso")
            }.message shouldContain "is invalid"
        }

        test("the tenant name in an error is clipped") {
            val long = "x".repeat(200)
            val msg = shouldThrow<IllegalArgumentException> { Config.validateTenantName(long) }.message!!
            msg shouldNotContain "x".repeat(41)
        }
    }

    context("TenantProfile") {
        test("a region on a government cloud is refused") {
            listOf(CloudEnvironment.GCC, CloudEnvironment.GCC_HIGH, CloudEnvironment.DOD).forEach { cloud ->
                shouldThrow<IllegalArgumentException> { mtProfile("gov", cloud, DefenderRegion.US) }
                    .message shouldContain "Tenant 'gov': a region applies only to the commercial cloud; ${cloud.code}"
            }
        }

        test("an invalid name is refused") {
            shouldThrow<IllegalArgumentException> { mtProfile("Bad Name") }.message shouldContain "is invalid"
        }

        test("apiBaseUrl is the region's host, else the cloud's") {
            mtProfile("a").apiBaseUrl shouldBe "https://api.security.microsoft.com"
            mtProfile("a", region = DefenderRegion.INA).apiBaseUrl shouldBe "https://ina.api.security.microsoft.com"
            mtProfile("a", CloudEnvironment.DOD).apiBaseUrl shouldBe "https://api-gov.securitycenter.microsoft.us"
        }
    }
})
