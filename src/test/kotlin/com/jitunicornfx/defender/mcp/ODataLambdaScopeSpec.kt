package com.jitunicornfx.defender.mcp

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.datatest.withData
import io.kotest.matchers.shouldBe

/** Regression tests for lambda-variable scoping and ':' placement in [OData.validate]. */
class ODataLambdaScopeSpec : FunSpec({
    val fields = setOf("machineTags", "healthStatus", "id")

    context("accepted lambda filters") {
        withData(
            "machineTags/any(t: t eq 'x')",
            "machineTags/all(t: startswith(t,'prod'))",
            "machineTags/any(t: t eq 'a') and machineTags/any(t: t eq 'b')",
            "(machineTags/any(t: t eq 'a')) or healthStatus eq 'Active'",
        ) { filter -> OData.validate(filter, fields) shouldBe filter }
    }

    context("refused lambda filters") {
        withData(
            "machineTags/any(ipAddress: ipAddress eq 'x') or ipAddress eq '10.0.0.1'",
            "machineTags/any(t: t eq 'x') and t eq 'y'",
            "machineTags/any(eq: eq eq 'x')",
            "machineTags/any(id: id eq 'x')",
            "machineTags/any(startswith: true)",
            "healthStatus eq 'a' or (true: 1)",
            "healthStatus eq 'a':'b'",
            "notAField/any(t: t eq 'x')",
            "machineTags/any(t: machineTags/any(t: t eq 'x'))",
            "(t: t eq 'x')",
        ) { filter -> shouldThrow<IllegalArgumentException> { OData.validate(filter, fields) } }
    }

    test("nested lambdas may use the outer variable inside the inner one") {
        val filter = "machineTags/any(t: machineTags/any(u: u eq t))"
        OData.validate(filter, fields) shouldBe filter
    }

    test("seg never lets percent-encoded dot segments decode to a parent path") {
        val encoded = Validators.seg("%2e%2e")
        java.net.URLDecoder.decode(encoded, Charsets.UTF_8) shouldBe "%2e%2e"
    }
})
