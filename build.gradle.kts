import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.serialization)
    alias(libs.plugins.shadow)
    application
    jacoco
}

group = "com.jitunicornfx.defender"
version = "0.1.0"

dependencies {
    implementation(platform(libs.ktor.bom))

    implementation(libs.mcp.kotlin.server)
    implementation(libs.clikt)

    // Outbound HTTP to Microsoft Entra ID and the Defender API. OkHttp is the default engine: blocking
    // sockets on its own pool, no NIO self-pipe (which some locked-down EDR hosts refuse).
    implementation(libs.ktor.client.core)
    implementation(libs.ktor.client.okhttp)

    // Inbound HTTP for the optional --http (Streamable HTTP / legacy SSE) transport.
    implementation(libs.ktor.server.cio)
    implementation(libs.ktor.server.cors)

    implementation(libs.kotlinx.serialization.json)
    implementation(libs.kotlinx.coroutines.core)

    // slf4j-simple logs to stderr, keeping stdout clean for the stdio JSON-RPC channel.
    implementation(libs.slf4j.simple)

    testImplementation(libs.kotest.runner.junit5)
    testImplementation(libs.kotest.assertions.core)
    testImplementation(libs.kotest.property)
    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation(libs.mcp.kotlin.client)
    testImplementation(libs.ktor.client.mock)
    testImplementation(libs.ktor.server.test.host)
}

application {
    mainClass.set("com.jitunicornfx.defender.mcp.MainKt")
}

kotlin {
    compilerOptions {
        jvmTarget = JvmTarget.JVM_21
        javaParameters = true
    }
}

java {
    sourceCompatibility = JavaVersion.VERSION_21
    targetCompatibility = JavaVersion.VERSION_21
}

tasks.test {
    useJUnitPlatform()
    // Tests must never reach the real tenant: wipe any DEFENDER_* the developer has exported.
    environment.keys.filter { it.startsWith("DEFENDER_") }.forEach { environment.remove(it) }
    systemProperty("kotest.framework.classpath.scanning.autoscan.disable", "true")
    finalizedBy(tasks.jacocoTestReport)
}

jacoco {
    toolVersion = libs.versions.jacoco.get()
}

tasks.jacocoTestReport {
    dependsOn(tasks.test)
    reports {
        xml.required.set(true)
        html.required.set(true)
        csv.required.set(false)
    }
}

// Coverage gate: `check` fails below these thresholds.
tasks.jacocoTestCoverageVerification {
    dependsOn(tasks.test)
    violationRules {
        rule {
            limit {
                counter = "LINE"
                minimum = "0.90".toBigDecimal()
            }
            limit {
                counter = "BRANCH"
                minimum = "0.80".toBigDecimal()
            }
        }
    }
}

tasks.check {
    dependsOn(tasks.jacocoTestCoverageVerification)
}

tasks.jar {
    archiveClassifier.set("thin")
}

tasks.shadowJar {
    archiveBaseName.set("microsoft-defender-mcp")
    archiveClassifier.set("all")
    archiveVersion.set(project.version.toString())
    mergeServiceFiles()
    manifest {
        attributes("Enable-Native-Access" to "ALL-UNNAMED")
    }
}
