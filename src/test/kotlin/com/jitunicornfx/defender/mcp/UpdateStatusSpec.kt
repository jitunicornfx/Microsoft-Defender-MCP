package com.jitunicornfx.defender.mcp

import io.kotest.core.spec.style.FunSpec
import io.kotest.datatest.withData
import io.kotest.matchers.booleans.shouldBeFalse
import io.kotest.matchers.booleans.shouldBeTrue
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotContain
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonPrimitive

/**
 * [UpdateStatus] and the `update` object `defender_server_info` renders from it: the answer a client
 * can ask for when the update notice, a push, never reached it.
 */
class UpdateStatusSpec : FunSpec({

    beforeEach { UpdateStatus.reset() }
    afterEach { UpdateStatus.reset() }

    val available = UpdateChecker.Result(updateAvailable = true, currentVersion = "0.1.0", latestVersion = "9.9.9")

    fun info(): JsonObject = updateInfo(UpdateStatus.active)
    fun JsonObject.text(key: String): String? = this[key]?.jsonPrimitive?.content

    context("check state") {
        test("a check still running says so, and names the running version") {
            val info = info()
            info.text("currentVersion") shouldBe SERVER_VERSION
            info.text("check") shouldBe "pending"
            info.text("updateAvailable") shouldBe "false"
            info.text("install") shouldBe "notAttempted"
            info.text("restartRequired") shouldBe "false"
            info["latestRelease"].shouldBeNull()
            info["installedVersion"].shouldBeNull()
            info["appliesOnExit"].shouldBeNull()
            info["failureReason"].shouldBeNull()
            info.text("releaseUrl") shouldBe UpdateChecker.RELEASES_PAGE_URL
            info.text("summary") shouldBe "The update check has not finished yet; ask again in a moment."
        }

        test("the initial snapshot defaults") {
            val s = UpdateStatus.Snapshot()
            s.checkState shouldBe UpdateStatus.CheckState.PENDING
            s.result.shouldBeNull()
            s.installState shouldBe UpdateStatus.InstallState.NOT_ATTEMPTED
            s.installedVersion.shouldBeNull()
            s.failureReason.shouldBeNull()
            s.appliesOnExit.shouldBeFalse()
            s.restartRequired.shouldBeFalse()
            UpdateStatus.active shouldBe s
        }

        test("an available release is reported with its version") {
            UpdateStatus.recordCheck(available)
            val info = info()
            info.text("check") shouldBe "completed"
            info.text("latestRelease") shouldBe "9.9.9"
            info.text("updateAvailable") shouldBe "true"
            info.text("summary") shouldBe available.message()
            info.text("summary")!! shouldContain "9.9.9 (currently running 0.1.0)"
        }

        test("a result with a custom release URL surfaces it") {
            UpdateStatus.recordCheck(available.copy(releaseUrl = "https://github.com/jitunicornfx/Microsoft-Defender-MCP/releases/tag/v9.9.9"))
            info().text("releaseUrl") shouldBe "https://github.com/jitunicornfx/Microsoft-Defender-MCP/releases/tag/v9.9.9"
        }

        test("an update with no latestRelease still counts as answered") {
            UpdateStatus.recordCheck(available.copy(latestRelease = null))
            UpdateStatus.active.checkState shouldBe UpdateStatus.CheckState.COMPLETED
            info()["latestRelease"].shouldBeNull()
        }

        test("up to date and could-not-tell are different answers") {
            UpdateStatus.recordCheck(UpdateChecker.evaluate("""{"tag_name":"v0.1.0"}""", "0.1.0"))
            info().text("check") shouldBe "completed"
            info().text("latestRelease") shouldBe "0.1.0"
            info().text("updateAvailable") shouldBe "false"
            info().text("summary")!! shouldContain "is up to date"

            UpdateStatus.reset()
            UpdateStatus.recordCheck(UpdateChecker.evaluate(null, "0.1.0"))
            info().text("check") shouldBe "failed"
            info()["latestRelease"].shouldBeNull()
            info().text("summary")!! shouldNotContain "up to date"
            info().text("summary") shouldBe
                "The update check could not get an answer from GitHub, so whether a newer release exists is not known."
            // The result is still recorded even though the check failed.
            UpdateStatus.active.result!!.currentVersion shouldBe "0.1.0"
        }

        test("a late failure never erases a recorded result") {
            UpdateStatus.markCheckStarted()
            UpdateStatus.recordCheck(available)
            UpdateStatus.markCheckFailed()
            UpdateStatus.active.checkState shouldBe UpdateStatus.CheckState.COMPLETED

            UpdateStatus.reset()
            UpdateStatus.markCheckDisabled()
            UpdateStatus.markCheckFailed()
            UpdateStatus.active.checkState shouldBe UpdateStatus.CheckState.DISABLED
        }

        test("a pending check can fail") {
            UpdateStatus.markCheckStarted()
            UpdateStatus.markCheckFailed()
            info().text("check") shouldBe "failed"
            info().text("summary")!! shouldContain "not known"
        }

        test("a disabled check says how it was disabled") {
            UpdateStatus.markCheckDisabled()
            info().text("check") shouldBe "disabled"
            info().text("summary")!! shouldContain Config.ENV_DISABLE_UPDATE_CHECK
            info().text("summary")!! shouldContain "--no-update-check"
            info().text("summary")!! shouldContain "DEFENDER_DISABLE_UPDATE_CHECK"
        }

        test("markCheckStarted moves any state back to pending") {
            UpdateStatus.markCheckDisabled()
            UpdateStatus.markCheckStarted()
            UpdateStatus.active.checkState shouldBe UpdateStatus.CheckState.PENDING
        }

        test("a completed snapshot without a result still produces a sentence") {
            val snapshot = UpdateStatus.Snapshot(checkState = UpdateStatus.CheckState.COMPLETED)
            updateSummary(snapshot) shouldBe "The update check completed but reported nothing."
            val info = updateInfo(snapshot)
            info.text("updateAvailable") shouldBe "false"
            info.text("releaseUrl") shouldBe UpdateChecker.RELEASES_PAGE_URL
        }
    }

    context("install state") {
        test("an installed release needs only a restart, and no path reaches the model") {
            UpdateStatus.recordCheck(available)
            UpdateStatus.recordInstall(UpdateInstaller.Outcome.Installed("9.9.9", "/opt/defender/app.jar"))
            val info = info()
            info.text("install") shouldBe "installed"
            info.text("installedVersion") shouldBe "9.9.9"
            info.text("restartRequired") shouldBe "true"
            info["appliesOnExit"].shouldBeNull()
            info.text("summary")!! shouldContain "Version 9.9.9 has been installed. Restart the server to run it."
            info.toString() shouldNotContain "/opt/defender"
        }

        test("a Windows install path never reaches the model either") {
            UpdateStatus.recordInstall(UpdateInstaller.Outcome.Installed("9.9.9", "C:\\Program Files\\defender\\app.jar"))
            info().toString() shouldNotContain "Program Files"
        }

        test("a staged release needs a restart only once its hook is registered, and not after it is lost") {
            UpdateStatus.recordCheck(available)
            UpdateStatus.recordInstall(
                UpdateInstaller.Outcome.Staged("9.9.9", "/opt/defender/app.jar.new", "a".repeat(64), "b".repeat(64)),
            )
            info().text("install") shouldBe "staged"
            info().text("appliesOnExit") shouldBe "false"
            info().text("restartRequired") shouldBe "false"
            info().text("summary")!! shouldContain "will NOT be applied automatically"
            info().text("summary")!! shouldContain "Update it manually."

            UpdateStatus.markStagedAppliesOnExit()
            info().text("appliesOnExit") shouldBe "true"
            info().text("restartRequired") shouldBe "true"
            info().text("summary")!! shouldContain "will be applied when this server exits"
            info().toString() shouldNotContain "/opt/defender"
            info().toString() shouldNotContain "a".repeat(64)

            UpdateStatus.markStagedLost()
            info().text("install") shouldBe "failed"
            info().text("restartRequired") shouldBe "false"
            info()["appliesOnExit"].shouldBeNull()
            info().text("failureReason") shouldBe UpdateStatus.STAGED_LOST_REASON
            info().text("summary")!! shouldContain "Automatic update did not complete: ${UpdateStatus.STAGED_LOST_REASON}"
            UpdateStatus.active.appliesOnExit.shouldBeFalse()
        }

        test("only a staged install can be lost") {
            UpdateStatus.recordInstall(UpdateInstaller.Outcome.Installed("9.9.9", "/opt/app.jar"))
            UpdateStatus.markStagedLost()
            UpdateStatus.active.installState shouldBe UpdateStatus.InstallState.INSTALLED
            UpdateStatus.active.restartRequired.shouldBeTrue()
            UpdateStatus.active.failureReason.shouldBeNull()

            UpdateStatus.reset()
            UpdateStatus.markStagedLost()
            UpdateStatus.active.installState shouldBe UpdateStatus.InstallState.NOT_ATTEMPTED
        }

        test("failed, skipped and switched-off installs each say what happened") {
            UpdateStatus.recordInstall(UpdateInstaller.Outcome.Failed("SHA-256 mismatch for 9.9.9 - refusing to install"))
            info().text("install") shouldBe "failed"
            info().text("failureReason") shouldBe "SHA-256 mismatch for 9.9.9 - refusing to install"
            info().text("summary")!! shouldContain "Automatic update did not complete: SHA-256 mismatch"
            info().text("restartRequired") shouldBe "false"

            UpdateStatus.recordInstall(UpdateInstaller.Outcome.Skipped)
            info().text("install") shouldBe "skipped"
            info().text("summary")!! shouldContain "There was nothing to install for the available release."

            UpdateStatus.markAutoInstallDisabled()
            info().text("install") shouldBe "disabled"
            info().text("summary")!! shouldContain Config.ENV_DISABLE_AUTO_UPDATE
            info().text("summary")!! shouldContain "--no-auto-update"
            info().text("restartRequired") shouldBe "false"
        }

        test("the summary joins the check sentence and the install sentence") {
            UpdateStatus.recordCheck(available)
            UpdateStatus.recordInstall(UpdateInstaller.Outcome.Installed("9.9.9", "/x.jar"))
            info().text("summary") shouldBe
                "${available.message()} Version 9.9.9 has been installed. Restart the server to run it."
        }
    }

    context("restartRequired for every install state") {
        withData(
            nameFn = { "${it.first} appliesOnExit=${it.second}" },
            Triple(UpdateStatus.InstallState.NOT_ATTEMPTED, false, false),
            Triple(UpdateStatus.InstallState.NOT_ATTEMPTED, true, false),
            Triple(UpdateStatus.InstallState.DISABLED, false, false),
            Triple(UpdateStatus.InstallState.INSTALLED, false, true),
            Triple(UpdateStatus.InstallState.STAGED, false, false),
            Triple(UpdateStatus.InstallState.STAGED, true, true),
            Triple(UpdateStatus.InstallState.FAILED, true, false),
            Triple(UpdateStatus.InstallState.SKIPPED, false, false),
        ) { (state, applies, expected) ->
            UpdateStatus.Snapshot(installState = state, appliesOnExit = applies).restartRequired shouldBe expected
        }
    }

    context("updateInfo / updateSummary text for every state combination") {
        val installWords = mapOf(
            UpdateStatus.InstallState.NOT_ATTEMPTED to "notAttempted",
            UpdateStatus.InstallState.DISABLED to "disabled",
            UpdateStatus.InstallState.INSTALLED to "installed",
            UpdateStatus.InstallState.STAGED to "staged",
            UpdateStatus.InstallState.FAILED to "failed",
            UpdateStatus.InstallState.SKIPPED to "skipped",
        )
        val combos = UpdateStatus.CheckState.entries.flatMap { c -> UpdateStatus.InstallState.entries.map { c to it } }
        withData(nameFn = { "${it.first} / ${it.second}" }, combos) { (check, install) ->
            val snapshot = UpdateStatus.Snapshot(
                checkState = check,
                result = if (check == UpdateStatus.CheckState.COMPLETED) available else null,
                installState = install,
                installedVersion = "9.9.9",
                failureReason = if (install == UpdateStatus.InstallState.FAILED) "fixed reason" else null,
            )
            val info = updateInfo(snapshot)
            info.text("check") shouldBe check.name.lowercase()
            info.text("install") shouldBe installWords.getValue(install)
            (info["appliesOnExit"] != null) shouldBe (install == UpdateStatus.InstallState.STAGED)
            val summary = updateSummary(snapshot)
            info.text("summary") shouldBe summary
            summary.isNotBlank().shouldBeTrue()
            summary shouldNotContain "null"
            summary shouldNotContain "\n"
            if (install == UpdateStatus.InstallState.NOT_ATTEMPTED) {
                summary shouldBe updateSummary(snapshot.copy(installState = UpdateStatus.InstallState.NOT_ATTEMPTED))
                if (check == UpdateStatus.CheckState.COMPLETED) summary shouldBe available.message()
            } else {
                // The check sentence comes first, then the install sentence after one space.
                summary.startsWith(updateSummary(snapshot.copy(installState = UpdateStatus.InstallState.NOT_ATTEMPTED)) + " ")
                    .shouldBeTrue()
            }
        }
    }

    context("concurrency") {
        test("records from different threads are never lost") {
            coroutineScope {
                (1..200).map { i ->
                    async(Dispatchers.Default) {
                        if (i % 2 == 0) UpdateStatus.recordCheck(available) else UpdateStatus.markAutoInstallDisabled()
                    }
                }.awaitAll()
            }
            UpdateStatus.active.checkState shouldBe UpdateStatus.CheckState.COMPLETED
            UpdateStatus.active.installState shouldBe UpdateStatus.InstallState.DISABLED
        }
    }

    context("the checker names the newest release whether or not it is newer") {
        test("latestRelease") {
            UpdateChecker.evaluate("""{"tag_name":"v0.3.0"}""", "0.1.0").latestRelease shouldBe "0.3.0"
            UpdateChecker.evaluate("""{"tag_name":"v0.1.0"}""", "0.1.0").latestRelease shouldBe "0.1.0"
            UpdateChecker.evaluate("""{"tag_name":"0.0.9"}""", "0.1.0").latestRelease shouldBe "0.0.9"
            UpdateChecker.evaluate("""{"tag_name":"not a version"}""", "0.1.0").latestRelease.shouldBeNull()
            UpdateChecker.evaluate(null, "0.1.0").latestRelease.shouldBeNull()
            available.latestRelease shouldBe "9.9.9"
        }
    }
})
