# Defender for Endpoint gap analysis: response actions, indicators and missing reads

Base URL for everything below: `https://api.security.microsoft.com`. Regional hosts work too, and an optional `/api/v1.0` prefix pins the version. Rate limits are per app unless noted.

**What the repo already has.** I checked `C:\MCP Dev\Microsoft-Defender-MCP\src`:
- `DefenderClientSpec.kt` already sends a test `POST /api/machines/{id}/isolate` with `{"Comment":..., "IsolationType":"Full"}`. The HTTP plumbing exists, but no tool is registered for it.
- `PromptShield.kt` already blocks phrases like "isolate|offboard|quarantine all machines".
- `defender_find_machines_by_ip` already calls `/api/machines/findbyip(ip='…',timestamp=…)`. That is the same "find device by internal IP" feature as the docs' `/api/machines/find(timestamp=,key=)`, so it is **not a gap**.

---

## 1. Missing capabilities

### 1a. Machine response actions (all return 201 plus a MachineAction; 100/min, 1,500/hr unless noted)

| Endpoint | What it does | Proposed tool | Tier and why | Approval | App permission | Notable limits |
|---|---|---|---|---|---|---|
| `POST /api/machines/{id}/isolate` body `{Comment*, IsolationType: Full\|Selective\|UnManagedDevice}` | Cuts the device off the network | `defender_isolate_machine` | **DESTRUCTIVE**: disrupts the user and the business, though reversible | y | Machine.Isolate | Full: Win10 1703+, Win11, Linux. Selective: Win10 1709+. Full-tunnel VPN devices lose the MDE cloud. Default for IsolationType is undocumented, so always send it. |
| `POST /api/machines/{id}/unisolate` `{Comment*}` | Releases from isolation | `defender_unisolate_machine` | **WRITE**: restores the normal state | y | Machine.Isolate | 400 "Action is already in progress" if a release is pending. Linux is labelled preview on this page (docs disagree). |
| `POST /api/machines/{id}/restrictCodeExecution` `{Comment*}` | WDAC policy blocks all but Microsoft-signed apps | `defender_restrict_app_execution` | **DESTRUCTIVE**: severely disrupts the user, though reversible | y | Machine.RestrictExecution | Win10 1709+ or Win11, Defender AV required. 400 if already pending. |
| `POST /api/machines/{id}/unrestrictCodeExecution` `{Comment*}` | Removes the app restriction | `defender_unrestrict_app_execution` | **WRITE**: restores the normal state | y | Machine.RestrictExecution | OS section on the page is copied from isolation. Assume the same OS support as restrict (inference). |
| `POST /api/machines/{id}/runAntiVirusScan` `{Comment*, ScanType*: Quick\|Full}` | Starts a Defender AV scan | `defender_run_av_scan` | **WRITE**: low impact. It may remediate per AV policy and a Full scan loads the device, but a pending scan can be cancelled. | y | Machine.Scan | Win10 1709+, Win11, Linux, macOS. Works in passive mode. 400 if already pending. |
| `POST /api/machines/{id}/StopAndQuarantineFile` `{Comment*, Sha1*}` (PascalCase path) | Kills the file's processes and removes the file | `defender_stop_and_quarantine_file` | **DESTRUCTIVE**: removes a file, and no API can restore it | y | Machine.StopAndQuarantine (or Machine.ReadWrite.All) | SHA-1 only. Win10 1703+ or Win11. Refused for Microsoft-signed or trusted-publisher files. AV must be at least passive. |
| `POST /api/machineactions/{id}/cancel` `{Comment}` | Cancels a pending or in-progress action | `defender_cancel_machine_action` | **WRITE**: only stops actions that have not finished, and it makes no change to the device | y | Any one Machine.* action permission (the mapping is undocumented) | **Preview.** 404 if the action is unknown. Cannot undo an action that already finished. |
| `POST /api/machines/{id}/offboard` | Stops the sensor, so EDR goes blind | n/a | **EXCLUDE** (see section 3) | n/a | Machine.Offboard | Cannot be reversed through the API. |
| `POST /api/machines/{id}/runliveresponse` | PutFile, RunScript or GetFile on the endpoint | n/a | **EXCLUDE** for now (see section 3) | n/a | Machine.LiveResponse | **Preview**. 10/min, 50 concurrent sessions. |
| `GET /api/machineactions/{id}/GetLiveResponseResultDownloadLink(index={n})` | SAS link to a live response result | n/a | **DEFER**: only useful together with live response | n/a | Machine.ReadWrite.All | **Preview**. Link valid 30 minutes. |
| `GET /api/libraryfiles` | Lists live response library files | `defender_list_library_files` (optional) | **READ_ONLY** but **DEFER**: it needs the Library.Manage scope, which also grants write | n | Library.Manage | **Preview** |
| `POST /api/libraryfiles` (multipart, 20 MB max), `DELETE /api/libraryfiles/{fileName}` | Upload, overwrite or delete library scripts | n/a | **EXCLUDE**: a supply-chain risk, because uploaded scripts can run on any device | n/a | Library.Manage | **Preview** |

### 1b. Indicators (custom IoCs)

| Endpoint | What it does | Proposed tool | Tier and why | Approval | App permission | Notable limits |
|---|---|---|---|---|---|---|
| `GET /api/indicators` (`$filter`, `$top`≤10,000, `$skip`) | Lists active IoCs | `defender_list_indicators` | **READ_ONLY** | n | Ti.ReadWrite (only this app's own indicators) or Ti.ReadWrite.All. **No read-only TI scope exists.** | Returns active indicators only |
| `POST /api/indicators` `{indicatorValue*, indicatorType*, action*, title*, description*, expirationTime, severity, rbacGroupNames, generateAlert, …}` | Creates an IoC, or updates it when the same value is posted again | `defender_submit_indicator` | **Split by action**: Audit or Warn is **WRITE**; Block, BlockAndRemediate or **Allowed** is **DESTRUCTIVE**. It is a tenant-wide policy change. | y | Ti.ReadWrite.All | 15,000 active per tenant, hard cap. No CIDR, wildcards or ranges. DomainName also matches subdomains. Not enforced while AV is passive. The key used to match an update is undocumented (presumably value plus type). |
| `DELETE /api/indicators/{id}` | Removes an IoC | `defender_delete_indicator` | **DESTRUCTIVE**: tenant-wide, cannot be undone except by re-creating. Deleting an Allowed indicator turns detections back on; deleting a Block indicator unblocks. | y | Ti.ReadWrite.All | 204 on success, 404 if not found |
| `POST /api/indicators/import` `{Indicators:[≤500]}` | Bulk create or update | n/a | **DEFER**: bulk changes with partial-failure semantics | n/a | Ti.ReadWrite.All | 30/min. Results are per item (`isFailed`). |
| `POST /api/indicators/BatchDelete` `{IndicatorIds:[≤500]}` | Bulk delete | n/a | **DEFER/EXCLUDE**: whether a 403 or 404 rolls back the batch is undocumented | n/a | Ti.ReadWrite.All | 30/min |

### 1c. Alerts (MDE alert endpoints are GA. Graph `alerts_v2` is the strategic cross-product surface, and no retirement date is published.)

| Endpoint | What it does | Proposed tool | Tier and why | Approval | App permission | Notable limits |
|---|---|---|---|---|---|---|
| `GET /api/alerts` (`$filter`, `$top`≤10,000, `$expand=evidence`) | Lists alerts | `defender_list_alerts` | READ_ONLY | n | Alert.ReadWrite.All (the docs list no Alert.Read.All; check whether it is available in the tenant) | 100/min |
| `GET /api/alerts/{id}` | Gets one alert | `defender_get_alert` | READ_ONLY | n | as above | Whether `$expand` works on a single alert is undocumented |
| `GET /api/alerts/{id}/domains`, `/ips`, `/files`, `/machine`, `/user` | Entities related to an alert | `defender_get_alert_entities` (one composite tool) or 5 separate tools | READ_ONLY | n | URL.Read.All / Ip.Read.All / File.Read.All / Machine.Read.All / User.Read.All (the MDE permission, not the Graph one) | Docs examples for domains and IPs drop the `/api` prefix. Use `/api`. |
| `PATCH /api/alerts/{id}` | Sets status, assignee, classification, determination, comment | `defender_update_alert` | **WRITE**: fields can be patched back, but comments are append-only | y | Alert.ReadWrite.All (the page prints "Alerts.ReadWrite.All", a typo) | Determination enum names conflict across pages (ConfirmedActivity vs ConfirmedUserActivity, NotMalicious vs Clean). Test against a live tenant. |
| `POST /api/alerts/batchUpdate` | Updates many alerts | `defender_update_alerts_bulk` | **DESTRUCTIVE**: bulk change, and the empty response body gives no per-alert confirmation | y | Alert.ReadWrite.All | 10/min, 500/hr. No documented maximum for alertIds, so set a server-side cap. |
| `POST /api/alerts/CreateAlertByReference` | Creates an alert from an advanced hunting event | `defender_create_alert_from_event` | **DESTRUCTIVE** (or defer): starts AIR automatically, which can remediate; may merge into an existing alert; alerts cannot be deleted | y | Alert.ReadWrite.All | 15/min |

### 1d. Files

| Endpoint | Proposed tool | Tier | App permission | Notes |
|---|---|---|---|---|
| `GET /api/files/{id}` | `defender_get_file` | READ_ONLY | File.Read.All | SHA1 or SHA256. MD5 support is uncertain. |
| `GET /api/files/{id}/stats?lookBackHours=` | `defender_get_file_stats` | READ_ONLY | File.Read.All | Maximum 720 hours |
| `GET /api/files/{id}/alerts` | `defender_get_file_alerts` | READ_ONLY | Alert.ReadWrite.All (a write scope for a read) | SHA1 only. An unknown file returns an empty set. |
| `GET /api/files/{id}/machines` | `defender_get_file_machines` | READ_ONLY | Machine.ReadWrite.All (a write scope for a read) | SHA1 only |

### 1e. Org-level vulnerability management (TVM) and scores (all READ_ONLY, no approval; rate limits mostly not stated)

| Endpoint | Proposed tool | Permission | Status |
|---|---|---|---|
| `GET /api/vulnerabilities` (`$top`≤8,000) | `defender_list_vulnerabilities` | Vulnerability.Read.All | GA |
| `GET /api/vulnerabilities/{cveId}` and `/machineReferences` | `defender_get_vulnerability` (with an `include_machines` option) | Vulnerability.Read.All | Preview banner |
| `GET /api/vulnerabilities/machinesVulnerabilities` | `defender_list_machine_vulnerabilities_org` | Vulnerability.Read.All | GA |
| `GET /api/recommendations`; `/{id}`; `/{id}/software`; `/{id}/machineReferences`; `/{id}/vulnerabilities` | `defender_list_recommendations`, `defender_get_recommendation` (with sub-resource options) | SecurityRecommendation.Read.All. The software sub-resource needs Software.Read.All; the vulnerabilities sub-resource needs Vulnerability.Read.All. | list GA; rest preview |
| `GET /api/Software`; `/{Id}`; `/{Id}/distributions`; `/{Id}/machineReferences`; `/{Id}/vulnerabilities`; `/{Id}/getmissingkbs` | `defender_list_software`, `defender_get_software` (with sub-resource options) | Software.Read.All (vulnerabilities sub-resource: Vulnerability.Read.All) | list and getmissingkbs GA; rest preview |
| `GET /api/exposureScore`, `/api/exposureScore/ByMachineGroups`, `/api/configurationScore` | `defender_get_scores` | Score.Read.All | exposure: preview; configuration: GA |
| `GET /api/deviceavinfo` | `defender_get_device_av_health` | Machine.Read.All | GA. 30/min. **May need a token with audience `https://api.securitycenter.microsoft.com`, or the call returns 403.** |

---

## 2. Recommendations for the requested capabilities

| Capability | Tier | Rationale and safeguards |
|---|---|---|
| **Isolate** | DESTRUCTIVE | Takes a user offline, but `unisolate` reverses it. Safeguards: require `Comment` (it is mandatory in the API anyway; enforce at least about 10 characters, ideally with a ticket or alert reference). Make `IsolationType` an explicit enum, defaulting to `Selective` or `Full` per operator config, never omitted. **Per-hour cap on the number of devices isolated** (for example 3), separate from the general action budget. Single machine ID only, no bulk variant. Before acting, fetch `get_machine` and show hostname, OS, health, rbacGroup, exposure and criticality in the approval prompt (a dry-run preview). Refuse if the OS is unsupported, and warn about full-tunnel VPN. Optionally keep a deny-list of tags (for example `DomainController`, `Tier0`) that cannot be isolated. Return the MachineAction ID and suggest polling with `get_machine_action`. |
| **Unisolate** | WRITE | Asymmetric on purpose: it restores the safe state, and a recovery path should not sit behind the DESTRUCTIVE tier. Still require approval and a comment, because an attacker could use release to undo containment. Optionally warn if isolation was requested less than X minutes ago or by a different requestor. |
| **Restrict app execution** | DESTRUCTIVE | WDAC lockdown is more disruptive than isolation in practice, and the user cannot work. Use the same safeguards as isolate (shared device-per-hour cap, preview, tag deny-list). Check for Win10 1709+ and Defender AV active before calling. |
| **Unrestrict** | WRITE | Same asymmetry and reasoning as unisolate. |
| **AV scan** | WRITE | Not disruptive. It can still trigger remediation per AV policy, and a Full scan is heavy. Require `ScanType` explicitly (no default) and a comment. Treat duplicate 400 "Action is already in progress" as informational, not an error. A light hourly cap is reasonable. |
| **Stop and quarantine file** | DESTRUCTIVE | Kills processes and removes the file. This API set has **no unquarantine endpoint** (restoring is done in the portal or on the device), and a wrong hash can break legitimate software. Safeguards: validate a 40-character hex SHA-1. Before acting, run `GET /api/files/{sha1}` and `/stats` and show signer, prevalence and determination in the approval prompt. Refuse or warn on high global prevalence or a Microsoft signer (the API refuses Microsoft-signed files anyway). One machine per call. Recommend submitting a BlockAndRemediate indicator for fleet-wide handling instead of fanning this out across devices. |
| **Submit indicator** | **Split**: Audit and Warn are WRITE; Block, BlockAndRemediate and Allowed are DESTRUCTIVE | Every indicator changes tenant-wide (or device-group-wide) enforcement. Safeguards: <br>• **Never allow `Allowed` outside the DESTRUCTIVE tier.** Consider a separate opt-in flag, because an allow-list entry suppresses detections and makes AIR ignore bad verdicts. <br>• **Make `expirationTime` required** in the tool (the API leaves it optional) and cap it, for example at 90 days by default. <br>• Reject the legacy actions `Alert` and `AlertAndBlock`, which were retired January 2022 even though the POST page still lists them. <br>• Enforce the per-type action matrix: files take Allowed, Audit, Warn, Block or BlockAndRemediate; IPs, URLs and domains take Allowed, Audit, Warn or Block; certificates take Allowed or BlockAndRemediate. <br>• Require `generateAlert=true` with Audit. <br>• Reject CIDR, wildcards and ranges, and require full 8-segment IPv6. <br>• Warn that DomainName also matches subdomains, and refuse very broad domains (public suffixes, or the tenant's own domains). <br>• Before acting, look up existing indicators with `GET /api/indicators?$filter=indicatorValue eq '…'`, because a POST silently **updates** an existing indicator. Show "create" vs "overwrite" in the approval prompt. <br>• Show the rbacGroupNames scope; an empty scope means all devices, so flag it. <br>• Tag `application` or `title` with the server's identity so you can audit what this server created. <br>• Watch the 15,000 tenant cap. |
| **Delete indicator** | DESTRUCTIVE | Reverses enforcement in both directions: deleting a Block re-enables the file, URL or IP; deleting an Allowed re-enables detection. Fetch the indicator and show it in the approval prompt. Optionally restrict deletion to indicators this server created. |
| **Cancel machine action** | WRITE | Useful as an "oops" button after an isolate or quarantine that is still pending. It is a **preview** API, and the permission mapping is undocumented. |

**Cross-cutting:** route all new actions through the existing ActionGate (elicitation plus hourly budget). Add a separate **per-device cooldown**, because the API returns 400 for duplicates. Never accept "all" or wildcard machine IDs. After success, return a MachineAction ID to poll (the existing list and get machine action tools cover polling). Add sanitized `Comment` text to the audit log; `Validators.comment` already strips control and tag characters.

---

## 3. Exclude or defer

- **Offboard (`POST /api/machines/{id}/offboard`): EXCLUDE.** It blinds EDR on the device, cannot be reversed through the API (the device must be onboarded again), and offers an attacker an easy way to remove visibility. If the user ever wants it, add it behind a separate build or config flag at DESTRUCTIVE with a 1-per-day cap.
- **Live response (`runliveresponse`, `GetLiveResponseResultDownloadLink`) and library upload or delete: EXCLUDE.** In effect this is arbitrary code execution on endpoints, plus file push and pull. The APIs are preview, script side effects cannot be undone, and library upload is a tenant-wide supply-chain surface. A narrow future option: a **GetFile-only** live response tool at DESTRUCTIVE, with a path allow-list and no PutFile or RunScript.
- **Indicator import and BatchDelete: DEFER.** Bulk scope of up to 500 per call, partial-failure and rollback semantics are unclear, and single submit or delete covers interactive analyst use.
- **Alert batchUpdate and CreateAlertByReference: phase 3 at the earliest.** Bulk changes and automatic AIR respectively.
- **Incidents (`/api/incidents`): DEFER, use Graph instead.** This is the Defender XDR API with a preview banner, and Microsoft steers callers to Graph `/security/incidents`. Do the same for cross-product alerts (Graph `alerts_v2`, SecurityAlert.ReadWrite.All). The MDE alert endpoints are GA and not deprecated, so they are fine for now.
- **Authenticated scan definitions (`/api/DeviceAuthenticatedScanDefinitions*`): EXCLUDE.** The list responses contain stored SNMP credentials, and writes create recurring scans and store credentials. Preview.
- **Assessment "via files" exports (`/api/machines/*Export`): EXCLUDE.** They return Azure Blob SAS URLs, which are bearer secrets, at 5/min and 20/hr. The device AV health via-files path is documented incorrectly (it duplicates `InfoGatheringExport`).
- **Large JSON exports (`/api/machines/SoftwareVulnerabilitiesByMachine`, `SoftwareInventoryByMachine`, `SecureConfigurationsAssessmentByMachine`, etc.): DEFER.** They return up to 200k rows per page, which is not suitable as LLM tool output. If added later, use the delta export `SoftwareVulnerabilityChangesByMachine` (requires `sinceTime`, at most 14 days back) with strict result limits.
- **Browser extension permissionsinfo, baseline profiles and configurations, certificate inventory: DEFER.** Low value, and the permissions or `$filter` lists in the docs are unverified.

---

## 4. Overlaps and missing read tools

**Already covered (no work needed):**
- `defender_collect_investigation_package` covers `POST /api/machines/{id}/collectInvestigationPackage`.
- `defender_get_investigation_package_uri` covers `GET /api/machineactions/{id}/getPackageUri`. That endpoint is limited to **2/min and 120/hr**; make sure the client backs off.
- `defender_list_machine_actions` and `defender_get_machine_action` cover polling for every new action. Add the new types to the documented `type` enum: Isolate, Unisolate, RestrictCodeExecution, UnrestrictCodeExecution, RunAntiVirusScan, StopAndQuarantineFile, Offboard, LiveResponse, CollectInvestigationPackage.
- `defender_find_machines_by_ip` already implements find-by-internal-IP-at-time.
- Per-device software, vulnerabilities, recommendations and missing KBs are covered. The org-level equivalents in 1e are the gap.

**Tier inconsistencies worth reconsidering:**
- `get_investigation_package_uri` is DESTRUCTIVE, but the API call itself is read-only. Its sensitivity comes from the forensic SAS URL it returns. Keeping it gated is defensible; just document why.
- `collect_investigation_package` is DESTRUCTIVE but does not disrupt the device. It is forensic, so the current tier is acceptable.

**Naming collision:** `defender_indicator_lookup` (an IP, domain or file reputation composite) is not IoC management. Name the new tools `defender_list_indicators`, `defender_submit_indicator` and `defender_delete_indicator`, and say "custom IoC" in the descriptions so the model does not confuse them.

**Read tools that most help the response actions:**
- Alerts: list, get, related entities.
- Files: get, stats, alerts, machines. These feed the quarantine and indicator previews.
- `GET /api/indicators`, which feeds the duplicate and overwrite check before a submit.
- Org-level vulnerabilities, recommendations, software and scores.
- `deviceavinfo`, which lets the server check AV mode before AV scan, quarantine or indicator calls.

**Permission caveat:** several read endpoints document only ReadWrite scopes (`files/{id}/alerts` needs Alert.ReadWrite.All; `files/{id}/machines` needs Machine.ReadWrite.All; `/api/indicators` needs Ti.ReadWrite). A READ_ONLY deployment therefore still needs write-capable app roles, so the access tier has to be enforced by the server, not by Entra. Say this in `server_info` and the README.

---

## 5. Phased plan

**Phase 1: core containment and the reads it depends on (about 13 tools).**
- Actions: `isolate_machine` (D), `unisolate_machine` (W), `restrict_app_execution` (D), `unrestrict_app_execution` (W), `run_av_scan` (W), `stop_and_quarantine_file` (D), `cancel_machine_action` (W, preview).
- Reads: `get_file`, `get_file_stats`, `list_alerts`, `get_alert`, `get_alert_entities`, `get_device_av_health` (watch the token audience).
- Infrastructure: per-device cooldown, a separate containment device-per-hour cap, tag deny-list, pre-action preview built into the approval prompt, and the new types added to the machine-action enum.

**Phase 2: indicators and alert triage (about 6 tools).**
- `list_indicators` (R), `submit_indicator` (W for Audit/Warn, D for Block/BlockAndRemediate/Allowed; expiration required; legacy actions rejected; overwrite detection), `delete_indicator` (D).
- `update_alert` (W), `get_file_alerts`, `get_file_machines`.

**Phase 3: org-level TVM and optional bulk (about 7 to 9 tools).**
- `list_vulnerabilities`, `get_vulnerability`, `list_recommendations`, `get_recommendation`, `list_software`, `get_software`, `get_scores` (all READ_ONLY; many are preview).
- Optionally `update_alerts_bulk` (D, with an ID cap) and `create_alert_from_event` (D).
- Evaluate a Graph `alerts_v2` and incidents module at the same time.

**Not planned:** offboard, live response and its library, indicator import and BatchDelete, authenticated scan definitions, SAS-based exports.

---

## Uncertainties to verify in a test tenant

- `IsolationType` default when omitted.
- Indicator update matching key (presumably value plus type).
- BatchDelete partial-failure behaviour.
- Which permission `cancel` requires for each action type.
- Alert determination enum names.
- MD5 support on `GET /api/files/{id}`.
- Whether `Alert.Read.All` exists for application access.
- `deviceavinfo` token audience.
- Path casing: copy the documented casing exactly, for example `StopAndQuarantineFile`, `getPackageUri`, `getmissingkbs`.
- Rate limits are undocumented for most TVM endpoints.

Relevant files:
- `C:\MCP Dev\Microsoft-Defender-MCP\src\main\kotlin\com\jitunicornfx\defender\mcp\tools\MachineTools.kt`
- `C:\MCP Dev\Microsoft-Defender-MCP\src\main\kotlin\com\jitunicornfx\defender\mcp\PromptShield.kt`
- `C:\MCP Dev\Microsoft-Defender-MCP\src\test\kotlin\com\jitunicornfx\defender\mcp\DefenderClientSpec.kt`