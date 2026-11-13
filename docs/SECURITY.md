# Security model

This server holds credentials that can read, and optionally change, the security state of an
organisation's endpoints. It is driven by an AI model that reads attacker-influenced data: device
names, command lines, file names, alert text and comments. The design treats the model as
**potentially manipulated** at all times.

## Threats and controls

### 1. Prompt injection through API data

An attacker who controls something Defender records can try to plant instructions for the model.
Examples are a process command line, a scheduled-task name or a device name.

| Control | Where |
|---|---|
| Every string value **and object key** in a response has control characters, zero-width characters, bidi overrides and Unicode tag characters removed | `PromptShield.sanitize` |
| `<` and `>` are neutralized, so neither markup nor chat-template tokens (`<\|im_start\|>`) survive | `PromptShield.clean` |
| API data is wrapped in `<<<UNTRUSTED_DEFENDER_DATA id=NONCE>>>` fences. The 96-bit nonce is new for each response. Data cannot contain `<`, so it cannot forge the end marker | `PromptShield.fence` |
| Strings that look like instructions to an AI raise a warning outside the fence. The data itself is left in place as evidence | `PromptShield.looksLikeInjection` |
| Server instructions tell the client that fenced content is never instructions | `SERVER_INSTRUCTIONS` |
| Error messages never contain remote text outside a fence. Exception messages are reduced to class names | `ResponseRenderer`, `invokeTool` |
| URLs from responses (`@odata.nextLink`) are never shown to the model. The server keeps them behind random, expiring `page_token`s, which are bound to the issuing tool and resource. A nextLink is followed only if it is https, on an allow-listed Defender host for the cloud, and on the same resource path. Any other link stops paging and is never requested | `Pager`, `NextLinkPolicy`, `PageCursorStore` |

### 2. A manipulated model triggering harmful actions

| Control | Where |
|---|---|
| **Read-only by default.** Write and destructive tools are not even registered unless the operator raises the access level | `ToolRegistry.select` |
| **Human approval** of every state-changing call, and of reads that reveal secrets (the investigation-package link), through MCP elicitation. A client that cannot elicit is refused, so the server fails closed | `ActionGate`, `ElicitationApprover` |
| The approval prompt labels AI-supplied values (such as comments) as AI-supplied, with invisible characters removed | `ActionGate.approvalMessage` |
| **Action budget**: at most N state changes per rolling hour (default 20). The server refuses rather than queues, because a burst is the signature of a hijacked loop | `ActionBudget` |
| **Audit log**: every decision (approved, declined, unsupported, over budget) is written to stderr as one JSON line | `ActionGate.record` |
| High-impact response actions (isolate, offboard, quarantine, live response) are not implemented at all | — |
| Tool globs can only narrow the tool set. They can never expose a tool above the access level | `ToolRegistry.select` |

### 3. Malicious tool arguments

| Control | Where |
|---|---|
| Unknown argument names are refused | `Args` |
| Every identifier is validated against the narrowest shape: 40-hex device IDs, GUIDs, RFC 1123 domains, IP literals, account names. Values are never echoed in full in errors | `Validators` |
| IP addresses are parsed **without DNS resolution**, so a hostname can never trigger a lookup | `Validators.ipAddress` |
| Path segments are percent-encoded. `.`, `..` and `;` are refused or escaped | `Validators.seg` |
| Structured filters are built with quoted, escaped literals. Raw `$filter` is tokenized and checked against the endpoint's documented filterable fields | `OData` |
| KQL that can move data out of the tenant (`externaldata`, `external_table`, `http_request*`, `cluster()`, `database()`, `workspace()`, `app()`, `adx()`, `arg()`) is refused. The check runs on code with literals and comments stripped | `KqlGuard` |

### 4. Credential and network safety

| Control | Where |
|---|---|
| Secrets come only from the environment and never from the command line. `toString()` redacts them, and the startup banner prints variable names only | `Config`, `startupBanner` |
| The API host cannot be set freely. It is `https://api.security.microsoft.com`, one of seven fixed regional hosts chosen by code, or the government cloud's host. The cloud pins the login host, API host and scope together | `DefenderRegion`, `CloudEnvironment` |
| Redirects are never followed, so the bearer token cannot be bounced to a `Location` | `DefenderClient` |
| Response bodies are read through a byte cap. Tool output is limited to a character budget | `DefenderClient.readCapped`, `ResponseRenderer` |
| Token errors report only the validated OAuth error code and `AADSTS` numbers, never `error_description` | `EntraTokenProvider.describeFailure` |
| Access tokens are checked for header-safe characters before use | `EntraTokenProvider` |

### 5. Several tenants

With several named tenants, the new risk is cross-tenant. Injected text in one tenant's data could steer the model
to read or change another tenant.

| Control | Where |
|---|---|
| With several tenants and no `DEFENDER_DEFAULT_TENANT`, every call must name its tenant, so no call lands on a tenant by default | `ToolContext.resolveTenant` |
| A tenant name is matched only against the configured names. It is never put into a URL | `ToolContext.resolveTenant` |
| Each tenant has its own API client: token cache, rate limiters, concurrency limit and page-token store. Nothing that authenticates or pages is shared, and a page token from one tenant is unknown to another | `TenantContext`, `DefenderRuntime` |
| A tenant can narrow the access level (e.g. a production tenant read-only). The level is checked on every call before approval and before any request | `Config.accessFor`, `invokeTool` |
| Approval prompts and audit lines name the tenant. Each result starts with a server-written `Tenant: <name>` line | `ToolCall.authorize`, `invokeTool` |
| The hourly state-change budget is shared across tenants, so spreading actions over tenants does not raise the limit | `ActionGate` |
| Server info lists tenant names, clouds and hosts, but never secrets or tenant IDs | `ToolRegistry.serverInfoTool` |

### 6. Automatic updates

Self-updating code is a supply-chain path, so it is constrained at every step:

| Control | Where |
|---|---|
| The update client is separate and unauthenticated. Defender credentials and tokens are never sent to GitHub | `UpdateChecker`, `UpdateInstaller` |
| Only the newest published, non-prerelease release is considered, and only a strictly newer version. A tag must match a strict version pattern, or it is ignored | `UpdateChecker` |
| An asset is installed only if it carries GitHub's `sha256:` digest. The download is verified against that digest and against the published size | `UpdateChecker.parseAsset`, `UpdateInstaller` |
| Downloads come only over HTTPS from GitHub hosts, matched by exact name. Redirects are followed manually and re-checked, up to a limit | `UpdateChecker.isAllowedDownloadUrl`, `UpdateInstaller.downloadTo` |
| The downloaded JAR must contain this server's main class before it replaces anything. The old JAR is backed up and restored if a write fails | `UpdateInstaller` |
| On Windows the verified file is staged and swapped at exit, but only if it still matches its digest, the target has not changed, and no other server is running from it | `UpdateInstaller.installStagedAtShutdown` |
| Release text never reaches the model: notices are server-written and carry only the validated version | `notifyUpdateAvailable`, `UpdateStatus` |
| The build fails if the advertised `SERVER_VERSION` drifts from the release version, which prevents reinstall loops | `verifyServerVersion` (Gradle) |
| Operators can opt out of installing (`DEFENDER_DISABLE_AUTO_UPDATE`) or of the check entirely (`DEFENDER_DISABLE_UPDATE_CHECK`) | `Config` |

### 7. `--http` transport

- It binds to loopback by default. Off loopback it refuses to start without a bearer token of at least 32 characters.
- Bearer tokens are compared in constant time. Each client address is throttled after repeated failures (429).
- The Host header is checked on loopback binds, which defeats DNS rebinding.
- Origin is checked against an allow-list. CORS denies by default.
- Request bodies are capped (413), and the number of live sessions is capped.

## Reporting

Report vulnerabilities privately to the maintainers. Do not open a public issue.
