# Microsoft Defender for Endpoint MCP Server

A [Model Context Protocol](https://modelcontextprotocol.io) server that gives AI assistants controlled
access to the [Microsoft Defender for Endpoint API](https://learn.microsoft.com/en-us/defender-endpoint/api/exposed-apis-list).
It is written in Kotlin with the official [Kotlin MCP SDK](https://github.com/modelcontextprotocol/kotlin-sdk),
Ktor (OkHttp client, CIO server), coroutines and Clikt. It is built to be safe against prompt injection.

**Safe by default:** the server starts read-only. Every state-changing call needs explicit approval
from a human through the MCP client. All Defender data comes back fenced as untrusted. See
[docs/SECURITY.md](docs/SECURITY.md).

## API coverage

| Area | Tools | Access |
|---|---|---|
| Advanced hunting (via Microsoft Graph `runHuntingQuery`) | `defender_run_advanced_query` | read |
| Automated investigations | `defender_list_investigations`, `defender_get_investigation` | read |
| | `defender_start_investigation` | write + approval |
| | `defender_collect_investigation_package`, `defender_get_investigation_package_uri` | destructive + approval |
| Domain-related alerts | `defender_get_domain_alerts`, `defender_get_domain_machines`, `defender_get_domain_stats` | read |
| IP-related alerts | `defender_get_ip_alerts`, `defender_get_ip_stats` | read |
| Machines | `defender_list_machines`, `defender_get_machine`, `defender_get_machine_logon_users`, `defender_get_machine_alerts`, `defender_get_machine_software`, `defender_get_machine_vulnerabilities`, `defender_get_machine_recommendations`, `defender_get_machine_missing_kbs`, `defender_find_machines_by_ip`, `defender_find_machines_by_tag`, `defender_list_machine_actions`, `defender_get_machine_action` | read |
| | `defender_tag_machine`, `defender_set_device_value` | write + approval |
| | `defender_tag_machines_bulk`, `defender_update_machine` (replaces the tag set) | destructive + approval |
| Remediation activity | `defender_list_remediation_tasks`, `defender_get_remediation_task`, `defender_get_remediation_task_machines` | read |
| Users | `defender_get_user_alerts`, `defender_get_user_machines` | read |
| Composite (concurrent) | `defender_machine_triage`, `defender_indicator_lookup` | read |
| Meta | `defender_server_info` | read |

Machine-action response tools (isolate, restrict app execution, offboard, quarantine, live response)
are deliberately **not** included.

## Prerequisites

- JDK 21 or newer (the build targets JVM 21 bytecode).
- An Entra ID app registration with a client secret. Grant it these **application** permissions on
  *WindowsDefenderATP* and give admin consent. Grant only what you use:

| Permission | Used by |
|---|---|
| `ThreatHunting.Read.All` (on **Microsoft Graph**, not WindowsDefenderATP) | advanced hunting |
| `Machine.Read.All` | machine reads, machine actions |
| `Machine.ReadWrite.All` | tagging, device value, update machine |
| `Machine.CollectForensics` | collect investigation package |
| `Alert.Read.All` / `Alert.ReadWrite.All` | domain/IP/user/machine alerts, investigations (start needs ReadWrite) |
| `User.Read.All` | user tools |
| `Software.Read.All`, `Vulnerability.Read.All`, `SecurityRecommendation.Read.All` | software, vulnerabilities, recommendations, missing KBs |
| `RemediationTasks.Read.All` | remediation activity |

## Build

```bash
./gradlew shadowJar
```

This writes `build/libs/microsoft-defender-mcp-0.1.0-all.jar`. `./gradlew check` runs the kotest suite and
enforces the JaCoCo coverage gate (90% line, 80% branch). The HTML report is in `build/reports/jacoco/test/html`.

## Configure

Configuration comes from environment variables, so secrets never appear on a command line. See
[.env.example](.env.example).

| Variable | Default | Meaning |
|---|---|---|
| `DEFENDER_TENANT_ID`, `DEFENDER_CLIENT_ID`, `DEFENDER_CLIENT_SECRET` | required (single tenant) | App registration credentials. For several tenants use `DEFENDER_TENANTS` instead (see [Multiple tenants](#multiple-tenants)) |
| `DEFENDER_TENANTS`, `DEFENDER_DEFAULT_TENANT` | unset | Named tenants, and the one used when a call names none |
| `DEFENDER_CLOUD` | `commercial` | `commercial`, `gcc`, `gcc-high`, `dod`. Sets the login host, API host and token scope together |
| `DEFENDER_REGION` | global | Regional endpoint (commercial cloud only): `us`, `eu`, `uk`, `au`, `swa`, `ina`, `aea` map to `https://<code>.api.security.microsoft.com`. Unset uses `https://api.security.microsoft.com` |
| `DEFENDER_ACCESS_LEVEL` | `read-only` | `read-only`, `write`, `destructive` |
| `DEFENDER_CONFIRMATION` | `elicit` | `elicit` (a human approves each state change) or `none` |
| `DEFENDER_MAX_ACTIONS_PER_HOUR` | `20` | State-changing calls allowed per rolling hour |
| `DEFENDER_MAX_CONCURRENT_REQUESTS` | `4` | Concurrent outbound API calls |
| `DEFENDER_TIMEOUT_MS` | `60000` | Per-request timeout |
| `DEFENDER_MAX_RESPONSE_BYTES` | `16777216` | Bytes read from one response (memory guard) |
| `DEFENDER_MAX_RESULT_CHARS` | `200000` | Characters one tool result may carry (context budget) |
| `DEFENDER_TOOLS` | all permitted | Comma-separated tool-name globs |
| `DEFENDER_MCP_AUTH_TOKEN` | unset | Bearer token for `--http`. Required, and at least 32 characters, off loopback |
| `DEFENDER_HTTP_ALLOWED_ORIGINS` | none | Browser origins allowed in `--http` mode |

### Multiple tenants

To serve several Defender tenants from one server, give each one a name and its own app registration.
Set `DEFENDER_TENANTS` instead of the three single-tenant variables:

```bash
DEFENDER_TENANTS=contoso,fabrikam-lab
DEFENDER_CONTOSO_TENANT_ID=…        DEFENDER_CONTOSO_CLIENT_ID=…        DEFENDER_CONTOSO_CLIENT_SECRET=…
DEFENDER_FABRIKAM_LAB_TENANT_ID=…   DEFENDER_FABRIKAM_LAB_CLIENT_ID=…   DEFENDER_FABRIKAM_LAB_CLIENT_SECRET=…
DEFENDER_FABRIKAM_LAB_REGION=eu     # optional per tenant: _CLOUD, _REGION, _ACCESS_LEVEL
DEFENDER_CONTOSO_ACCESS_LEVEL=read-only
```

- **Names:** 1-32 lowercase letters, digits or `-`, starting with a letter. In variable names the name is
  upper-cased and `-` becomes `_` (`fabrikam-lab` → `DEFENDER_FABRIKAM_LAB_…`).
- **Shared defaults:** `DEFENDER_CLOUD` and `DEFENDER_REGION` apply to every tenant that sets neither (a region only to
  commercial tenants). A tenant's `_ACCESS_LEVEL` can narrow the server-wide `DEFENDER_ACCESS_LEVEL` but never widen it.
  A tenant that asks for more is capped. The server says so in a startup warning and in `defender_server_info`'s
  `accessWarnings`, so set `DEFENDER_ACCESS_LEVEL` (or `--access`) as well.
- **The `tenant` argument:** every API tool gains a `tenant` argument listing the configured names. It is required
  unless `DEFENDER_DEFAULT_TENANT` names a default. Each result starts with `Tenant: <name>`, and approval prompts
  and audit lines name the tenant.
- **Isolation:** each tenant has its own API client (token cache, rate limits, concurrency) and its own page tokens,
  so a `page_token` from one tenant is meaningless to another. The hourly state-change budget is shared, because it
  exists to stop a runaway agent, whichever tenant it targets.
- **Mixing is refused:** setting `DEFENDER_TENANTS` together with `DEFENDER_TENANT_ID` / `CLIENT_ID` / `CLIENT_SECRET`
  is refused. The single-tenant variables keep working on their own, as one tenant named `default`.
- **`--check`:** checks every tenant concurrently and reports each by name.

Check the configuration (this acquires a Defender API token and a Microsoft Graph token per tenant, then exits):

```bash
java -jar build/libs/microsoft-defender-mcp-0.1.0-all.jar --check
```

## Run

```text
Usage: microsoft-defender-mcp [<options>]

  --stdio / --http             Transport (default --stdio)
  --host TEXT                  HTTP bind address (default 127.0.0.1)
  --port INT                   HTTP port (default 3074)
  --region [us|eu|uk|au|swa|ina|aea]   (single tenant only)
  --access [read-only|write|destructive]
  --no-confirm                 Skip human approval (unattended automation only)
  --max-actions-per-hour INT
  --tools TEXT                 Tool-name glob(s), repeatable
  --check                      Validate configuration and exit
```

### Claude Desktop / Claude Code (stdio)

```json
{
  "mcpServers": {
    "defender": {
      "command": "java",
      "args": ["-jar", "C:/path/to/microsoft-defender-mcp-0.1.0-all.jar"],
      "env": {
        "DEFENDER_TENANT_ID": "…",
        "DEFENDER_CLIENT_ID": "…",
        "DEFENDER_CLIENT_SECRET": "…"
      }
    }
  }
}
```

### Streamable HTTP / SSE

```bash
DEFENDER_MCP_AUTH_TOKEN=$(openssl rand -hex 32) java -jar microsoft-defender-mcp-0.1.0-all.jar --http --port 3074
```

Streamable HTTP is served at `/mcp` and the legacy HTTP+SSE transport at `/sse`.

## Design notes

- **Coroutines** run all I/O. A `Semaphore` limits concurrency. Sliding-window limiters that suspend
  rather than block keep calls within Defender's quotas (100/min, 45/min for hunting, 2/min for package
  links). Token refresh is single-flight behind a `Mutex`. The triage tools use structured concurrency
  (`coroutineScope` + `async`) to fetch independent resources in parallel.
- **Paging** follows [Microsoft Graph paging](https://learn.microsoft.com/en-us/graph/paging). The first request of a
  listing uses `top`, `skip` and `filter`. Each later page is fetched by requesting `@odata.nextLink` verbatim, never by
  rebuilding it from `$skip`/`$skiptoken`. The link stays on the server: the model gets an opaque `page_token`
  (30-minute lifetime, bound to the tool and resource) and passes it back to continue. `max_pages` (1-10) follows
  several links in one call. A page trimmed to fit the output budget resumes at the exact next record. If the API
  rejects a page token with `DirectoryPageTokenNotFoundException`, the server re-reads the last successful page once,
  skips the records already returned and continues. If that also fails, it asks for the listing to be restarted.
- **Retries:** a 429 is retried after `Retry-After`, up to a cap. Transient 5xx errors are retried
  only for reads. A 401 refreshes the token once.
