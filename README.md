# Red Agent

After a Red Team engagement ends, this tool provides the following features based on the findings in the submitted report:
- Retest feature: Tests whether findings have been remediated and reports the result

This repository is meant to be run **directly from a checkout with `make dev`** (Vite dev server + uvicorn with reload). There is no build-and-serve step to perform: hosting, TLS, and the SOCKS transport are provisioned separately and are not part of this repository.

## Architecture

```
┌─────────────┐     ┌──────────────────────┐     ┌──────────────┐
│  Frontend   │────▶│      Agent API       │────▶│ LLM Server   │
│ (Vite+React)│     │      (FastAPI)       │     │ (LMStudio…)  │
│  :5173      │     │       :8000          │     │  :1234       │
└─────────────┘     └──────────────────────┘     └──────────────┘
                       │        │        │
                       │        │        └─▶ ┌──────────────────────────┐
                       │        │            │ tools/AD_Recon/          │
                       │        │            │ ad_dns_recon.py          │
                       │        │            │ (DC auto-discovery subprocess) │
                       │        │            └──────────────────────────┘
                       │        │
                       │        └─▶ ┌──────────────┐
                       │            │  Kali MCP    │
                       │            │  (stdio)     │
                       │            └──────────────┘
                       │
                       ▼
              ┌────────────────────────────┐
              │  SQLite                    │
              │  ./data/retest_history.db  │
              │  (retest result persistence) │
              └────────────────────────────┘
```

- **Frontend**: Vite + React + TailwindCSS. UI for the finding list and retest execution
- **Agent API**: FastAPI-based AI agent. Orchestrates confirmation-command generation for findings, HITL approval, and command execution on Kali. Directly invokes the LLM and Kali MCP
- **LLM Server**: An LLM server providing an OpenAI-compatible API (LM Studio, llama.cpp's `llama-server`, etc.). Prepared separately; point `LLM_BASE_URL` at it
- **Kali MCP**: An MCP server that executes commands on Kali Linux. The Agent API launches it as a child process over stdio and communicates via the MCP protocol
- **DC Discovery (ad_dns_recon)**: A helper script that, during verification, automatically obtains the AD domain's DC (FQDN/IP) via SMB→Registry→DNS SRV. Launched as a subprocess by the Agent API
- **SQLite**: A persistence store for retest results (markdown + final_output). Used for sharing history across browsers

Traffic to the target range goes through a SOCKS5 proxy on `127.0.0.1:${SOCKS_PORT}` (default `1080`). That proxy is provisioned outside this repository; the agent only consumes it (via `proxychains`).

## Getting started

### Prerequisites

- Python 3.11 or later
- [Bun](https://bun.sh/) v1.0 or later (for the Frontend)
- GNU Make
- `proxychains` configured to point at the SOCKS5 proxy (`127.0.0.1:1080` by default)
- Reachability to an OpenAI-compatible LLM endpoint

### 0. Quick Start
```
make install
(edit .venv suitable for your environment)
cp data/findings-sample.json findings.json
make dev
```


### 1. Install dependencies

```bash
make install
```

This is the only setup command. It does all of the following, and re-running it is safe:

1. `bun install` (front/)
2. Creates the project root's `venv/` if missing, then `pip install -r requirements.txt` into it
3. Creates `.env` and `data/findings.json` from their samples **when they do not already exist** (an existing file is never overwritten)

Installing Python packages system-wide is never attempted, so this works on distributions that block it under PEP 668 (Kali, recent Debian/Ubuntu). If venv creation itself fails, install the OS package first: `sudo apt install python3-venv`.

The generated `.env` leaves `SESSION_SIGNING_SECRET` empty, so **authentication is disabled** and `make dev` opens straight into the app with no login screen. See "Authentication (login)" to turn it on.

`make dev-agent` automatically activates `venv/` before running Python commands, so it does not need to be activated manually (if `venv/` is missing it warns and falls back to the system python). To use a different venv directory name, override it with `VENV_DIR`, e.g. `make VENV_DIR=.venv install`.

### 2. Point `.env` at your LLM

`make install` already created `.env`. Edit it:

```bash
$EDITOR .env
```

At minimum, set `LLM_BASE_URL` / `LLM_MODEL` / `LLM_API_KEY` for the LLM endpoint you were given. **This is the only value you must fill in** — everything else has a working default. If they are left unset, the agent falls back to `http://localhost:1234/v1` and every retest fails. See the "Environment variables" section for the rest. `make dev` sets `APP_ENV=dev` automatically, which makes the session cookie non-Secure so login works over plain `http://localhost:5173`.

Leave `VITE_API_BASE_URL` **empty**. The frontend then uses relative paths, and the Vite dev server proxies `/api`, `/threads`, and `/health` to the Agent API — so the browser talks to a single origin and no CORS configuration is needed, including when you open the UI from another machine at `http://<host>:5173`.

### 3. Adjust the findings (optional)

`make install` already created it from the sample, so you can go straight to `make dev` and click through the app with the sample findings.

```bash
$EDITOR data/findings.json                    # the file FINDINGS_FILE points to
```

It lives outside version control (only `data/findings-sample.json` is tracked), so your edits are never committed. See "Findings data" below for the field-by-field meaning.

To regenerate either after deleting it, run `make bootstrap-config` — it recreates only what is missing and leaves existing files alone.

### 4. Create a login user (optional)

Skip this for a local `make dev` trial — `make install` leaves auth disabled.

Authentication is enabled only when `SESSION_SIGNING_SECRET` is set. Because **no one can log in with zero users**, create at least one:

```bash
python -c "import secrets; print('SESSION_SIGNING_SECRET=' + secrets.token_hex(32))"   # paste into .env
make create-user USER=alice     # password entered interactively
```

Leaving `SESSION_SIGNING_SECRET` empty disables auth entirely (every endpoint open). That is convenient for a purely local trial, but do not do it on a shared host.

### 5. Run

```bash
# Start Frontend + Agent API together (front :5173 / agent :8000)
make dev

# Start individually
make dev-front
make dev-agent
```

Then open http://localhost:5173. The API spec is available at http://localhost:8000/docs (Swagger UI) or http://localhost:8000/redoc (not exposed when `ENABLE_DOCS=false`).

The Agent API alone can also be started without make:

```bash
uvicorn agent.main:app --reload --host 0.0.0.0 --port 8000
```

### Other make targets

```bash
make build            # frontend type check + production bundle (verification only)
make lint             # ESLint for the frontend
make bootstrap-config # recreate any missing .env / findings.json from samples
make list-users       # list login users
make reset-password USER=alice
make clean          # remove front/node_modules
```

## Environment variables

Copy `.env.example` to create `.env`. The file is read by the Makefile as well, so keep it in plain `KEY=VALUE` form (no quoting, no shell expansion).

### Frontend

| Variable | Description | Default |
|--------|------|-----------|
| `VITE_API_BASE_URL` | API endpoint the frontend connects to. **Keep empty** so relative paths go through the Vite proxy | (empty) |
| `VITE_THREADS_BASE_URL` | Override when running `/threads` on a different host | (empty = same as API_BASE) |
| `VITE_ENABLE_SOCKS_CHECK` | Block Retest / RTO execution while SOCKS is down. `.env.example` ships `false` so a local trial works without a proxy | `true` |
| `VITE_ENABLE_RETEST` / `VITE_ENABLE_RTO` / `VITE_ENABLE_COMMAND_APPROVAL` | Build-time feature flags. A disabled feature is excluded from nav, home cards, and routing | `true` / `true` / `true` |
| `FRONTEND_PORT` | Listen port of the Vite dev server | `5173` |
| `FRONTEND_ALLOWED_HOSTS` | Hostnames allowed by Vite's Host check (comma-separated). Needed only when reaching the dev server under a name other than localhost | (empty) |
| `FRONTEND_HMR_CLIENT_PORT` | Port the browser uses for Vite HMR (WebSocket) when the dev server sits behind a reverse proxy that terminates on a different port. Empty = same as the dev server port | (empty) |
| `AGENT_PORT` | Agent API port (Vite proxy target) | `8000` |

### Agent API

| Variable | Description | Default |
|--------|------|-----------|
| `APP_ENV` | Run mode. `make dev` sets `dev` automatically. When `dev`, the Cookie Secure default below becomes false | `prod` |
| `SESSION_SIGNING_SECRET` | Session cookie signing key (a long random value). Empty disables auth. Users are managed in the DB (`users`) and created with `tools/auth/manage_users.py` | (empty) |
| `SESSION_TTL_SECONDS` | Session lifetime (seconds) | `28800` |
| `SESSION_COOKIE_SECURE` | The cookie's Secure attribute. If unspecified, depends on `APP_ENV` (dev=false / prod=true). An explicit value takes precedence | (depends on APP_ENV) |
| `SESSION_COOKIE_NAME` | Session cookie name | `ra_session` |
| `MFA_SECRET_KEY` | Fernet key encrypting TOTP secrets at rest. MFA enrollment is possible only when set | (empty) |
| `MFA_CHALLENGE_TTL_SECONDS` | Lifetime of the MFA challenge token (login step 1 → step 2) | `300` |
| `LOGIN_LOCKOUT_THRESHOLD` / `LOGIN_LOCKOUT_WINDOW_SECONDS` | Temporary, auto-clearing throttling of login failures (429 without verifying credentials) | `5` / `900` |
| `AUDIT_LOG_RETENTION_DAYS` | Retention days for the audit log (`audit_log`). An in-app task periodically deletes rows beyond this | `180` |
| `AUDIT_LOG_PRUNE_INTERVAL_HOURS` | Interval for periodic audit-log deletion (hours; also once right after startup) | `24` |
| `CORS_ORIGINS` | Allowed CORS origins (comma-separated) | `http://localhost:5173,http://127.0.0.1:5173` |
| `CORS_ORIGIN_REGEX` | Regex for origins allowed in addition to the above | `^https?://(localhost\|127\.0\.0\.1):\d+$` |
| `ENABLE_DOCS` | Whether to expose `/docs` `/redoc` `/openapi.json` | `true` |
| `ENABLE_COMMAND_APPROVAL` | Server-side gate for the command-approval (HITL) feature. Keep in sync with `VITE_ENABLE_COMMAND_APPROVAL` | `true` |
| `THREAD_SECRET_TTL_SECONDS` | In-memory retention seconds for the secret (password) tied to a thread | `3600` |
| `SSE_PING_INTERVAL_SECONDS` | Heartbeat interval for SSE (`:ping` comments) | `15` |
| `LOG_LEVEL` | Minimum level for the application logger | `INFO` |

### SOCKS

| Variable | Description | Default |
|--------|------|-----------|
| `SOCKS_HOST` | Host of the SOCKS5 proxy | `127.0.0.1` |
| `SOCKS_PORT` | Port of the SOCKS5 proxy (the hop used by `ad_dns_recon` / proxychains) | `1080` |
| `SOCKS_CHECK_PORT` | Port that remote SOCKS clients dial **into** (the reverse-tunnel control port). Switches liveness to an ESTABLISHED-connection check. Empty = listen check | (empty) |

The proxy itself is provisioned outside this repository and **any SOCKS5 implementation works as-is**. The agent only consumes it through proxychains and never manages it — no management API is required, because upstream SOCKS servers do not provide one.

`GET /api/v1/health/socks` has two modes, picked by whether `SOCKS_CHECK_PORT` is set. The frontend polls it every 5s and shows the result in the header.

| Mode | Condition | `active` means | Accuracy |
|---|---|---|---|
| `established` | `SOCKS_CHECK_PORT` set | An ESTABLISHED TCP connection exists on that port, i.e. **a client is attached** | Reflects real usability |
| `listen` | `SOCKS_CHECK_PORT` empty | A TCP connect to `SOCKS_HOST:SOCKS_PORT` succeeds | Only proves the proxy is listening |

Response: `{"active": bool, "mode": "established"|"listen", "host": str, "port": int, "client_count": int|null}`.

**Point `SOCKS_CHECK_PORT` at the inbound control port, never at `SOCKS_PORT`.** `SOCKS_PORT` is the local proxychains hop: it has no connections while idle, and counting there would also pick up the health check's own connection.

TCP state is read via `psutil` from the OS connection table (`/proc/net/tcp` on Linux — world readable, so no elevated privileges are needed; PIDs are never inspected).

When `VITE_ENABLE_SOCKS_CHECK` is enabled, `active: false` blocks both Retest and RTO from starting. There is no way to list or disconnect clients from this app.

### LLM Server

| Variable | Description | Default |
|--------|------|-----------|
| `LLM_BASE_URL` | Base URL of the LLM server | `http://localhost:1234/v1` |
| `LLM_MODEL` | LLM model name to use | `local-model` |
| `LLM_API_KEY` | LLM API key | `lm-studio` |
| `LLM_TEMPERATURE` | LLM temperature | `0.2` |
| `LLM_TIMEOUT` | LLM request timeout (seconds) | `3600` |

### Findings / Kali MCP

| Variable | Description | Default |
|--------|------|-----------|
| `FINDINGS_FILE` | Path to the findings JSON file | `./data/findings.json` |
| `KALI_MCP_COMMAND` | Command to launch the Kali MCP server. If unset, the Python running the agent is used | (sys.executable) |
| `KALI_MCP_SCRIPT` | Path to the Kali MCP server script | `./kali-mcp/server.py` |
| `KALI_PROXY_ENABLED` | Master switch for prefixing proxychains. `false` never prefixes regardless of the `use_proxychains` value | `true` |
| `KALI_PROXY_COMMAND` | The command string to prefix | `proxychains -q` |

### Retest history (SQLite persistence)

| Variable | Description | Default |
|--------|------|-----------|
| `DATABASE_URL` | SQLAlchemy URL. Non-SQLite (e.g. PostgreSQL) can also be specified | `sqlite+aiosqlite:///./data/retest_history.db` |
| `RETEST_FINAL_OUTPUT_MAX_BYTES` | Storage cap in bytes for `final_output_json` (0 = unlimited; when exceeded, truncated keeping head and tail) | `1048576` |

### DC auto-discovery (ad_dns_recon)

| Variable | Description | Default |
|--------|------|-----------|
| `AD_DNS_RECON_TIMEOUT` | Subprocess execution timeout per run (seconds) | `60` |
| `AD_DNS_RECON_MAX_ATTEMPTS` | Number of retries when zero results were obtained | `2` |
| `AD_DNS_RECON_RETRY_DELAY_SECONDS` | Wait seconds between retries | `2` |

### Entra collection (roadrecon)

| Variable | Description | Default |
|--------|------|-----------|
| `ROADRECON_BIN` | roadrecon executable (absolute path if outside PATH) | `roadrecon` |
| `ROADRECON_TOKEN_TYPE` | Injected token type (`prt-cookie` / `refresh-token` / `access-token`) | `prt-cookie` |
| `ENTRA_DB_DIR` | Output directory for the collection SQLite (roadrecon.db) (per tenant) | `./data/entra` |
| `ENTRA_RECON_PROXYCHAINS` | Whether to run collection through proxychains (SOCKS) | `true` |
| `ENTRA_RECON_TIMEOUT` | Timeout for roadrecon auth / gather (seconds, parent process). For huge tenants, raise to `1800`–`3600` | `900` |
| `ROADRECON_TIMEOUT` | Per-subcommand timeout for each roadrecon subcommand (seconds, child process) | `600` |
| `ENTRA_GATHER_JOB_TTL_SECONDS` | Seconds to keep collection job state in memory (after which polling returns 404 → falls back to confirming via the list) | `1800` |

roadrecon is not in `requirements.txt` because of its large dependency tree. Install it into the venv only if you need Entra ID verification:

```bash
./venv/bin/pip install roadrecon
```

Collection (`roadrecon gather`) is run by the Agent API wrapped in `proxychains` over SOCKS (`ENTRA_RECON_PROXYCHAINS=true`). Token injection and collection are performed from the UI's "Settings" screen after startup.

> **Collection is asynchronous (job + polling)**: `POST /api/v1/entra/gather` starts collection in the background and immediately returns **202 + `job_id`**. The frontend polls `GET /api/v1/entra/gather/jobs/{job_id}` with backoff (4s→8s, up to 15 minutes) to wait for completion. Even if gather takes several minutes for a huge tenant, each HTTP request stays short. For CLI use that wants synchronous bulk collection, use `POST /api/v1/entra/collect` (`roadrecon --mode both`).

## Findings data

`FINDINGS_FILE` (default `./data/findings.json`) is the source of truth for both the finding list shown in the UI and the verification logic. Start from `data/findings-sample.json`:

```jsonc
{
  "report_metadata": {
    "company_name": "Example Corp",
    "generated_at": "2026-01-15T10:00:00+09:00",   // ISO-8601 with offset
    "total_findings": 3
  },
  "findings": [
    {
      "section": 1,                                 // order of appearance; drives the No.<n> identifier
      "platform": ["ad"],                           // "ad" / "entra" / "other" / "retest_not_supported"
      "verification_inputs": [],                    // values prompted for at run time
      "judgment_criteria": "…conditions for deciding Resolved…",
      "tool_hints": ["nxc ldap", "impacket-GetUserSPNs"],  // optional; when set, restricts verification to ONLY these tools
      "title": "An SPN is bound to a domain administrator account",
      "risk_level": "High",
      "summary": "…",
      "description": "…",
      "recommendation": "…",
      "references": [{ "name": "…", "url": "https://…" }]
    }
  ]
}
```

Fields used along the verification path:

| Item | What to fill in |
|------|----------------------|
| `platform` | Target environment (see "Setting `platform`" below). Multiple allowed, e.g. `["ad","entra"]`. Unspecified is treated as `["other"]` |
| `verification_inputs` | Declarations of data variables to prompt the user for at run time (optional; see "Runtime user input"). Empty means no input form is shown |
| `judgment_criteria` | The judgment criteria for deciding "Resolved" (if Unspecified, judged by whether the recommended remediation was applied) |
| `tool_hints` | Optional list restricting which tools verify this finding (e.g. `["nxc ldap", "impacket-GetUserSPNs"]`). Surfaced to the planner as `[Tools to Use]`. **When set, the agent uses ONLY these tools**, falling back to another tool only when the check cannot be determined with them (and it must say why). Empty/omitted lets the agent choose tools freely |

The agent authors the actual verification commands itself from `title` / `description` / `recommendation` / `judgment_criteria`; the findings file declares **what to check**, not how — except that `tool_hints`, when set, restricts **which tools** may be used.

### Setting `platform`

`platform` is the one field that changes how a finding is *executed*, so it is worth getting right. It is an array; a bare string is coerced to a one-element array, and an empty/missing value becomes `["other"]`.

| Value | Meaning |
|---|---|
| `ad` | On-prem Active Directory. Needs AD credentials; commands reach the target network |
| `entra` | Microsoft Entra ID (cloud). Verified against the roadrecon database collected beforehand |
| `other` | Everything else (Linux/Unix, web apps, …). The agent infers the environment from the finding text |
| `retest_not_supported` | Automated retest is impossible (manual confirmation only). The retest button is disabled in the UI |

What the value actually drives:

- **The `[Target Platform]` block in the prompt.** Taken as authoritative — the agent never infers the environment from the finding text when this is set.
- **Whether the Entra database path is supplied.** Only when `entra` is present does the prompt carry the collected `roadrecon.db` path. An AD-only finding never sees it, so an unrelated database cannot be dangled in front of the agent.
- **proxychains.** The starting point for deciding SOCKS routing per command (see the proxychains section under "Kali MCP integration").
- **Which credentials the UI asks for.** An **`entra`-only** finding skips the AD credential modal; if two or more tenants were collected, a tenant picker is shown instead. Any finding that includes `ad` takes the AD credential flow.
- **Whether retest can start at all.** `retest_not_supported` disables the button in both the finding list and the detail view.

Combine values when a finding genuinely spans environments: `["ad","entra"]` makes the agent check both sides and gives it both the AD credentials and the Entra database path.

### SQLite (retest history)

`./data/retest_history.db` is created automatically when `make dev-agent` starts. Tables are initialized with `Base.metadata.create_all()`, so no migration is needed (Alembic is expected to be introduced separately for future schema changes).

Because history is written by the backend on SSE `final`, no client-side persistence such as IndexedDB is used on the frontend. The same history is visible across browsers.

## Kali MCP integration

At startup the Agent API launches `kali-mcp/server.py` as a child process and communicates via the MCP protocol over stdio.

As a prerequisite, Python and the fastmcp package are required on Kali (installed by `make install` via `requirements.txt`).

The script path can be changed with the `KALI_MCP_SCRIPT` environment variable. The default is `kali-mcp/server.py` relative to the project root.

### proxychains

Prefixing is decided **per command**, by the agent. `execute_kali_command(command, use_proxychains)` prefixes `KALI_PROXY_COMMAND` (default `proxychains -q`) only when `use_proxychains=true`, which is also the default when the argument is omitted. A command that already starts with `proxychains` is left alone, so it is never double-prefixed. `KALI_PROXY_ENABLED=false` is a master switch that suppresses prefixing entirely. Never write `proxychains` into the command string; pass the decision through the argument.

The agent decides from `platform` plus what the command actually touches — the two do not always agree, so it is judged per command rather than per finding:

| Command reaches | proxychains | Example |
|---|---|---|
| The target network | **yes** | `nxc smb <dc> -u … -p …`, `ldapsearch`, `dig @<target DNS>` |
| Only the local `roadrecon.db` (Entra retest) | **no** | `roadrecon-view … --database <path>` |
| Kali itself | **no** | `cat`, `grep`, `sqlite3 <local file>` |

Entra is the case worth noting: collection reaches the cloud and is done server-side beforehand, whereas a **retest only reads the local database**, so routing it through the proxy would make it fail. When the agent cannot tell, it chooses proxychains — failing to reach the target is worse than a wasted hop.

There is no server-side override; the decision is the agent's, guided by `agent/prompts.py`.

### Runtime user input (verification_inputs)

Prompt the user for data variables that change per run, such as the target server, **before executing the retest**. Only when a finding declares `verification_inputs` does the frontend show an input form (modal) before execution (**not shown for findings without a declaration**).

- Make `key` match the command's `{{key}}`, and also list that variable name in the command's `variables`.
- The server-side validates the input with `pattern` (an allowlist regex) via `fullmatch` before injecting it (to guard against command injection). The default `pattern` allows only IP/hostname-equivalent values (rejects whitespace, quotes, `;`, etc.).
- **Server-injected values take precedence** for `domain`/`user`/`password`/`dc`, etc.; user input cannot replace credentials or the DC (only data variables are satisfied).

Declaration fields:

| Field | Required | Content |
|---|---|---|
| `key` | ✓ | Variable name (matches the command's `{{key}}`) |
| `label` | ✓ | Display name of the input field |
| `placeholder` | optional | Placeholder of the input field |
| `required` | optional | Default `true`. `false` for optional input |
| `multiple` | optional | Default `false`. `true` for multiple values (an add/remove multi-row UI). Each value is validated individually with `pattern` and **joined space-separated** into one variable |
| `pattern` | optional | Allowed regex per value. Default is `^[A-Za-z0-9_.-]+$` |

**Notes to keep commands from breaking**

- Place `multiple` variables (multiple values) **unquoted** → `nxc smb {{targets}} ...`. Quoting makes `"10.0.0.1 10.0.0.2"` a single argument and breaks execution (the same convention as the existing `{{dcs}}`). A single-value variable that may contain whitespace, like `{{password}}`, is quoted as before.
- Put `multiple` **only on tools that accept multiple targets** (nxc/crackmapexec are fine; single-host tools are not).

**proxychains / UDP / custom scripts**

- TCP (target NW): `proxychains: true` (through SOCKS). Do not write proxychains in the command string; control it with the flag
- Entra: the agent queries the already-collected `roadrecon.db` directly (e.g. `roadrecon-view ... --database <path>`). The real path is supplied in the prompt's execution context; only collection is server-side. Being local file access, these run **without** proxychains

**Judgment criteria**: Write the conditions for deciding Resolved/Unresolved in `judgment_criteria` (per finding) (conditions that span the output of multiple commands are allowed). If Unspecified, judged by whether the recommended remediation was applied.

## DC auto-discovery (ad_dns_recon)

During retest execution, when `execution_context` includes a domain/user/password, the Agent API launches `tools/AD_Recon/ad_dns_recon.py` as a subprocess in the background to mechanically obtain DC information (FQDN / IP), and registers it in the in-process DC cache (`agent/dc_discovery.py:_DC_CACHE`). It is injected into the LLM's command-generation prompt as "known DCs", suppressing unnecessary re-runs of SRV queries.

- The password is passed via the environment variable `AD_RECON_PASSWORD`, not a CLI argument, so it is not exposed in cleartext in the process list (`ps aux`, etc.)
- Assumes reaching the remote via SOCKS5. Specify the destination port with `SOCKS_PORT`
- The DC cache is only in process memory and is not persisted to the DB (volatile on restart)
- The result can also be checked with `GET /api/v1/dc-cache?domain=<domain>` (for debugging)

## Retest history

Completed retest results are persisted to SQLite (`./data/retest_history.db` by default).

- Write: the backend saves just before emitting SSE `final`. markdown and `final_output` are gzip-compressed and stored in a BLOB
- Read: `GET /api/v1/retest-history?finding_no=<no>` fetches per finding in newest-first order
- Delete: `DELETE /api/v1/retest-history/{id}` or `DELETE /api/v1/retest-history?finding_no=<no>`
- `final_output_json` is truncated keeping head and tail when it exceeds `RETEST_FINAL_OUTPUT_MAX_BYTES` (default 1MB) (with a `... truncated N bytes ...` marker in the middle)

From the UI, view and delete it in the "Past verification history" section of FindingDetail. The same history is visible across browsers.

## Authentication (login)

Access control is implemented in `agent/auth.py`. Users are managed in the DB (`users` table) (all equal, no roles).

```bash
# Generate a session signing key and set it in .env (auth is enabled only when this is set)
python -c "import secrets; print('SESSION_SIGNING_SECRET=' + secrets.token_hex(32))"

# Create a user (CLI; password entered interactively. Create the first user this way too)
python tools/auth/manage_users.py create alice
python tools/auth/manage_users.py list                 # list
python tools/auth/manage_users.py passwd alice         # reset password
python tools/auth/manage_users.py disable alice        # disable (login blocked; existing sessions also invalidated immediately)
```

- Auth is enabled only when `SESSION_SIGNING_SECRET` is set (if unset, no auth and fully open = for local trials). Because **no one can log in with zero users**, create at least one via the CLI
- Login: `POST /api/v1/login` (matches **username + password** against a DB user → issues an httpOnly cookie); destroy with `POST /api/v1/logout`. The session cookie carries the username, and each request checks in the DB whether that user is active (reflecting disabling immediately)
- **Each user can change their own password from the UI**: "Change login password" on the Settings screen (`POST /api/v1/change-password`) updates after verifying the current password (reflected in the DB immediately). Account issuance, disabling, and resets are done via the CLI (admin operation)
- **MFA (TOTP) is optional**: enrollment from the Settings screen is possible only when `MFA_SECRET_KEY` (a Fernet key) is set. Secrets are encrypted at rest; losing the key requires `mfa-reset`
- Repeated login failures are throttled temporarily (`LOGIN_LOCKOUT_THRESHOLD` failures within `LOGIN_LOCKOUT_WINDOW_SECONDS` → 429 without verifying credentials, auto-clearing)
- The frontend checks `GET /api/v1/auth/status` at startup and shows the login screen if unauthenticated. It returns to the login screen when the API returns 401
- SSE sends the cookie automatically on the same origin. Over plain http the cookie must be non-Secure — `make dev` handles this by setting `APP_ENV=dev`; otherwise set `SESSION_COOKIE_SECURE=false`

**Audit log**: Records key operations (login / login_failed / logout / change_password / retest / command_execute) in the `audit_log` table with "username, time, operation, target, source IP" (accountability for who did what). Sensitive command bodies and passwords are not recorded. About 0.3KB per row, lightweight. Rows beyond the retention period (default **180 days**, `AUDIT_LOG_RETENTION_DAYS`) are deleted by an **in-app periodic task** (right after startup and every `AUDIT_LOG_PRUNE_INTERVAL_HOURS`, default 24h). Because DELETE reuses free pages, size stays roughly capped (if you need to return actual disk, run `VACUUM` separately).

## HITL (Human-in-the-Loop)

Controlled by the "Confirm generated commands before execution" checkbox in `FindingDetail`, and gated server-side by `ENABLE_COMMAND_APPROVAL` (default `true` in this workspace):

- **ON (default)**: An approval dialog is shown each time a command is generated, and the user chooses approve / edit / reject. The checkbox itself also defaults to ON (`requireApproval: true`), so retests pause for review out of the box
- **OFF**: Uncheck the box to approve and execute LLM-generated commands automatically, with no dialog. When the server gate `ENABLE_COMMAND_APPROVAL=false`, the checkbox has no effect and execution is always automatic

Commands run **without a shell** (`shell=False`, argv-based): shell metacharacters (`|`, `>`, `;`, `&&`, `$(...)`) are passed as literal arguments, never interpreted, so a single command can only invoke one binary. In the dialog, **edit is constrained**: the tool/binary is locked to the LLM's choice and only its arguments are editable (each argument is its own field). The server rejects an edit that changes the binary (`403`), so "edit" cannot become an arbitrary-command-execution vector.

The setting is client-local (memory only, not persisted). Keep `VITE_ENABLE_COMMAND_APPROVAL` in sync with the server-side flag.

## SOCKS health check

`/api/v1/health/socks` checks liveness with `psutil`. When `SOCKS_CHECK_PORT` is set it reports `active` only if an ESTABLISHED connection exists with **that** port as the local port (a client is attached); when it is empty it falls back to a plain TCP connect to `SOCKS_HOST:SOCKS_PORT` (proves only that the proxy is listening). See the "SOCKS" section above for details. The frontend Header badge shows the state by polling every 5 seconds.

## report_analysis_mcp

`report_analysis_mcp/server.py` is an MCP server that analyzes PDF-format security reports. Main tools:

| Tool | Description |
|--------|------|
| `find_report_pdf` | Recursively searches a directory and returns scored candidate report PDFs |
| `read_pdf` | Extracts text from a PDF (with OCR fallback for scanned PDFs) |
| `extract_report_sections` | Extracts the findings and recommended-remediation sections from `read_pdf` output |

Like `kali-mcp/server.py`, it is used in stdio mode.

## Directory structure

```
Red_Agent/
├── agent/                       # AI agent (FastAPI)
│   ├── main.py                  # FastAPI app entry / endpoint definitions
│   ├── agent.py                 # Agent logic / MCP integration / subprocess launch for DC auto-discovery
│   ├── prompts.py               # System prompt definitions
│   ├── schemas.py               # Pydantic schemas
│   ├── auth.py                  # Auth primitives (scrypt hash / session signing)
│   ├── totp.py                  # TOTP (MFA) enrollment and verification
│   ├── users.py                 # DB store for login users (multi-user operation)
│   ├── login_throttle.py        # Temporary throttling of repeated login failures
│   ├── audit.py                 # Audit-log recording (who did what)
│   ├── credential_mask.py       # Masking of credentials in logs / outputs
│   ├── playbooks/
│   │   └── rto-sample.json      # RTO playbook seed (tracked; the runtime rto.json is generated by export and is gitignored)
│   ├── rto_playbook.py          # RTO playbook loader
│   ├── store.py                 # In-memory thread state management
│   ├── findings.py              # Loading / caching of findings JSON
│   ├── verdict.py               # Resolved / Unresolved verdict handling
│   ├── dc_discovery.py          # Mechanical DC-info extraction and in-process cache
│   ├── markdown_extract.py      # markdown extraction from final_output
│   ├── db.py                    # SQLAlchemy async engine / Base / initialization
│   ├── retest_history.py        # Retest history repository (save/list/get/delete)
│   ├── rto_history.py           # RTO history repository
│   └── models/                  # ORM models (retest_record / rto_record / user / audit_log)
├── front/                       # Frontend (Vite + React)
│   ├── package.json
│   ├── vite.config.ts           # dev server + /api, /threads, /health proxy to the Agent API
│   ├── index.html
│   └── src/
│       ├── components/
│       │   ├── common/          # Badge, CodeBlock, ConfirmDialog, LoadingSpinner
│       │   ├── config/          # AdCredentialsPanel, MfaPanel, PasswordChangePanel
│       │   ├── entra/           # EntraCollectionNotice, EntraDataPanel
│       │   ├── findings/        # FindingDetail, FindingRow, FindingTable
│       │   ├── layout/          # RootLayout, Header, PageContainer, Sidebar
│       │   ├── rto/             # RtoFinalOutputView
│       │   └── retest/          # RetestPanel, HITLReviewDialog, CommandPreview, ExecutionResult, FinalOutputView, ReportExport
│       ├── contexts/            # AuthContext, SocksContext
│       ├── hooks/               # useFindings, useRetest, useRTO, useCommandExecution
│       ├── lib/                 # api.ts, findings-store.ts, verification-history-store.ts, rto-history-store.ts,
│       │                       #  credentials-store.ts, retest-settings-store.ts, features.ts,
│       │                       #  final-output.ts, markdown-export.ts, pdf.ts, pdf-export.ts, verdict.ts
│       ├── pages/               # HomePage, RetestPage, RTOPage, ConfigPage, ErrorPage
│       └── types/               # finding.ts, retest.ts, rto.ts, report.ts
├── tools/                       # Helper tools
│   ├── auth/
│   │   └── manage_users.py      # Login-user management CLI (create/list/passwd/disable/enable)
│   ├── AD_Recon/
│   │   └── ad_dns_recon.py      # Auto-discovers the AD domain's DC via SMB→Registry→DNS SRV
│   └── Entra_Recon/
│       └── roadrecon_collect.py # roadrecon auth / gather wrapper
├── kali-mcp/                    # Kali Linux command-execution MCP server
│   ├── server.py                # fastmcp-based MCP server (execute_kali_command, per-command prefix via use_proxychains)
│   └── client-sample.py         # Sample for connection testing
├── report_analysis_mcp/         # Report PDF analysis MCP server
│   └── server.py                # find_report_pdf / read_pdf / extract_report_sections
├── data/                        # Data storage directory
│   ├── findings-sample.json     # Sample findings JSON
│   └── retest_history.db        # SQLite retest history (auto-created on first startup, gitignored)
├── docs/
│   └── api.md                   # API documentation
├── requirements.txt             # Python dependency packages
├── Makefile                     # Install / dev startup / build / user management
└── .env.example                 # Environment variable template
```
