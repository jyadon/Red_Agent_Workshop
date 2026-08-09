# API Specification

List of Agent API (FastAPI) endpoints.
For detailed schemas and request examples, see the Swagger UI (`/docs`) or ReDoc (`/redoc`).

## Authentication

Multi-user login sessions (httpOnly Cookie). Enabled only when `SESSION_SIGNING_SECRET` is set (when unset, everything is open with no authentication). Users are managed in the DB (`users` table) and created with `tools/auth/manage_users.py` (all equal, no roles). Static API-key authentication has been removed. Major operations are recorded in `audit_log`.

### POST /api/v1/login

Matches username/password against a DB user and, on success, issues an httpOnly session Cookie.

```json
{ "username": "alice", "password": "operator-password" }
```

**Response**: `{ "ok": true }` (`Set-Cookie: ra_session=...; HttpOnly; Secure; SameSite=Strict`). The Cookie token contains the username, and each request confirms the user's validity in the DB (deactivation takes effect immediately).

**Errors**: `401` Invalid credentials (failures are audited) / `503` Authentication is not configured

### POST /api/v1/logout

Destroys the session Cookie. **Response**: `{ "ok": true }`

### POST /api/v1/change-password

Changes the password of the currently logged-in user **themselves** (authentication required). After matching the current password, the scrypt hash of the new password is stored in the DB (`users`) and takes effect **immediately**. On success, the session Cookie is reissued to keep the current login. Account issuance, deactivation, and reset are done via the CLI (administrator operations).

```json
{ "current_password": "old-password", "new_password": "new-strong-password" }
```

**Response**: `{ "ok": true }`

**Errors**: `401` current password mismatch / `400` new password is invalid (fewer than 8 characters, or same as current) / `503` authentication not configured

### GET /api/v1/auth/status

Returns whether login is required, the authentication state, and the username (accessible even when unauthenticated). Used by the frontend to decide whether the login screen is needed.

```json
{ "authenticated": false, "auth_required": true, "username": null }
```

When authentication is disabled (unset on the server side), returns `{ "authenticated": true, "auth_required": false, "username": null }`.

Other protected endpoints return `401 Authentication required` unless a valid session Cookie (and a valid user) is present.

---

## Findings

Retrieves findings loaded from a server-side JSON file.
The JSON file path is specified by the environment variable `FINDINGS_FILE` (default: `data/findings.json`).

### GET /api/v1/findings

Retrieves the list of findings and the report metadata.

**Response**

```json
{
  "metadata": {
    "company_name": "Security Assessment Report",
    "generated_at": "2026-03-21T00:15:00Z",
    "total_findings": 1
  },
  "findings": [
    {
      "section": 1,
      "title": "Use of Weak Passwords",
      "risk_level": "High",
      "summary": "For multiple domain administrator accounts...",
      "description": "An attacker could use password spraying attacks or...",
      "recommendation": "It is recommended to set passwords that are difficult to guess...",
      "references": [
        { "name": "NIST SP 800-63", "url": "https://pages.nist.gov/800-63-4/" }
      ]
    }
  ]
}
```

When the JSON file has only the `section` field, a `no` in `No.1` format is auto-filled.

In addition to display fields (`title` / `risk_level` / `summary` / `description` / `recommendation` / `references`), each finding may have `platform` / `verification_inputs` (data variables prompted for at run time) / `judgment_criteria` for the verification path. The agent authors the actual commands itself.

`platform` is an array of `ad` / `entra` / `other` / `retest_not_supported` (multiple allowed; missing or empty becomes `["other"]`). It decides the target environment stated in the prompt, whether the collected Entra database path is supplied, which credentials the UI asks for, and whether retest can start at all. See the README section "Setting `platform`" for the full breakdown.

### GET /api/v1/findings/{finding_id}

Retrieves the finding with the specified ID.

**Errors**: `404` Finding not found

### POST /api/v1/findings/reload

Discards the cache and reloads from the JSON file. Call this after swapping the file.

---

## Threads

A resource for managing Verification tasks.
Provides SSE streaming and HITL interrupt/resume as a shared foundation.

### POST /threads

Creates a thread.

**Verification (`kind=verification`)**

Receives one finding and automatically starts the flow: check-command generation -> HITL approval -> execution on Kali.

```json
{
  "kind": "verification",
  "context": {
    "primary_finding_id": "No.1",
    "findings": [{
      "no": "No.1",
      "title": "Use of Weak Passwords",
      "risk_level": "High",
      "summary": "...",
      "description": "...",
      "recommendation": "...",
      "references": []
    }]
  },
  "input": { "user_instruction": "Be concise" }
}
```

**Response**

```json
{
  "ok": true,
  "thread_id": "dcad8101-b66e-42d3-98ae-0929ad3598fb",
  "kind": "verification",
  "status": "running",
  "title": null
}
```

### GET /threads/{thread_id}

Retrieves the thread's state, pending interrupt, final result, and errors.

### POST /threads/{thread_id}/resume

Returns approve/edit/reject for a HITL interrupt and resumes processing.

The number of entries in the `decisions` array must match the number of entries in `interrupt.actions`.

```json
{
  "decisions": [
    { "type": "approve" }
  ]
}
```

For command editing:

```json
{
  "decisions": [
    {
      "type": "edit",
      "edited_args": { "command": "cat /etc/ssh/sshd_config" }
    }
  ]
}
```

| type | Behavior |
|------|------|
| `approve` | Execute the command as-is |
| `edit` | Rewrite the arguments with `edited_args` and execute |
| `reject` | Do not execute the command |

### GET /threads/{thread_id}/stream

Receives thread events in real time via Server-Sent Events.

**Parameters**

| Name | Location | Description |
|------|------|------|
| `after` | query | Last-read seq. On reconnect, receive only events after this value |

**List of SSE events**

| event | Description |
|-------|------|
| `status` | Processing start / progress |
| `chunk` | Agent's intermediate output (during verification) |
| `metadata` | Structured data such as codeBlocks |
| `interrupt` | Waiting for HITL approval. The `actions` array contains command information |
| `resumed` | A resume was accepted |
| `command_result` | Command execution result (output, exitCode, durationMs) |
| `final` | Processing complete |
| `error` | Processing failed |

**interrupt event example**

```json
{
  "type": "interrupt",
  "seq": 3,
  "interrupt": {
    "id": "da3d49459f639c6baf0f327706852902",
    "actions": [
      {
        "index": 0,
        "name": "execute_kali_command",
        "args": { "command": "grep PermitRootLogin /etc/ssh/sshd_config" },
        "description": "Tool execution requires approval",
        "allowed_decisions": ["approve", "edit", "reject"]
      }
    ]
  }
}
```

**metadata event example (kali code block extraction)**

When the LLM's response contains a ````kali` code block, it is extracted as an executable command.

```json
{
  "type": "metadata",
  "seq": 4,
  "codeBlocks": [
    {
      "id": "cb-a1b2c3d4",
      "language": "bash",
      "code": "chage -l admin",
      "executable": true,
      "riskLevel": "cautious",
      "description": "chage -l admin"
    }
  ]
}
```

---

## Commands

### POST /api/v1/commands/execute

Starts command execution with HITL approval.
Creates a thread and presents the command as an interrupt.

```json
{
  "command": "grep PermitRootLogin /etc/ssh/sshd_config",
  "label": "Check SSH root setting",
  "findingId": "No.1"
}
```

**Response**

```json
{
  "ok": true,
  "thread_id": "c4679e6e-4cc9-49a0-b068-e911d1b1ec40",
  "status": "waiting_human"
}
```

**Execution flow**

1. Receive `thread_id`
2. Subscribe to SSE with `GET /threads/{thread_id}/stream`
3. Review the command on the `interrupt` event
4. approve/edit/reject with `POST /threads/{thread_id}/resume`
5. After approval, it executes via Kali MCP and `command_result` -> `final` are returned over SSE

---

## Retest

### POST /api/v1/retest

Receives findingIds and creates a verification thread for each finding.

```json
{
  "findingIds": ["No.1", "No.2"]
}
```

**Response**

```json
{
  "id": "exec-a1b2c3d4",
  "findingIds": ["No.1", "No.2"],
  "status": "running",
  "startedAt": "2026-03-22T00:00:00Z",
  "commands": [
    {
      "id": "dcad8101-b66e-42d3-98ae-0929ad3598fb",
      "findingId": "No.1",
      "command": "verification thread for No.1",
      "label": "Use of Weak Passwords",
      "status": "running"
    }
  ]
}
```

Each `commands[].id` corresponds to the `thread_id` of a verification thread.
You can subscribe to individual verification results with `GET /threads/{thread_id}/stream`.

---

## Health

### GET /health

```json
{ "ok": true }
```

---

## Common Error Responses

```json
{
  "detail": "error message"
}
```

| Status | Description |
|-----------|------|
| `400` | Bad request (missing required parameters, etc.) |
| `401` | Unauthenticated (session Cookie invalid/missing) |
| `403` | Feature disabled on the server (e.g. command approval when `ENABLE_COMMAND_APPROVAL=false`), or a constrained-edit violation on resume (attempting to change the tool/binary instead of only its arguments) |
| `404` | Resource not found |
| `409` | State inconsistency (sending a message to a running thread, etc.) |
| `502` | Failed to connect to Kali MCP / LLM server |
