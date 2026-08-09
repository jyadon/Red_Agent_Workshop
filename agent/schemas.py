from typing import Any, Literal
from pydantic import (
    BaseModel,
    HttpUrl,
    Field,
    ConfigDict,
    field_validator,
    model_validator,
)


class LoginRequest(BaseModel):
    """Login request body; username/password is matched against the DB user."""

    username: str = Field(..., min_length=1, examples=["alice"])
    password: str = Field(..., min_length=1, examples=["operator-password"])


class ChangePasswordRequest(BaseModel):
    """Login password change request body; stores the new password after verifying the current one."""

    current_password: str = Field(..., min_length=1, examples=["old-password"])
    new_password: str = Field(..., min_length=8, examples=["new-strong-password"])


class MfaLoginRequest(BaseModel):
    """MFA second-step request body: the short-lived token from step 1 plus a one-time code."""

    mfa_token: str = Field(..., min_length=1)
    code: str = Field(..., min_length=6, max_length=10, examples=["123456"])


class MfaVerifyRequest(BaseModel):
    """MFA enrollment completion (code verification) request body."""

    code: str = Field(..., min_length=6, max_length=10, examples=["123456"])


class MfaDisableRequest(BaseModel):
    """MFA removal request body; confirms identity with the current TOTP code."""

    code: str = Field(..., min_length=6, max_length=10, examples=["123456"])


class ReferenceItem(BaseModel):
    name: str = Field(..., examples=["OpenSSH manual"])
    url: HttpUrl = Field(..., examples=["https://man.openbsd.org/sshd_config"])


class FindingItem(BaseModel):
    no: str = Field(..., examples=["No.1"])
    section: int | str | None = Field(default=None, examples=[1])
    # Target platform, predefined per finding. Drives verification-path branching
    # (whether Entra collection is needed, and which environment is in scope).
    # ad: on-prem AD / entra: Microsoft Entra ID (cloud) / other: everything else (Linux, etc.).
    # retest_not_supported: automatic retest unsupported; the frontend disables retest when present.
    # Multiple values allowed (e.g. ["ad", "entra"] for a finding spanning both).
    # A single string is auto-coerced to a list; missing/empty becomes ["other"].
    platform: list[Literal["ad", "entra", "other", "retest_not_supported"]] = Field(
        default_factory=lambda: ["other"], examples=[["ad"], ["ad", "entra"]]
    )

    @field_validator("platform", mode="before")
    @classmethod
    def _coerce_platform(cls, v: object) -> object:
        if v is None or v == "" or v == []:
            return ["other"]
        if isinstance(v, str):
            return [v]
        return v
    title: str = Field(..., examples=["SSH root login is enabled"])
    risk_level: str = Field(..., examples=["High"])
    summary: str = Field(..., examples=["Root login over SSH is permitted"])
    description: str = Field(..., examples=["PermitRootLogin is set to yes in sshd_config, so direct login as root is possible."])
    recommendation: str = Field(..., examples=["Set PermitRootLogin to no to forbid root login."])
    references: list[ReferenceItem] = []

    # Optional restriction: the tools to use when verifying this finding (e.g. "nxc ldap",
    # "impacket-GetUserSPNs"). Surfaced to the planner prompt as [Tools to Use]. When set, the
    # planner must design commands using ONLY these tools, falling back to another tool only when
    # the check cannot be determined with them (and must say why). When unset/empty, the planner
    # chooses tools freely. A single string is coerced to a list; missing/empty becomes [].
    tool_hints: list[str] = Field(
        default_factory=list, examples=[["nxc ldap", "impacket-GetUserSPNs"]]
    )

    @field_validator("tool_hints", mode="before")
    @classmethod
    def _coerce_tool_hints(cls, v: object) -> object:
        if v is None or v == "" or v == []:
            return []
        if isinstance(v, str):
            return [v]
        return v

    # Optional criteria for judging a finding "Resolved" at retest. When set, it is passed
    # to the interpretation prompt as [Judgment Criteria] and the LLM must follow it strictly to decide
    # Resolved / Partially Resolved / Unresolved. When unset, the decision is based on whether
    # the recommendation was applied. May reference conditions spanning multiple commands' output.
    judgment_criteria: str | None = Field(
        default=None,
        examples=["Resolved if there are fewer than 5 Global Administrators and each admin has MFA registered"],
    )

    @field_validator("judgment_criteria", mode="before")
    @classmethod
    def _coerce_judgment_criteria(cls, v: object) -> object:
        if v is None:
            return None
        s = str(v).strip()
        return s or None


    # Optional declaration of data variables the user must supply at retest. Only findings with
    # this declaration cause the frontend to show an input form before running. Keys must match
    # the command's {{key}}. Values are pattern-validated server-side before injection (only
    # declared keys are injected). VerificationInput is defined later (forward reference).
    verification_inputs: list["VerificationInput"] = Field(default_factory=list)


class VerificationInput(BaseModel):
    """Declaration of a data variable the user supplies at retest.

    Used for values that vary per engagement/run (e.g. the target server). The frontend shows an
    input form only when a finding carries this declaration. The key must match the command
    template's {{key}}; the value is pattern-validated server-side (an allowlist regex) before
    injection to prevent command injection.
    """

    key: str = Field(..., examples=["target"])
    label: str = Field(..., examples=["Target server (IP/FQDN)"])
    placeholder: str | None = Field(default=None, examples=["10.10.10.4"])
    required: bool = True
    # Optional default used when the field is left blank; it is injected into {{key}} and is
    # itself pattern-validated. placeholder is only a hint and is unrelated. A default effectively
    # makes an input "optional with a default value".
    default: str | None = Field(default=None, examples=["12345"])
    # True: sensitive input (e.g. a password). Stored in the server secret store rather than
    # runtime user vars, escaped inside '...' on injection, and masked as <PASS> in display/logs/
    # command output (no plaintext retained). A secret input MUST be placed inside single quotes
    # '{{key}}' in the template (escaping assumes '...'). The frontend renders it as a password field.
    secret: bool = False
    # True: allow multiple values (frontend shows an add/remove multi-row UI). Each value is
    # pattern-validated individually server-side, then joined with spaces into one variable (same
    # "unquoted, space-joined multi-target" scheme as {{dcs}}). Place {{key}} UNQUOTED in the
    # command (quoting would collapse multiple values into a single argument and break execution).
    multiple: bool = False
    # Allowed pattern per value. Default permits only IP/hostname-like input (rejects whitespace,
    # quotes, ;, etc.). With multiple, each value must satisfy this pattern individually.
    pattern: str = Field(
        default=r"^[A-Za-z0-9_.-]+$", examples=[r"^[A-Za-z0-9_.-]+$"]
    )


class VerificationExecutionContext(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    # domain / user / dns are injected UNQUOTED into command templates (e.g. `-u {{user}}`,
    # `@{{dns}}`), so they are validated with a shell-metacharacter-free allowlist to prevent
    # command injection. Values are restricted to DNS-name / AD-username / IP-or-hostname forms.
    #
    # Entra-only findings do not use AD credentials (credentials are server-injected and the
    # already-collected roadrecon.db for the tenant is referenced). So domain/user/pass are
    # optional and empty/missing normalizes to None (see _empty_to_none). The allowlist pattern
    # is applied only when a value is present, so AD-path injection protection is preserved.
    domain: str | None = Field(
        default=None, min_length=1, max_length=255,
        pattern=r"^[A-Za-z0-9._-]+$", examples=["corp.local"],
    )
    user: str | None = Field(
        default=None, min_length=1, max_length=255,
        pattern=r"^[A-Za-z0-9._@-]+$", examples=["administrator"],
    )
    # password may legitimately contain any character (', whitespace, $, etc.), so no pattern is
    # applied. It is injected inside '...' (single quotes) and only single quotes are escaped
    # server-side just before injection to neutralize injection (see agent.py). max_length matches
    # the AD password limit (256) purely to bound size.
    pass_: str | None = Field(default=None, alias="pass", min_length=1, max_length=256, examples=["Secret123!"])

    # On the Entra path the frontend sends domain/user/pass as empty strings "". Fold empty/blank
    # to None (equivalent to "unspecified"), neutralizing it before min_length/pattern validation.
    @field_validator("domain", "user", "pass_", mode="before")
    @classmethod
    def _empty_to_none(cls, v: Any) -> Any:
        if isinstance(v, str) and v.strip() == "":
            return None
        return v
    dns: str | None = Field(
        default=None, max_length=255,
        pattern=r"^[A-Za-z0-9.:_-]+$", examples=["10.0.1.10"],
    )

    # Selects which tenant's already-collected roadrecon.db to reference for Entra verification
    # (non-sensitive). If omitted, the server defaults to the single collected DB when only one
    # exists. Token ingestion happens via the dedicated collection API (EntraCollectRequest), not retest.
    tenant: str | None = Field(default=None, examples=["contoso.onmicrosoft.com"])


class RTOExecutionContext(BaseModel):
    """RTO-specific execution context, separate from the retest VerificationExecutionContext.

    domain/user/pass/dns are all REQUIRED (RTO automates credentialed AD attacks and has no
    credential-less path like Entra). domain/user/dns are injected unquoted into command
    templates and validated with a shell-metacharacter-free allowlist (same injection protection
    as VerificationExecutionContext). domain doubles as the "target domain" input.
    """

    model_config = ConfigDict(populate_by_name=True)

    domain: str = Field(
        ..., min_length=1, max_length=255,
        pattern=r"^[A-Za-z0-9._-]+$", examples=["corp.local"],
    )
    user: str = Field(
        ..., min_length=1, max_length=255,
        pattern=r"^[A-Za-z0-9._@-]+$", examples=["administrator"],
    )
    # password may legitimately contain ', whitespace, $, etc., so no pattern. Injected inside
    # '...' with only single quotes escaped server-side just before injection (see agent.py).
    pass_: str = Field(
        ..., alias="pass", min_length=1, max_length=256, examples=["Secret123!"]
    )
    dns: str = Field(
        ..., min_length=1, max_length=255,
        pattern=r"^[A-Za-z0-9.:_-]+$", examples=["10.0.1.10"],
    )


class RTOExtractRule(BaseModel):
    """Rule to extract a value from step output via regex and inherit it into later steps' variables.

    Extracted values are individually shell-quoted (shlex.quote-equivalent) before being embedded
    into the command, so ``{{var}}`` can be used unquoted safely (multiple matches are joined).
    """

    var: str = Field(..., examples=["dcs"])
    # Uses the named group ``val`` if present, else group(1), else the whole match.
    pattern: str = Field(..., examples=[r"(?P<val>\S+)\s+VULNERABLE"])
    # String used to join multiple matches. A space join enables multi-target use.
    join: str = ","
    # Extraction source. Currently only "output" is supported (future: "stderr", etc.).
    source: str = "output"
    # If True, when a variable of the same name already exists, append via join instead of
    # overwriting (aggregates enumeration results from multiple steps into one variable, e.g.
    # collecting members of several groups into joe_users).
    append: bool = False


class RTOArtifact(BaseModel):
    """Registers an artifact a step produced (BH zip, hashes, collected files) for review."""

    # Variables ({{target}}, etc.) may be substituted. There are no built-in workdir/timestamp
    # variables, so specify a concrete path in the playbook (unresolved variables are left as-is).
    path: str = Field(..., examples=["/tmp/rto/spn_hashes_{{target}}.txt"])
    label: str | None = Field(default=None, examples=["SPN hash"])


class RTOStep(BaseModel):
    id: str = Field(..., examples=["host-discovery"])
    description: str | None = Field(default=None, examples=["Enumerate live hosts"])
    # Attack name shown in the report's success list (e.g. "Joe account"). Falls back to
    # description -> id when unset. Attach to judged attack steps.
    label: str | None = Field(default=None, examples=["Joe account"])
    # Optional remediation added to the report's "Recommended Remediation" if this attack succeeds.
    remediation: str | None = Field(
        default=None,
        examples=["Apply a strong password policy to privileged accounts"],
    )
    # Optional regex marking clear success. When set, a match against the output makes the verdict
    # deterministic (match=success / no-match=failure), removing LLM-judgment variance. Attach to
    # attacks with a mechanical marker like (Pwn3d!) or VULNERABLE. The observation text is still
    # generated by the judge. When unset, success/failure/inconclusive is decided by LLM judgment.
    success_pattern: str | None = Field(
        default=None, examples=[r"(?m)^SMB.*\[\+\]"]
    )
    # Optional template for the report observation text on success. When set, the LLM is not called
    # and this text is used deterministically. `{items}` is replaced by the success_pattern captures
    # (named val or group(1)) collected per matching line and joined; `{count}` is the match count.
    # When unset, the LLM judgment generates the observation text.
    observation_template: str | None = Field(
        default=None,
        examples=["Confirmed a Joe account among privileged group members {items}"],
    )
    # {{target}} / {{domain}} / {{user}} / {{password}} / {{dns}} and extract-inherited variables
    # are substituted at runtime.
    command: str = Field(..., examples=["nmap -sn {{target}}"])
    # Whether to prefix proxychains. Set false for local execution or commands that do not go
    # through SOCKS (ICMP/UDP, etc.); the MCP execution layer adds the prefix, so do not write it
    # into the command string.
    proxychains: bool = True
    # Branch condition evaluated before execution; skip the step if false. None always executes.
    # Example: {"all": [{"var_present": "dcs"}, {"output_matches": {"id": "smb", "pattern": "..."}}]}
    when: dict[str, Any] | None = None
    # Rules to extract variables from output after execution (variable inheritance).
    extract: list[RTOExtractRule] = Field(default_factory=list)
    # Optional registration of a produced artifact.
    artifact: RTOArtifact | None = None
    # Steps with True are judged for success by the AI after execution.
    judge: bool = False
    judge_criteria: str | None = Field(
        default=None, examples=["Success if at least one live host is detected"]
    )


class RTOInterpret(BaseModel):
    """Per-group interpretation settings (compress bounded output into a structured finding)."""

    # What the AI should summarize. Summarizes from default perspectives even when unset.
    goal: str | None = Field(default=None, examples=["Summarize obtained hashes and weak accounts"])


class RTOGroup(BaseModel):
    """A cohesive block of attack steps; an interpretation report is generated per group after execution.

    Only groups with interpret contribute to the final report. Collection-only groups (AD Recon,
    etc.) that omit interpret still execute and extract but are excluded from the final report.
    """

    id: str = Field(..., examples=["cred-attacks"])
    name: str | None = Field(default=None, examples=["Credential attacks"])
    steps: list[RTOStep] = Field(default_factory=list)
    interpret: RTOInterpret | None = None
    # Optional group-wide execution gate; skip the whole group if false.
    when: dict[str, Any] | None = None


class RTOFinal(BaseModel):
    """Final-stage settings that consolidate all groups' interpretation reports."""

    # By default, reconstructs only the paths leading to domain-admin privilege.
    goal: str | None = Field(
        default=None, examples=["Reconstruct only the paths leading to Domain Admin privilege"]
    )


class RTOPlaybook(BaseModel):
    name: str = Field(..., examples=["default-rto"])
    description: str | None = None
    version: int = 1
    # v2: group structure. map (per-group interpretation) -> reduce (final consolidation).
    groups: list[RTOGroup] = Field(default_factory=list)
    # Backward compat: flat steps. Normalized into a single group when groups is empty.
    steps: list[RTOStep] = Field(default_factory=list)
    final: RTOFinal | None = None

    @model_validator(mode="after")
    def _normalize_legacy_steps(self) -> "RTOPlaybook":
        # Fold the legacy form (no groups, steps only) into one group treated as v2. Attach
        # interpret to preserve legacy behavior (report generated from all steps).
        if not self.groups and self.steps:
            self.groups = [
                RTOGroup(
                    id="default",
                    name=self.name,
                    steps=self.steps,
                    interpret=RTOInterpret(),
                )
            ]
        return self



class ThreadContext(BaseModel):
    primary_finding_id: str | None = None
    findings: list[dict[str, Any]] = Field(default_factory=list)


class ThreadCreateRequest(BaseModel):
    kind: Literal["verification", "command_approval", "rto"]
    title: str | None = None
    context: ThreadContext = Field(default_factory=ThreadContext)
    auto_start: bool = True
    input: dict[str, Any] | None = None
    # False (default): auto-execute agent-generated commands without HITL approval.
    # True: use the legacy interrupt -> user approval -> resume flow.
    require_approval: bool = False


class ThreadResponse(BaseModel):
    ok: bool = True
    thread_id: str
    kind: Literal["verification", "command_approval", "rto"]
    status: Literal["idle", "running", "waiting_human", "completed", "failed"]
    title: str | None = None
    interrupt: dict[str, Any] | None = None
    final_output: Any | None = None
    error: str | None = None


class ReviewDecision(BaseModel):
    type: Literal["approve", "edit", "reject"]
    edited_args: dict[str, Any] | None = None
    comment: str | None = None


class ResumeRequest(BaseModel):
    # Required. Validated server-side to match the active interrupt id.
    interrupt_id: str = Field(..., min_length=1, examples=["intr-9f8b2c1d..."])
    decisions: list[ReviewDecision]
    # When true, the current decisions are applied and every SUBSEQUENT command in this run is
    # auto-approved (no further review dialog). Lets the operator review the first command(s) then
    # stop being interrupted. Only honored for verification threads.
    auto_approve_remaining: bool = False


class ExecuteCommandRequest(BaseModel):
    command: str = Field(..., min_length=1, examples=["nmap -sV 10.0.0.5"])
    label: str | None = Field(default=None, examples=["Port scan"])
    findingId: str | None = Field(default=None, examples=["No.1"])


class RetestRequest(BaseModel):
    findingIds: list[str] = Field(..., min_length=1, examples=[["No.1", "No.2"]])


class EntraCollectRequest(BaseModel):
    """Manual trigger for Entra data collection (roadrecon gather); independent of retest.

    token is sensitive (PRT Cookie, etc.). The server only passes it to the collection subprocess
    via an environment variable, does not persist it, and discards `.roadtools_auth` after collection.
    """

    tenant: str = Field(..., examples=["contoso.onmicrosoft.com"])
    token: str = Field(..., min_length=1, examples=["<PRT-Cookie>"])
    token_type: Literal["prt-cookie", "refresh-token", "access-token"] = Field(
        default="prt-cookie"
    )


class EntraAuthRequest(BaseModel):
    """Entra authentication only (auth); exchanges a PRT Cookie, etc. for access/refresh tokens.

    The short-lived PRT Cookie is used once here, and the exchanged tokens are kept in the server's
    in-memory session (not persisted). Actual collection happens later via `EntraGatherRequest`
    (with session_id), so re-collection is possible without re-fetching the cookie.
    """

    tenant: str = Field(..., examples=["contoso.onmicrosoft.com"])
    token: str = Field(..., min_length=1, examples=["<PRT-Cookie>"])
    token_type: Literal["prt-cookie", "refresh-token", "access-token"] = Field(
        default="prt-cookie"
    )


class EntraGatherRequest(BaseModel):
    """Entra collection (gather); runs roadrecon gather with the session's tokens from auth.

    session_id comes from the success response of `EntraAuthRequest` (/api/v1/entra/auth). The same
    session_id may be called multiple times (re-collection, failure retry).
    """

    session_id: str = Field(..., min_length=1, examples=["a1b2c3..."])


class RtoExportCommand(BaseModel):
    """One placeholder-ized command selected for export into the RTO playbook."""

    command: str = Field(..., min_length=1, examples=["netexec ldap {{dc}} -u '{{user}}' -p '{{password}}' -d '{{domain}}' -M ldap-checker"])
    label: str | None = Field(default=None, examples=["LDAP signing / channel binding"])
    description: str | None = None
    # None -> the playbook default (proxychains on) applies.
    proxychains: bool | None = None


class RtoExportRequest(BaseModel):
    """Export selected (placeholder-ized) retest commands into the live RTO playbook (rto.json)."""

    findingNo: str | None = Field(default=None, examples=["No.3"])
    commands: list[RtoExportCommand] = Field(..., min_length=1)


