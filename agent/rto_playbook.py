from __future__ import annotations

import json
import os
import re
import shlex
from pathlib import Path
from typing import Any

from agent.schemas import RTOExtractRule, RTOPlaybook

# Live playbook path (grown by exporting retest commands; gitignored). Override with the
# RTO_PLAYBOOK_PATH env var. When the live file is absent, fall back to the tracked sample seed.
_DEFAULT_PLAYBOOK_PATH = Path(__file__).parent / "playbooks" / "rto.json"
_SAMPLE_PLAYBOOK_PATH = Path(__file__).parent / "playbooks" / "rto-sample.json"

_PLACEHOLDER_RE = re.compile(r"\{\{\s*(\w+)\s*\}\}")


def live_playbook_path() -> Path:
    """The live playbook file that exports append to (env override wins). May not exist yet."""
    env = os.environ.get("RTO_PLAYBOOK_PATH")
    return Path(env) if env else _DEFAULT_PLAYBOOK_PATH


def get_playbook_path() -> Path:
    """Resolve which playbook to run.

    Precedence: RTO_PLAYBOOK_PATH override > live playbook (rto.json) > sample seed
    (rto-sample.json). The sample lets RTO run out of the box before anything is exported.
    """
    live = live_playbook_path()
    if live.exists():
        return live
    return _SAMPLE_PLAYBOOK_PATH


def load_playbook(path: Path | None = None) -> RTOPlaybook:
    """Load and validate the JSON playbook.

    Called on every run, so edits to the file take effect on the next RTO run
    without a restart. Malformed or missing data raises, and the caller
    (start_rto) treats it as a failure.
    """
    p = path or get_playbook_path()
    if not p.exists():
        raise FileNotFoundError(f"RTO playbook not found: {p}")
    with p.open("r", encoding="utf-8") as f:
        data = json.load(f)
    return RTOPlaybook(**data)


def placeholderize_command(command: str, context: dict[str, str]) -> str:
    """Replace literal engagement values in a command with ``{{name}}`` placeholders.

    ``context`` maps a placeholder name (e.g. ``domain`` / ``user`` / ``password`` / ``dns`` /
    a runtime-input key) to the real value used in this run. Longer values are substituted first
    so a short value cannot clobber part of a longer one. The shell single-quote-escaped form of
    each value (``'`` -> ``'\\''``) is also replaced, so a password containing a quote is caught.
    Used to strip secrets/engagement specifics before a captured command is stored or exported.
    """
    if not command or not context:
        return command
    out = command
    for name, value in sorted(
        ((k, v) for k, v in context.items() if v), key=lambda kv: len(kv[1]), reverse=True
    ):
        token = "{{" + name + "}}"
        out = out.replace(value, token)
        escaped = value.replace("'", "'\\''")
        if escaped != value:
            out = out.replace(escaped, token)
    return out


def _slugify_step_id(text: str, taken: set[str]) -> str:
    """Build a filesystem/JSON-friendly step id from text, unique within ``taken``."""
    base = re.sub(r"[^a-z0-9]+", "-", (text or "step").lower()).strip("-")[:48] or "step"
    candidate = base
    i = 2
    while candidate in taken:
        candidate = f"{base}-{i}"
        i += 1
    taken.add(candidate)
    return candidate


def _empty_live_playbook() -> dict[str, Any]:
    return {
        "name": "ad-rto",
        "description": "Live RTO playbook, grown by exporting commands from successful retests.",
        "version": 2,
        "groups": [],
    }


def append_commands_to_live(
    items: list[dict[str, Any]], *, group_id: str, group_name: str | None = None
) -> dict[str, Any]:
    """Append exported commands as steps to the live playbook (rto.json), creating it if absent.

    Each item is ``{command, label?, description?, proxychains?}``. Deduplicates by command
    string across the whole playbook (already-present commands are skipped). Commands are grouped
    under ``group_id`` (created if missing). The result is schema-validated before writing.
    Returns ``{added, skipped, path}``.
    """
    path = live_playbook_path()
    if path.exists():
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    else:
        data = _empty_live_playbook()

    groups = data.setdefault("groups", [])
    existing_cmds = {
        s.get("command")
        for g in groups
        if isinstance(g, dict)
        for s in g.get("steps", [])
        if isinstance(s, dict)
    }
    taken_ids = {
        s.get("id")
        for g in groups
        if isinstance(g, dict)
        for s in g.get("steps", [])
        if isinstance(s, dict) and s.get("id")
    }

    target = next((g for g in groups if isinstance(g, dict) and g.get("id") == group_id), None)
    if target is None:
        target = {"id": group_id, "name": group_name or "Exported from retests", "steps": []}
        groups.append(target)
    steps = target.setdefault("steps", [])

    added = 0
    skipped = 0
    for item in items:
        command = str(item.get("command") or "").strip()
        if not command or command in existing_cmds:
            skipped += 1
            continue
        step: dict[str, Any] = {
            "id": _slugify_step_id(str(item.get("label") or command), taken_ids),
            "command": command,
        }
        if item.get("label"):
            step["label"] = str(item["label"])
        if item.get("description"):
            step["description"] = str(item["description"])
        if isinstance(item.get("proxychains"), bool):
            step["proxychains"] = item["proxychains"]
        steps.append(step)
        existing_cmds.add(command)
        added += 1

    # Validate the whole document before persisting; a malformed result raises and nothing is written.
    RTOPlaybook(**data)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
        f.write("\n")
    return {"added": added, "skipped": skipped, "path": str(path)}


def render_command(command: str, variables: dict[str, str]) -> tuple[str, list[str]]:
    """Replace `{{var}}` with values from ``variables``.

    Variables that are empty or undefined are recorded in ``missing`` and left
    as the literal ``{{var}}``. The caller skips any step whose ``missing`` is
    non-empty to avoid running an incomplete command.
    """
    missing: list[str] = []

    def repl(match: re.Match[str]) -> str:
        name = match.group(1)
        value = variables.get(name)
        if value:
            return value
        if name not in missing:
            missing.append(name)
        return match.group(0)

    rendered = _PLACEHOLDER_RE.sub(repl, command)
    return rendered, missing


def extract_tokens(
    rules: list[RTOExtractRule], output: str
) -> dict[str, list[tuple[str, str]]]:
    """Match each extract rule against the output and return ``{var: [(raw, rendered), ...]}``.

    Raw tokens with no join or dedup. ``raw`` is the extracted value itself;
    ``rendered`` is individually ``shlex.quote``-ed for command embedding. Named
    group ``val`` is preferred, then group(1), then the whole match. Dedup and
    join are left to the caller to keep per-token append dedup exact and avoid
    the ambiguity of splitting an already-joined string.
    """
    result: dict[str, list[tuple[str, str]]] = {}
    for rule in rules:
        try:
            regex = re.compile(rule.pattern)
        except re.error:
            # Ignore invalid regex (treated as unmet); the caller skips it.
            continue
        toks = result.setdefault(rule.var, [])
        for m in regex.finditer(output or ""):
            if "val" in (m.groupdict() or {}):
                value = m.group("val")
            elif m.groups():
                value = m.group(1)
            else:
                value = m.group(0)
            if value:
                toks.append((value, shlex.quote(value)))
        if not toks:
            result.pop(rule.var, None)
    return result


def apply_extract(
    rules: list[RTOExtractRule], output: str
) -> dict[str, tuple[str, str]]:
    """Apply extract rules to the output and return ``{var: (raw, rendered)}``.

    raw: extracted values concatenated with join (for when-evaluation/display).
    rendered: each match individually ``shlex.quote``-ed then concatenated with
    join (for command embedding; ``{{var}}`` can be used safely without quoting).

    Duplicate raw values are removed while preserving order. Variables with zero
    matches are omitted.
    """
    joined: dict[str, tuple[str, str]] = {}
    rule_by_var = {r.var: r for r in rules}
    for var, toks in extract_tokens(rules, output).items():
        sep = rule_by_var[var].join
        seen: set[str] = set()
        raw_parts: list[str] = []
        rend_parts: list[str] = []
        for raw, rend in toks:
            if raw in seen:
                continue
            seen.add(raw)
            raw_parts.append(raw)
            rend_parts.append(rend)
        if raw_parts:
            joined[var] = (sep.join(raw_parts), sep.join(rend_parts))
    return joined


def evaluate_when(cond: Any, state: dict[str, Any]) -> bool:
    """Evaluate a step/group ``when`` condition. None or non-dict is True (always run).

    ``state`` holds:
      - raw_variables: {var: raw value} (pre-quote; for var_present/var_equals)
      - outputs:       {step_id: output string}
      - judge_results: {step_id: verdict text}
      - step_status:   {step_id: "done"|"skipped"|"error"}

    Primitives: var_present / var_absent / var_equals{name,value} /
    output_matches{id,pattern} / judge_result{id,equals} / step_status{id,equals}.
    Composites: all[...] / any[...] / not{...}.
    """
    if cond is None or not isinstance(cond, dict):
        return True

    if "all" in cond:
        return all(evaluate_when(c, state) for c in cond["all"] or [])
    if "any" in cond:
        return any(evaluate_when(c, state) for c in cond["any"] or [])
    if "not" in cond:
        return not evaluate_when(cond["not"], state)

    variables = state.get("raw_variables", {})
    if "var_present" in cond:
        return bool(variables.get(cond["var_present"]))
    if "var_absent" in cond:
        return not bool(variables.get(cond["var_absent"]))
    if "var_equals" in cond:
        c = cond["var_equals"] or {}
        return variables.get(c.get("name")) == c.get("value")
    if "output_matches" in cond:
        c = cond["output_matches"] or {}
        out = state.get("outputs", {}).get(c.get("id"), "") or ""
        try:
            return re.search(c.get("pattern", ""), out) is not None
        except re.error:
            return False
    if "judge_result" in cond:
        c = cond["judge_result"] or {}
        jr = state.get("judge_results", {}).get(c.get("id"), "") or ""
        return str(c.get("equals", "")) in jr
    if "step_status" in cond:
        c = cond["step_status"] or {}
        return state.get("step_status", {}).get(c.get("id")) == c.get("equals")

    # Fail safe: unknown conditions do not run.
    return False
