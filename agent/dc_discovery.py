"""Mechanical extraction of domain controller info and a finding-wide cache.

Design principles:
- Do not rely on LLM output or free-form text. Parse only the strictly known
  formats of command results (`dig SRV +short`, `dig +short <host>`,
  `nxc smb ...`) via regular expressions.
- If a line does not match a pattern exactly, do not register it (false negatives
  are acceptable, false positives are forbidden).
- Valid only within the same process (the cache is lost on process restart).
"""
from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class DCEntry:
    hostname: str  # FQDN, lowercase, trailing "." stripped
    ip: str | None  # IPv4 dotted notation, or None when not resolved
    discovered_at: float = field(default_factory=time.time)
    source: str = "unknown"


# domain (lowercase, trailing "." stripped) -> list of DCEntry
_DC_CACHE: dict[str, list[DCEntry]] = {}


# ----------------------------
# Strict parsers
# ----------------------------

# Each line of `dig @<dns> _ldap._tcp.<domain> SRV +short`:
#   "0 100 389 dc01.corp.local."
# Leading/trailing whitespace allowed; any other malformed format is rejected.
_DIG_SRV_SHORT_LINE_RE = re.compile(
    r"^\s*\d+\s+\d+\s+\d+\s+([a-zA-Z][a-zA-Z0-9_.-]*?)\.?\s*$"
)

# Extract the SRV query target domain from the command string
#   e.g. "dig @10.0.1.10 _ldap._tcp.corp.local SRV +short"
_DIG_SRV_QUERY_DOMAIN_RE = re.compile(
    r"_ldap\._tcp\.([a-zA-Z][a-zA-Z0-9.-]*[a-zA-Z0-9])",
    re.IGNORECASE,
)

# IPv4 literal (strict, 0-255 range)
_IPV4_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
_IPV4_LINE_RE = re.compile(
    rf"^\s*({_IPV4_OCTET}(?:\.{_IPV4_OCTET}){{3}})\s*$"
)

# Extract the target host from `dig @<dns> +short <hostname>`.
_DIG_A_HOST_RE = re.compile(r"\bdig\b(?P<args>.+)", re.IGNORECASE)
_HOSTNAME_TOKEN_RE = re.compile(
    r"^(?!_)[a-zA-Z][a-zA-Z0-9-]*(?:\.[a-zA-Z][a-zA-Z0-9-]*)+\.?$"
)

# Output line of `nxc smb <target> -u ... -p ...` (NetExec / CrackMapExec compatible):
#   "SMB    10.0.1.5  445  DC01    [*] ... (name:DC01) (domain:corp.local) ..."
_NXC_SMB_LINE_RE = re.compile(
    r"\bSMB\b\s+"
    r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\s+"
    r"\d+\s+"
    r"\S+\s+"
    r".*?\(name:(?P<name>[^)\s]+)\)\s*"
    r"\(domain:(?P<domain>[^)\s]+)\)",
    re.IGNORECASE,
)


# ----------------------------
# Normalization
# ----------------------------

def _normalize_hostname(host: str) -> str:
    return host.strip().rstrip(".").lower()


def _normalize_domain(domain: str) -> str:
    return domain.strip().rstrip(".").lower()


def _is_valid_hostname(host: str) -> bool:
    return bool(_HOSTNAME_TOKEN_RE.match(host.rstrip(".")))


def _is_valid_ipv4(ip: str) -> bool:
    return bool(_IPV4_LINE_RE.match(ip))


# ----------------------------
# Parsers (pure functions)
# ----------------------------

def parse_dig_srv(output: str) -> list[str]:
    """Return hostnames (FQDN, lowercase, trailing "." stripped) from `dig SRV +short` output."""
    results: list[str] = []
    for line in output.splitlines():
        m = _DIG_SRV_SHORT_LINE_RE.match(line)
        if not m:
            continue
        candidate = _normalize_hostname(m.group(1))
        if _is_valid_hostname(candidate):
            results.append(candidate)
    return results


def parse_dig_a_first_ip(output: str) -> str | None:
    """Return the first IPv4 from `dig +short <host>` output (assumes one IP per line)."""
    for line in output.splitlines():
        m = _IPV4_LINE_RE.match(line)
        if m:
            return m.group(1)
    return None


def parse_nxc_smb(output: str) -> list[tuple[str, str, str]]:
    """Extract (domain, hostname FQDN, ip) tuples from `nxc smb` output, exact matches only."""
    results: list[tuple[str, str, str]] = []
    for m in _NXC_SMB_LINE_RE.finditer(output):
        ip = m.group("ip")
        netbios = m.group("name")
        domain = _normalize_domain(m.group("domain"))
        if not _is_valid_ipv4(ip) or not domain or not netbios:
            continue
        fqdn = _normalize_hostname(f"{netbios}.{domain}")
        if not _is_valid_hostname(fqdn):
            continue
        results.append((domain, fqdn, ip))
    return results


def extract_dig_srv_domain_from_command(command: str) -> str | None:
    """Extract the domain part from a `dig ... _ldap._tcp.<domain> SRV ...` command."""
    m = _DIG_SRV_QUERY_DOMAIN_RE.search(command)
    return _normalize_domain(m.group(1)) if m else None


def extract_dig_a_host_from_command(command: str) -> str | None:
    """Roughly extract the target hostname from a `dig` command's args. SRV queries are excluded."""
    if "_ldap._tcp" in command.lower():
        return None
    m = _DIG_A_HOST_RE.search(command)
    if not m:
        return None
    args = m.group("args")
    for token in args.split():
        # Skip `@` args (DNS server), flags, and record-type keywords.
        if token.startswith("@") or token.startswith("-") or token.startswith("+"):
            continue
        if token.upper() in {"A", "AAAA", "MX", "TXT", "ANY", "PTR", "NS", "SOA", "CNAME"}:
            continue
        if _is_valid_hostname(token):
            return _normalize_hostname(token)
    return None


# ----------------------------
# Cache operations
# ----------------------------

def register_dc(domain: str, hostname: str, ip: str | None, source: str) -> DCEntry | None:
    """Add or merge a DC entry for the domain, with strict validation. Returns None on failure."""
    domain_key = _normalize_domain(domain)
    host_key = _normalize_hostname(hostname)

    if not domain_key or not _is_valid_hostname(host_key):
        return None
    if ip is not None and not _is_valid_ipv4(ip):
        return None

    entries = _DC_CACHE.setdefault(domain_key, [])

    # Merge with existing host (only backfill IP; never change the hostname).
    for i, existing in enumerate(entries):
        if existing.hostname == host_key:
            if existing.ip == ip:
                return existing
            if existing.ip is None and ip is not None:
                merged = DCEntry(
                    hostname=existing.hostname,
                    ip=ip,
                    discovered_at=time.time(),
                    source=source,
                )
                entries[i] = merged
                logger.info("DC entry updated: domain=%s host=%s ip=%s", domain_key, host_key, ip)
                return merged
            # Do not overwrite an existing IP (prevents rewrites from misdetection).
            return existing

    entry = DCEntry(hostname=host_key, ip=ip, source=source)
    entries.append(entry)
    logger.info("DC entry registered: domain=%s host=%s ip=%s source=%s",
                domain_key, host_key, ip, source)
    return entry


def update_ip_by_hostname(hostname: str, ip: str) -> bool:
    """Backfill IP on entries matching the FQDN, across all domains if it spans several."""
    target = _normalize_hostname(hostname)
    if not _is_valid_hostname(target) or not _is_valid_ipv4(ip):
        return False
    updated = False
    for entries in _DC_CACHE.values():
        for i, e in enumerate(entries):
            if e.hostname == target and e.ip is None:
                entries[i] = DCEntry(
                    hostname=e.hostname,
                    ip=ip,
                    discovered_at=time.time(),
                    source="dig_a",
                )
                updated = True
    if updated:
        logger.info("DC IP backfilled: host=%s ip=%s", target, ip)
    return updated


def get_dcs(domain: str) -> list[DCEntry]:
    return list(_DC_CACHE.get(_normalize_domain(domain), []))


def get_all_cached_dcs() -> dict[str, list[DCEntry]]:
    """Return a shallow copy of the full DC cache (for the debug API) so callers cannot mutate _DC_CACHE."""
    return {domain: list(entries) for domain, entries in _DC_CACHE.items()}


def clear_dc_cache() -> None:
    """For test/admin use."""
    _DC_CACHE.clear()


def format_dcs_for_prompt(domain: str) -> str:
    """Return plain text to embed into build_finding_prompt; empty string if the cache is empty."""
    entries = get_dcs(domain)
    if not entries:
        return ""
    lines = [
        f"[Known domain controllers (discovered in prior verifications within this process, domain={_normalize_domain(domain)})]"
    ]
    for e in entries:
        ip_str = e.ip if e.ip else "IP not resolved"
        lines.append(f"  - {e.hostname} ({ip_str})  [source: {e.source}]")
    return "\n".join(lines)


# ----------------------------
# Dispatcher over command output
# ----------------------------

def absorb_command_output(
    command: str,
    output: str,
    default_domain: str | None = None,
) -> int:
    """Identify the command type, extract and register DC info with the matching parser.

    Returns the number of entries registered (new + merged). Commands that cannot
    be clearly identified are skipped to avoid misextraction.
    """
    if not command or not output:
        return 0

    cmd_lower = command.lower()
    count = 0

    # 1) dig / nslookup SRV query
    if "_ldap._tcp" in cmd_lower and ("dig" in cmd_lower or "nslookup" in cmd_lower):
        domain_from_cmd = extract_dig_srv_domain_from_command(command) or (
            _normalize_domain(default_domain) if default_domain else None
        )
        if domain_from_cmd:
            for host in parse_dig_srv(output):
                if register_dc(domain_from_cmd, host, None, source="dig_srv") is not None:
                    count += 1

    # 2) dig A record (+short)
    elif "dig" in cmd_lower and "+short" in cmd_lower and "_ldap._tcp" not in cmd_lower:
        target_host = extract_dig_a_host_from_command(command)
        ip = parse_dig_a_first_ip(output)
        if target_host and ip:
            if update_ip_by_hostname(target_host, ip):
                count += 1
            elif default_domain:
                # Not yet registered: create a new entry under default_domain.
                if register_dc(default_domain, target_host, ip, source="dig_a") is not None:
                    count += 1

    # 3) nxc / netexec smb output (loose command match, strict output format).
    #    netexec is the same successor tool as nxc and does not substring-match "nxc",
    #    so both spellings are allowed.
    if ("nxc" in cmd_lower or "netexec" in cmd_lower) and "smb" in cmd_lower:
        for domain_str, fqdn, ip in parse_nxc_smb(output):
            if register_dc(domain_str, fqdn, ip, source="nxc_smb") is not None:
                count += 1

    return count
