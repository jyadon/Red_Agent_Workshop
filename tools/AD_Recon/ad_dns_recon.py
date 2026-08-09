#!/usr/bin/env python3
"""
ad-dns-recon: AD domain information auto-discovery tool v2
Automatically discovers a DC's FQDN/IP from a domain name.

Progress and diagnostic information is written to stderr via logging.
Only the final result (--json or human-readable summary) is written to stdout.
The backend launches this with --json --quiet and parses the JSON from stdout.
"""

import argparse
import json
import logging
import os
import socket
import sys
from datetime import datetime

# Env var used to pass the password, preferred over -p/--password to avoid
# cleartext exposure in process lists (`ps aux`); the CLI flag is kept for compatibility.
_PASSWORD_ENV_VAR = "AD_RECON_PASSWORD"

import dns.message
import dns.query
import dns.resolver
import socks
from impacket.dcerpc.v5 import rrp, transport
from impacket.smbconnection import SMBConnection


logger = logging.getLogger("ad_dns_recon")


def _configure_logging(quiet: bool, verbose: bool = False) -> None:
    """Configure logging so progress logs go to stderr (WARNING+ if quiet, DEBUG if verbose, else INFO)."""
    if quiet:
        level = logging.WARNING
    elif verbose:
        level = logging.DEBUG
    else:
        level = logging.INFO

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(levelname)s %(message)s"))

    root_logger = logging.getLogger()
    # Remove existing handlers to prevent duplicate output
    for h in list(root_logger.handlers):
        root_logger.removeHandler(h)
    root_logger.addHandler(handler)
    root_logger.setLevel(level)


def setup_socks_proxy(host, port):
    """Set the SOCKS proxy globally (with remote name resolution enabled)."""
    socks.set_default_proxy(socks.SOCKS5, host, port, rdns=True)
    socket.socket = socks.socksocket

    original_getaddrinfo = socket.getaddrinfo

    def patched_getaddrinfo(host, port, *args, **kwargs):
        try:
            socket.inet_aton(host)
            return original_getaddrinfo(host, port, *args, **kwargs)
        except (socket.error, OSError):
            pass
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (host, port))]

    socket.getaddrinfo = patched_getaddrinfo


def get_domain_from_smb(target, username, password, domain=""):
    """Retrieve the domain/host name via SMB negotiation."""
    try:
        smb = SMBConnection(target, target)
        smb.login(username, password, domain)
        server_domain = smb.getServerDNSDomainName()
        server_name = smb.getServerName()
        smb.close()
        return server_domain, server_name
    except Exception as e:
        logger.error("SMB connection failed against %s: %s", target, e)
        return None, None


def get_dns_from_registry(target, username, password, domain):
    """Read the DNS server configuration from the remote host's registry."""
    try:
        string_binding = f"ncacn_np:{target}[\\pipe\\winreg]"
        rpctransport = transport.DCERPCTransportFactory(string_binding)
        rpctransport.set_credentials(username, password, domain)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(rrp.MSRPC_UUID_RRP)

        resp = rrp.hOpenLocalMachine(dce)
        hklm = resp["phKey"]

        resp = rrp.hBaseRegOpenKey(
            dce,
            hklm,
            "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces",
        )
        interfaces_key = resp["phkResult"]

        dns_servers = set()
        index = 0
        while True:
            try:
                resp = rrp.hBaseRegEnumKey(dce, interfaces_key, index)
                subkey_name = resp["lpNameOut"][:-1]

                resp = rrp.hBaseRegOpenKey(dce, interfaces_key, subkey_name)
                iface_key = resp["phkResult"]

                for value_name in ["NameServer", "DhcpNameServer"]:
                    try:
                        resp = rrp.hBaseRegQueryValue(dce, iface_key, value_name)
                        value = resp[1].rstrip("\x00").strip()
                        if value:
                            for ip in value.replace(",", " ").split():
                                if ip and ip != "0.0.0.0":
                                    dns_servers.add(ip)
                    except Exception:
                        pass

                rrp.hBaseRegCloseKey(dce, iface_key)
                index += 1
            except Exception:
                break

        dce.disconnect()
        return list(dns_servers)
    except Exception as e:
        logger.error("Registry read failed: %s", e)
        return []


def resolve_dcs_via_srv(dns_server, domain):
    """Retrieve the DC list from SRV records."""
    results = []
    try:
        query = dns.message.make_query(
            f"_ldap._tcp.dc._msdcs.{domain}", dns.rdatatype.SRV
        )
        response = dns.query.tcp(query, dns_server, timeout=10)

        for answer in response.answer:
            for rdata in answer:
                if rdata.rdtype == dns.rdatatype.SRV:
                    dc_fqdn = str(rdata.target).rstrip(".")

                    a_query = dns.message.make_query(dc_fqdn, dns.rdatatype.A)
                    a_response = dns.query.tcp(a_query, dns_server, timeout=10)

                    for a_answer in a_response.answer:
                        for a_rdata in a_answer:
                            if a_rdata.rdtype == dns.rdatatype.A:
                                results.append(
                                    {
                                        "fqdn": dc_fqdn,
                                        "ip": str(a_rdata.address),
                                        "priority": rdata.priority,
                                        "weight": rdata.weight,
                                    }
                                )
    except Exception as e:
        logger.warning("SRV query failed against %s: %s", dns_server, e)

    return results


def discover_dc_via_pivot(pivot, username, password, domain):
    """Discover the DC through a pivot host."""
    logger.info("Mode: Pivot host discovery")
    logger.info("Step 1: Querying SMB on pivot host %s", pivot)

    discovered_domain, hostname = get_domain_from_smb(pivot, username, password, domain)
    if not discovered_domain:
        return None

    logger.info("Pivot host: %s", hostname)
    logger.info("Domain (from SMB): %s", discovered_domain)

    if domain and domain.lower() != discovered_domain.lower():
        logger.warning(
            "Specified domain (%s) differs from pivot's domain (%s)",
            domain,
            discovered_domain,
        )

    target_domain = domain or discovered_domain

    logger.info("Step 2: Reading DNS configuration from %s", pivot)
    dns_servers = get_dns_from_registry(pivot, username, password, target_domain)
    if not dns_servers:
        logger.error("Could not read DNS servers from pivot")
        return None
    logger.info("DNS servers: %s", dns_servers)

    logger.info("Step 3: Querying SRV records for domain %s", target_domain)
    all_dcs = []
    for dns_srv in dns_servers:
        logger.info("Querying %s...", dns_srv)
        dcs = resolve_dcs_via_srv(dns_srv, target_domain)
        all_dcs.extend(dcs)

    return {"domain": target_domain, "dns_servers": dns_servers, "dcs": all_dcs}


def discover_dc_via_domain_name(domain, username, password):
    """Discover the DC by attempting to connect to the domain name itself."""
    logger.info("Mode: Direct domain name connection")
    logger.info("Trying SMB to %s (assuming it resolves to a DC)", domain)

    discovered_domain, hostname = get_domain_from_smb(
        domain, username, password, domain
    )
    if not discovered_domain:
        return None

    logger.info("Connected to: %s", hostname)
    logger.info("Domain: %s", discovered_domain)

    # Continue treating the DC itself as the pivot
    return discover_dc_via_pivot(domain, username, password, domain)


def discover_dc_via_dns_server(domain, dns_server):
    """Discover DCs by querying SRV records directly against the given DNS server.

    Requires no SMB/RPC authentication, so it works with AD-integrated DNS as well as
    non-AD-integrated DNS that still serves `_ldap._tcp.dc._msdcs.<domain>`.
    """
    logger.info("Mode: Direct DNS server query")
    logger.info("Querying SRV records for %s against %s", domain, dns_server)

    dcs = resolve_dcs_via_srv(dns_server, domain)
    if not dcs:
        logger.error(
            "No SRV records returned from %s for domain %s", dns_server, domain
        )
        return None

    return {"domain": domain, "dns_servers": [dns_server], "dcs": dcs}


def discover_dc_via_local_dns(domain):
    """Query SRV records directly via local DNS."""
    logger.info("Mode: Local DNS resolution")
    logger.info("Querying local DNS for SRV records of %s", domain)

    try:
        resolver = dns.resolver.Resolver()
        srv_records = resolver.resolve(
            f"_ldap._tcp.dc._msdcs.{domain}", "SRV", tcp=True
        )

        dcs = []
        for rdata in srv_records:
            dc_fqdn = str(rdata.target).rstrip(".")
            try:
                a_records = resolver.resolve(dc_fqdn, "A", tcp=True)
                for a in a_records:
                    dcs.append(
                        {
                            "fqdn": dc_fqdn,
                            "ip": str(a.address),
                            "priority": rdata.priority,
                            "weight": rdata.weight,
                        }
                    )
            except Exception:
                pass

        return {"domain": domain, "dns_servers": ["(local)"], "dcs": dcs}
    except Exception as e:
        logger.error("Local DNS query failed: %s", e)
        return None


def build_json_output(result, args):
    """Convert the result into a JSON structure."""
    if not result:
        return {
            "success": False,
            "error": "No results obtained",
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }

    unique_dcs = {}
    for dc in result.get("dcs", []):
        if dc["fqdn"] not in unique_dcs:
            unique_dcs[dc["fqdn"]] = dc

    output = {
        "success": len(unique_dcs) > 0,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "query": {
            "domain": args.domain,
            "mode": "dns-server"
            if args.dns_server
            else "local-dns"
            if args.local_dns
            else "pivot"
            if args.pivot
            else "direct",
            "pivot_host": args.pivot,
            "socks_proxy": None
            if args.no_socks
            else f"{args.socks_host}:{args.socks_port}",
        },
        "result": {
            "domain": result.get("domain"),
            "dns_servers": result.get("dns_servers", []),
            "domain_controllers": [
                {
                    "fqdn": fqdn,
                    "short_name": fqdn.split(".")[0],
                    "ip": info["ip"],
                    "priority": info["priority"],
                    "weight": info["weight"],
                }
                for fqdn, info in unique_dcs.items()
            ],
        },
        "hosts_entries": [
            {
                "ip": info["ip"],
                "fqdn": fqdn,
                "short_name": fqdn.split(".")[0],
            }
            for fqdn, info in unique_dcs.items()
        ],
    }
    return output


def print_results(result, args):
    """Display results according to the output mode, writing only the final result to stdout."""
    if args.json:
        output = build_json_output(result, args)
        # Parsed by the backend; write to stdout.
        print(json.dumps(output, indent=2, ensure_ascii=False))
        return

    if not result or not result["dcs"]:
        print("\n[-] No DCs found")
        return

    unique_dcs = {dc["fqdn"]: dc for dc in result["dcs"]}

    print(f"\n{'=' * 60}")
    print(f"Results for domain: {result['domain']}")
    print(f"{'=' * 60}")
    print(f"\n[+] Domain Controllers:")
    for fqdn, info in unique_dcs.items():
        print(
            f"    {fqdn} -> {info['ip']} "
            f"(priority={info['priority']}, weight={info['weight']})"
        )

    print(f"\n[+] Information:")
    for fqdn, info in unique_dcs.items():
        short = fqdn.split(".")[0]
        print(f"    IP Address: {info['ip']}")
        print(f"    FQDN: {fqdn}")
        print(f"    Short: {short}")


def main():
    parser = argparse.ArgumentParser(
        description="Discover Domain Controllers from a domain name",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # DNS-server mode (when AD DNS is reachable but is not itself a DC)
  %(prog)s lab.local --dns-server 10.0.1.10

  # Pivot host mode (recommended)
  %(prog)s lab.local --pivot 192.168.1.50 -u user -p pass

  # Direct mode (domain name resolves to DC)
  %(prog)s lab.local -u user -p pass

  # Local DNS mode (when /etc/resolv.conf points to internal DNS)
  %(prog)s lab.local --local-dns
""",
    )
    parser.add_argument("domain", help="AD domain name (e.g., lab.local)")
    parser.add_argument("--pivot", help="Pivot/member host to query (IP or hostname)")
    parser.add_argument(
        "--dns-server",
        help=(
            "DNS server IP to query directly for SRV records "
            "(no SMB/RPC auth required; use when DNS is reachable but is not a DC)."
        ),
    )
    parser.add_argument("-u", "--username")
    parser.add_argument(
        "-p",
        "--password",
        help=(
            "Password for SMB/RPC authentication. "
            f"If omitted, falls back to env var ${_PASSWORD_ENV_VAR} "
            "(preferred — avoids `ps aux` exposure)."
        ),
    )
    parser.add_argument(
        "--local-dns",
        action="store_true",
        help="Use local DNS resolver (no auth needed)",
    )
    parser.add_argument("--socks-host", default="127.0.0.1")
    parser.add_argument("--socks-port", type=int, default=1080)
    parser.add_argument("--no-socks", action="store_true", help="Disable SOCKS proxy")
    parser.add_argument(
        "--json", action="store_true", help="Output results in JSON format"
    )
    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Suppress progress messages (logging level=WARNING)",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose progress messages (logging level=DEBUG)",
    )
    args = parser.parse_args()

    _configure_logging(quiet=args.quiet, verbose=args.verbose)

    # Prefer the env var over the CLI arg (avoids cleartext exposure in `ps aux`), and
    # pop it immediately after reading to prevent inheritance by child processes.
    env_password = os.environ.pop(_PASSWORD_ENV_VAR, None)
    if env_password:
        if args.password and args.password != env_password:
            logger.warning(
                "Both -p/--password and $%s were given; using $%s.",
                _PASSWORD_ENV_VAR,
                _PASSWORD_ENV_VAR,
            )
        args.password = env_password

    if not args.no_socks:
        setup_socks_proxy(args.socks_host, args.socks_port)
        logger.info(
            "Using SOCKS5 proxy at %s:%s", args.socks_host, args.socks_port
        )

    result = None

    if args.dns_server:
        # Mode D: direct SRV query against the given DNS server (no auth)
        result = discover_dc_via_dns_server(args.domain, args.dns_server)
    elif args.local_dns:
        # Mode C: local DNS
        result = discover_dc_via_local_dns(args.domain)
    elif args.pivot:
        # Mode A: via pivot host
        if not args.username or not args.password:
            logger.error("--pivot requires -u and -p")
            sys.exit(1)
        result = discover_dc_via_pivot(
            args.pivot, args.username, args.password, args.domain
        )
    else:
        # Mode B: direct domain name
        if not args.username or not args.password:
            logger.error("Direct domain mode requires -u and -p")
            sys.exit(1)
        result = discover_dc_via_domain_name(args.domain, args.username, args.password)

    print_results(result, args)


if __name__ == "__main__":
    main()
