import os
import re
import shlex
import subprocess

from fastmcp import FastMCP

mcp = FastMCP("Kali-Direct-Manager")

# proxychains prefixing control.
# - KALI_PROXY_ENABLED: set to "false" as a master switch to never prefix (for testing).
# - KALI_PROXY_COMMAND: the command to prefix (default `proxychains -q`).
#
# Whether proxychains is needed differs per command, so the caller specifies it each
# time via use_proxychains. When KALI_PROXY_ENABLED=false, nothing is prefixed regardless
# of use_proxychains. For backward compatibility use_proxychains defaults to True
# (same as the previous "always prefix" behavior).
_PROXY_ENABLED = os.getenv("KALI_PROXY_ENABLED", "true").strip().lower() != "false"
_PROXY_COMMAND = os.getenv("KALI_PROXY_COMMAND", "proxychains -q").strip()
_PROXY_TOKENS = shlex.split(_PROXY_COMMAND) if _PROXY_COMMAND else []

# Binaries that already imply proxychains; used to avoid a double prefix when the caller
# (or the LLM) accidentally included proxychains in the command string.
_PROXYCHAINS_BINS = {"proxychains", "proxychains4", "proxychains-ng"}


def _already_proxychained(argv: list[str]) -> bool:
    """True when argv already begins with a proxychains binary (optionally via sudo)."""
    if not argv:
        return False
    if argv[0] in _PROXYCHAINS_BINS:
        return True
    return argv[0] == "sudo" and len(argv) > 1 and argv[1] in _PROXYCHAINS_BINS


def _build_argv(command: str, use_proxychains: bool = True) -> list[str]:
    """Split a command string into an argv list and optionally prepend the proxychains
    tokens.

    SECURITY: the returned argv is executed with shell=False, so shell metacharacters in
    the command string (`;` `|` `&&` `$(...)` `>` backticks, etc.) become literal
    arguments to the target binary rather than being interpreted by a shell. This removes
    the command-injection / chaining surface: a single command string can only ever invoke
    the one binary at argv[0]. Raises ValueError on unbalanced quotes (propagated to the
    caller as a parse error).
    """
    argv = shlex.split(command)
    if not argv:
        return argv
    if not use_proxychains or not _PROXY_ENABLED or not _PROXY_TOKENS:
        return argv
    if _already_proxychained(argv):
        # Already prefixed (e.g. the LLM mistakenly included proxychains); run as-is.
        return argv
    return [*_PROXY_TOKENS, *argv]


@mcp.tool()
def execute_kali_command(command: str, use_proxychains: bool = True) -> str:
    """
    Run a single command in the Kali Linux terminal and return its output.
    Examples: 'nmap -sV 127.0.0.1', 'ls -la', 'whoami'

    The command is tokenized (shell-style quoting is honored) and executed WITHOUT a shell
    (shell=False), so it invokes exactly one binary. Shell features such as pipes (`|`),
    redirection (`>`), chaining (`;`, `&&`), and command substitution (`$(...)`) are NOT
    supported -- such characters are passed to the binary as literal arguments. Design each
    call as one tool invocation.

    use_proxychains: set True for commands that must reach the target network over
    SOCKS, and False for commands that stay local to Kali or do not support a proxy.
    When True, proxychains is prefixed automatically (can be master-disabled via the
    KALI_PROXY_ENABLED=false environment variable). Defaults to True (always prefix).
    """
    try:
        argv = _build_argv(command, use_proxychains)
    except ValueError as e:
        # Unbalanced quotes, etc. Surface as output rather than raising so the agent sees it.
        return f"Command parse error: {e}"
    if not argv:
        return "No command was provided."
    try:
        result = subprocess.run(
            argv,
            shell=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
        output = result.stdout + result.stderr
        return output if output else "The command completed successfully but produced no output."
    except FileNotFoundError:
        # shell=False raises this when the binary is missing (shell=True previously reported
        # it via stderr). Keep the message shape stable for the agent.
        return f"Execution error: command not found: {argv[0]}"
    except Exception as e:
        return f"Execution error: {str(e)}"


_HELP_OUTPUT_CAP = int(os.getenv("COMMAND_HELP_OUTPUT_CAP", "8000"))
# A bare program name only: a letter/digit followed by name chars. No path separators or shell
# metacharacters, so `--help` can only target a binary on PATH (not an arbitrary absolute path).
_BINARY_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")


@mcp.tool()
def command_help(binary: str) -> str:
    """
    Return the `--help` text of a binary (advisory only). This helps a human reviewer spot
    invalid or nonexistent options while editing a command's arguments; it does not run any
    target-affecting action. Executed without a shell and without proxychains (help is local),
    with a short timeout and capped output. Returns an error string on failure.
    """
    name = (binary or "").strip()
    if not name:
        return "No binary name was provided."
    if not _BINARY_NAME_RE.fullmatch(name):
        return f"Invalid binary name: {name}"
    try:
        result = subprocess.run(
            [name, "--help"],
            shell=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
        text = ((result.stdout or "") + (result.stderr or "")).strip()
        if not text:
            return f"{name} --help produced no output."
        return text[:_HELP_OUTPUT_CAP]
    except FileNotFoundError:
        return f"command not found: {name}"
    except subprocess.TimeoutExpired:
        return f"{name} --help timed out."
    except Exception as e:
        return f"Error running {name} --help: {e}"


if __name__ == "__main__":
    mcp.run()
