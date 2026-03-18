# module/input.py

from __future__ import annotations
from typing import List, Dict, Any
from pathlib import Path
import ipaddress  # NEW: for strict IP/CIDR validation

from .normalization import normalize_rule, load_and_normalize_new
from .directory import PROJECT_ROOT

# ANSI (for nicer UX; kept minimal and consistent)
RESET = "\033[0m"
FG_GREEN = "\033[32m"
FG_LIGHT_YELLOW = "\033[1;33m"
FG_CYAN = "\033[36m"
FG_RED = "\033[31m"


def _read_choice(prompt: str, valid: set[str]) -> str:
    """
    Read a single-choice input that must be in the `valid` set.
    Keeps prompting until a valid value is entered.
    """
    valid_lower = {v.lower() for v in valid}
    while True:
        choice = (input(prompt) or "").strip().lower()
        if choice in valid_lower:
            return choice
        print(f"{FG_RED}Invalid choice. Please try again by giving input either 1 or 2.{RESET}\n")


def _prompt_nonempty(label: str) -> str:
    """
    Prompt for a non-empty single-line string. Re-prompts if empty.
    """
    while True:
        val = input(f"{label}: ").strip()
        if val:
            return val
        print(f"{FG_RED}{label} cannot be empty. Please enter a value.{RESET}\n")


def _prompt_list_required(label: str) -> List[str]:
    """
    Prompt for a comma-separated list with at least one item.
    Does NOT accept 'any' and does not allow empty input.
    Re-prompts until at least one valid token is provided.
    """
    while True:
        raw = input(f"{label}: ").strip()
        items = [x.strip() for x in raw.split(",") if x.strip()]
        # Filter out accidental 'any'
        items = [x for x in items if x.lower() != "any"]
        if items:
            return items
        print(f"{FG_RED}{label} cannot be empty or 'any'. Please enter one or more values.{RESET}\n")


# ====== UPDATED: allow 'any' for IP lists AND validate proper IP/CIDR tokens ======
def _prompt_list_ip_allow_any(label: str) -> List[str]:
    """
    Prompt for IP list fields that may accept 'any' (Source IP or Destination IP).
    - If user types exactly 'any', returns ['any'].
    - Otherwise requires a comma-separated list of valid IPv4/IPv6 addresses or CIDRs.
      Examples: 10.0.0.1, 10.0.0.0/24, 2001:db8::1, 2001:db8::/32
    """
    def _is_valid_ip_token(tok: str) -> bool:
        tok = tok.strip()
        if not tok:
            return False
        try:
            if "/" in tok:
                # Accept IPv4/IPv6 prefixes (CIDR). strict=False also accepts host /32 or /128 as network.
                ipaddress.ip_network(tok, strict=False)
            else:
                # Accept single IPv4/IPv6 addresses.
                ipaddress.ip_address(tok)
            return True
        except ValueError:
            return False

    while True:
        raw = input(f"{label}: ").strip()
        if not raw:
            print(f"{FG_RED}{label} cannot be empty. Enter 'any' or one/more IPs/CIDRs.{RESET}\n")
            continue

        if raw.lower() == "any":
            return ["any"]

        items = [x.strip() for x in raw.split(",") if x.strip()]
        invalid = [x for x in items if not _is_valid_ip_token(x)]
        if invalid:
            print(
                f"{FG_RED}Invalid {label}: {', '.join(invalid)}{RESET}\n"
                f"{FG_RED}Allowed: 'any' or valid IPv4/IPv6 address/CIDR{RESET}\n"
            )
            continue

        if items:
            return items

        print(f"{FG_RED}Please enter 'any' or one/more {label} values (comma-separated).{RESET}\n")
# ============================================================================


def _prompt_protocol() -> str:
    """
    Prompt for a single protocol from allowed set.
    No default. No 'any'.
    """
    allowed = {"tcp", "udp", "icmp", "smtp", "ftp"}
    while True:
        p = (input(f"Protocol: ") or "").strip().lower()
        if p in allowed:
            return p
        print(f"{FG_RED}Invalid protocol. Allowed: {', '.join(sorted(allowed))}.{RESET}\n")


def _prompt_ports_required() -> List[str]:
    """
    Prompt for ports (single numbers like 443, ranges like 1000-2000).
    No default. No 'any'. At least one required.
    Basic syntactic validation: numbers and ranges only.
    """
    def _is_valid_token(tok: str) -> bool:
        tok = tok.strip()
        if not tok:
            return False
        if "-" in tok:
            parts = tok.split("-", 1)
            if len(parts) != 2:
                return False
            a, b = parts[0].strip(), parts[1].strip()
            return a.isdigit() and b.isdigit() and int(a) >= 1 and int(b) >= 1
        return tok.isdigit() and int(tok) >= 1

    while True:
        # CHANGED: added the prompt so "Port" is visible
        raw = input("Port: ").strip()
        items = [x.strip() for x in raw.split(",") if x.strip()]
        items = [x for x in items if x.lower() != "any"]
        if items and all(_is_valid_token(x) for x in items):
            return items
        print(f"{FG_RED}Please enter at least one valid port or port-range (no 'any').{RESET}\n")


# ====== NEW: site must be DC1/DC2/DC3 only ======
def _prompt_site_dc_only() -> str:
    """
    Prompt for Site that must be one of DC1, DC2, DC3 (case-insensitive).
    Returns the normalized uppercase value.
    """
    allowed = {"dc1", "dc2", "dc3"}
    while True:
        site = (input("Site: ") or "").strip().lower()
        if site in allowed:
            return site.upper()
        print(f"{FG_RED}Invalid site. Allowed values: DC1, DC2, or DC3.{RESET}\n")
# ===============================================


def _manual_rule_input_minimal() -> Dict[str, Any]:
    """
    Collect only the fields you requested and build a rule suitable for normalization/checking:
      - Site (stored as DC1, DC2, or DC3 for display)
      - Source Zone
      - Source IP
      - Destination Zone
      - Destination IP
      - Port
      - Protocol

    No defaults; re-prompts until valid entries are provided.
    """
    print(f"\n{FG_LIGHT_YELLOW}Enter New Rule:{RESET}")
    # CHANGED: enforce DC1/DC2/DC3 only
    site = _prompt_site_dc_only()
    src_zone = _prompt_list_required("Source Zone")
    # CHANGED: allow 'any' for Source IP, else require valid IPv4/IPv6 address/CIDR
    src_ip = _prompt_list_ip_allow_any("Source IP")
    dst_zone = _prompt_list_required("Destination Zone")
    # CHANGED: allow 'any' for Destination IP, else require valid IPv4/IPv6 address/CIDR
    dst_ip = _prompt_list_ip_allow_any("Destination IP")
    dst_ports = _prompt_ports_required()
    protocol = _prompt_protocol()

    # Build the minimal rule. We map "Site" to firewall_name so it shows nicely in output.
    # Vendor defaulted to cisco; action is irrelevant to collision logic.
    rule = {
        "rule_name": "",
        "firewall_name": site,
        "src_zones": src_zone,
        "dst_zones": dst_zone,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": protocol,
        "ports": dst_ports
    }
    return rule


def run_input_flow() -> List[Dict[str, Any]]:
    """
    Presents the user with:
      - (1) Input Manually (with ONLY the fields requested, Source/Destination IP can be 'any')
      - (2) Input as File (auto-load new_rules.json from project root)

    Returns a list of **normalized** rules ready for collision checking.
    """
    print(f"\n{FG_LIGHT_YELLOW}Please choose your input based on your task:{RESET}")
    print("(1) Input Manually")
    print("(2) Input as File\n")

    choice = _read_choice("Enter choice: ", {"1", "2"})

    if choice == "2":
        # Auto-load new_rules.json from project root
        default_file = Path(PROJECT_ROOT) / "new_rules.json"
        if not default_file.exists():
            print(f"{FG_LIGHT_YELLOW}Error: new_rules.json not found at: {default_file}{RESET}\n")
            return []
        try:
            normalized = load_and_normalize_new(default_file)
            print(f"\nLoaded {len(normalized)} rule(s) from {default_file}")
            return normalized
        except Exception as e:
            print(f"{FG_RED}Failed to load new rules from file: {e}{RESET}\n")
            return []

    # Manual entry with minimal fields
    normalized_out: List[Dict[str, Any]] = []
    while True:
        raw_rule = _manual_rule_input_minimal()
        normalized = normalize_rule(raw_rule)
        normalized_out.append(normalized)

        more = _read_choice(f"\n{FG_LIGHT_YELLOW}Add another rule to check? (y/n) : {RESET}", {"y", "n"})
        if more == "n":
            break

    return normalized_out