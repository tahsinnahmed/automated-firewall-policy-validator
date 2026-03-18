# module/display.py

from pathlib import Path
from typing import Union, Iterable, List, Dict, Any
import sys

# Paths/constants used for banner suppression and vendor rule sources
try:
    from .directory import WELCOME_ANSI, DEFAULT_RULES_CISCO, DEFAULT_RULES_PALOALTO
except Exception:
    WELCOME_ANSI = None
    DEFAULT_RULES_CISCO = None
    DEFAULT_RULES_PALOALTO = None

# Normalization loader to parse & normalize vendor rule files
try:
    from .normalization import load_and_normalize_existing
except Exception:
    load_and_normalize_existing = None

# Collision computation
try:
    from .checker import find_collisions
except Exception:
    find_collisions = None

# ANSI colors (kept minimal)
RESET = "\033[0m"
FG_GREEN = "\033[32m"
FG_YELLOW = "\033[33m"
FG_LIGHT_YELLOW = "\033[1;33m"
FG_CYAN = "\033[36m"
FG_RED = "\033[31m"


# ---------------------------- Core file display ---------------------------- #

def _print_one(file_path: Path, exit_on_missing: bool, suppress_banner: bool = False) -> None:
    """
    Prints a single file. If suppress_banner=True AND this is the welcome.ansi file,
    prints content without the header/footer bar.
    """
    if not file_path:
        return
    if not file_path.exists():
        print(f"{FG_RED}Error: file not found → {file_path}{RESET}")
        if exit_on_missing:
            sys.exit(1)
        return

    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        print(f"{FG_RED}Error reading file {file_path}: {e}{RESET}")
        if exit_on_missing:
            sys.exit(1)
        return

    suppress_for_welcome = False
    try:
        if WELCOME_ANSI is not None:
            suppress_for_welcome = file_path.resolve() == Path(WELCOME_ANSI).resolve()
    except Exception:
        suppress_for_welcome = False

    if suppress_banner and suppress_for_welcome:
        print(content)
        return

    print(f"\n{FG_CYAN}============ {file_path.name} ============{RESET}\n")
    print(content)
    print(f"{FG_CYAN}================= End ================={RESET}\n")


def show_logs(
    path_or_paths: Union[str, Path, Iterable[Union[str, Path]]],
    exit_on_missing: bool = False,
    suppress_banner: bool = False
) -> None:
    """
    Displays one or multiple files with optional header/footer banner.
    """
    if isinstance(path_or_paths, (list, tuple, set)):
        for p in path_or_paths:
            _print_one(Path(p), exit_on_missing=False, suppress_banner=suppress_banner)
        return

    if path_or_paths is None:
        print(f"{FG_RED}No file to show.{RESET}")
        return

    _print_one(Path(path_or_paths), exit_on_missing=exit_on_missing, suppress_banner=suppress_banner)


# ----------------------- Helpers for rule field formatting ------------------ #

def _fmt_ports(ports: List[Dict[str, int]]) -> str:
    """
    Format a list of port ranges like [{"from":80,"to":80},{"from":1000,"to":2000}]
    into "80, 1000-2000". Returns "any" if empty/invalid.
    """
    parts: List[str] = []
    for r in ports or []:
        try:
            f = int(r.get("from"))
            t = int(r.get("to"))
        except Exception:
            continue
        if f == t:
            parts.append(str(f))
        else:
            parts.append(f"{min(f, t)}-{max(f, t)}")
    return ", ".join(parts) if parts else "any"


def _fmt_ips(ips: List[str]) -> str:
    return ", ".join(ips) if ips else "any"


def _fmt_list(vals: List[str]) -> str:
    return ", ".join(vals) if vals else "any"


# ------------------- Rules-by-site (vendor shown ONLY in header) ------------ #

def show_rules_by_site_vendor(site: str, vendor: str) -> None:
    """
    Loads the appropriate vendor rules file, normalizes, filters by SITE,
    and prints the rules.

    Vendor name is shown ONLY in the header line:
      "\n{FG_CYAN}================ {target_site} : {vendor_name} Firewall Rules ================{RESET}\n"
    """
    # Resolve vendor -> file path & printable name
    vkey = (vendor or "").strip().lower()
    if vkey in ("1", "cisco"):
        rules_path = Path(DEFAULT_RULES_CISCO) if DEFAULT_RULES_CISCO else None
        vendor_name = "Cisco"
    elif vkey in ("2", "paloalto"):
        rules_path = Path(DEFAULT_RULES_PALOALTO) if DEFAULT_RULES_PALOALTO else None
        vendor_name = "PaloAlto"
    else:
        print(f"{FG_RED}Invalid vendor selection.{RESET}")
        return

    if not rules_path or not rules_path.exists():
        print(f"{FG_RED}Rules file not found for selected vendor.{RESET}")
        return

    if load_and_normalize_existing is None:
        print(f"{FG_RED}Normalization module not available. Cannot load rules.{RESET}")
        return

    # Normalize site
    target_site = (site or "").strip().upper()
    if not target_site:
        print(f"{FG_RED}Invalid site selection.{RESET}")
        return

    # Load & filter by site
    try:
        normalized_rules = load_and_normalize_existing([rules_path])
    except Exception as e:
        print(f"{FG_RED}Failed to load/normalize rules: {e}{RESET}")
        return

    filtered = [r for r in (normalized_rules or []) if (r.get("site") or "").strip().upper() == target_site]

    # Header with vendor name shown ONLY here (as requested)
    print(f"\n{FG_CYAN}================ {target_site} : {vendor_name} Firewall Rules ================{RESET}\n")

    if not filtered:
        print(f"{FG_RED}No rules found for site {target_site}, where vendor is {vendor_name}.{RESET}")
        print(f"\n{FG_CYAN}============================ End ============================={RESET}\n")
        return

    # Body WITHOUT vendor name
    for idx, r in enumerate(filtered, start=1):
        print(f"{FG_LIGHT_YELLOW}Rule {idx}:{RESET}")
        print(f"  Site:              {(r.get('site') or '').upper()}")
        print(f"  Firewall Name:     {r.get('firewall_name', '')}")
        print(f"  Rule Name:         {r.get('rule_name', '')}")
        print(f"  Source Zone:       {_fmt_list(r.get('src_zones'))}")
        print(f"  Source IP:         {_fmt_ips(r.get('src_ip'))}")
        print(f"  Destination Zone:  {_fmt_list(r.get('dst_zones'))}")
        print(f"  Destination IP:    {_fmt_ips(r.get('dst_ip'))}")
        print(f"  Port:              {_fmt_ports(r.get('ports'))}")
        print(f"  Protocol:          {_fmt_list(r.get('protocols'))}\n")

    print(f"{FG_CYAN}=========================== End ==========================={RESET}\n")


# -------------------------- Collision report (PRINT) ------------------------ #

from typing import List, Dict, Any, Iterable, Tuple

def show_collision_report(existing_rules: List[Dict[str, Any]],
                          new_rules: List[Dict[str, Any]]) -> None:
    """
    Calls checker.find_collisions to compute collisions and prints the report.
    The collision banner now shows the correct site(s) where collisions occurred.
    If multiple sites collide, they are printed comma-separated (e.g., DC1, DC2).
    """
    if find_collisions is None:
        print(f"{FG_RED}Collision engine not available.{RESET}")
        return

    def _site_of(rule: Dict[str, Any]) -> str:
        # Normalize site safely
        return (rule.get("site") or "").strip().upper() or "N/A"

    def _unique_preserve(seq: Iterable[str]) -> List[str]:
        # Keep first-seen order while deduplicating
        seen = set()
        out: List[str] = []
        for x in seq:
            if x not in seen:
                seen.add(x)
                out.append(x)
        return out

    # Compute collisions
    collisions: List[Tuple[Dict[str, Any], Dict[str, Any]]] = find_collisions(existing_rules, new_rules)

    print(f"\n{FG_CYAN}==================== Report ====================={RESET}\n")

    if not collisions:
        # Reflect the sites the user actually checked (from new_rules)
        tried_sites = _unique_preserve(_site_of(nr) for nr in (new_rules or []))
        tried_sites = [s for s in tried_sites if s != "N/A"]
        tried_sites_str = ", ".join(tried_sites) if tried_sites else "N/A"
        print(f"{FG_GREEN}No Collision! The given rule does not exist in {tried_sites_str}.{RESET}")
        print(f"\n{FG_CYAN}===================== End ======================{RESET}\n")
        return

    # Build the site list from the actual collisions.
    # Prefer the new rule's site (nr), but also include existing rule's site (er) if different.
    sites_from_nr = [_site_of(nr) for (nr, _er) in collisions]
    sites_from_er = [_site_of(er) for (_nr, er) in collisions]
    sites_combined = _unique_preserve(sites_from_nr + sites_from_er)
    sites_combined = [s for s in sites_combined if s != "N/A"]

    sites_str = ", ".join(sites_combined) if sites_combined else "N/A"
    print(f"{FG_RED}Collision detected! The given rule already exists in {sites_str}.{RESET}")

    # Detailed section(s)
    for idx, (nr, er) in enumerate(collisions, start=1):
        existing_site = _site_of(er)
        new_site = _site_of(nr)

        print(f"\n{FG_CYAN}# Collision: {idx}{RESET}")

        # Existing Rule
        print(f"{FG_LIGHT_YELLOW}Existing Rule:{RESET}")
        print(f"  Site:              {existing_site}")
        print(f"  Firewall Name:     {er.get('firewall_name', '')}")
        print(f"  Rule Name:         {er.get('rule_name', '')}")
        print(f"  Source Zone:       {_fmt_list(er.get('src_zones'))}")
        print(f"  Source IP:         {_fmt_ips(er.get('src_ip'))}")
        print(f"  Destination Zone:  {_fmt_list(er.get('dst_zones'))}")
        print(f"  Destination IP:    {_fmt_ips(er.get('dst_ip'))}")
        print(f"  Port:              {_fmt_ports(er.get('ports'))}")
        print(f"  Protocol:          {_fmt_list(er.get('protocols'))}\n")

        # New Rule
        print(f"{FG_LIGHT_YELLOW}New Rule:{RESET}")
        print(f"  Site:              {new_site}")
        print(f"  Source Zone:       {_fmt_list(nr.get('src_zones'))}")
        print(f"  Source IP:         {_fmt_ips(nr.get('src_ip'))}")
        print(f"  Destination Zone:  {_fmt_list(nr.get('dst_zones'))}")
        print(f"  Destination IP:    {_fmt_ips(nr.get('dst_ip'))}")
        print(f"  Port:              {_fmt_ports(nr.get('ports'))}")
        print(f"  Protocol:          {_fmt_list(nr.get('protocols'))}")

    print(f"\n{FG_CYAN}=========================== End ==========================={RESET}\n")