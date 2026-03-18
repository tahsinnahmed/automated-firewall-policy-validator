# module/normalization.py

from __future__ import annotations

import json
from pathlib import Path
import xml.etree.ElementTree as ET
from ipaddress import ip_network, collapse_addresses
from typing import List, Dict, Any

# Protocol universe (vendor-agnostic)
ALL_PROTOCOLS = ["tcp", "udp", "icmp", "smtp", "ftp"]

# Site universe (case-insensitive normalization)
ALLOWED_SITES = {"DC1", "DC2", "DC3", "HQ"}

__all__ = [
    "load_and_normalize_existing",
    "load_and_normalize_new",
    "normalize_rule",
]


# -----------------------------
# Small helpers
# -----------------------------
def _first_present(d: Dict[str, Any], keys: List[str], default=None):
    for k in keys:
        if k in d and d[k] not in (None, "", []):
            return d[k]
    return default


def _normalize_site(site_val: str | None, firewall_name: str | None) -> str:
    """
    Normalize site to one of ALLOWED_SITES.
    - Prefer explicit 'site' if provided (case-insensitive).
    - Else derive from first token of firewall_name.
    - Fallback to 'HQ' if unknown/missing.
    """
    if site_val:
        s = str(site_val).strip().upper()
        return s if s in ALLOWED_SITES else "HQ"
    name = (firewall_name or "").strip()
    if name:
        first = name.split()[0].upper()
        return first if first in ALLOWED_SITES else "HQ"
    return "HQ"


# -----------------------------
# Address/ports/protocol helpers
# -----------------------------
def _normalize_any_addresses(addrs: List[str]) -> List[str]:
    out: List[str] = []
    for a in addrs or []:
        s = (a or "").strip().lower()
        if s == "any":
            out.extend(["0.0.0.0/0", "::/0"])
        elif s:
            out.append(s)
    return out


def _to_canonical_cidrs(addrs: List[str], collapse: bool = True) -> List[str]:
    v4_nets, v6_nets, raws = [], [], []
    for a in addrs or []:
        try:
            net = ip_network(a, strict=False)
            if net.version == 4:
                v4_nets.append(net)
            else:
                v6_nets.append(net)
        except Exception:
            raws.append(a.lower())
    if collapse:
        if v4_nets:
            v4_nets = list(collapse_addresses(v4_nets))
        if v6_nets:
            v6_nets = list(collapse_addresses(v6_nets))
    cidrs = [n.with_prefixlen for n in v4_nets] + [n.with_prefixlen for n in v6_nets]
    out, seen = [], set()
    for x in cidrs + raws:
        xl = x.lower()
        if xl not in seen:
            seen.add(xl)
            out.append(xl)
    return out


def _normalize_protocol(proto: str) -> List[str]:
    p = (proto or "any").strip().lower()
    if p in ("any", "ip"):
        return ALL_PROTOCOLS.copy()
    return [p]


def _normalize_ports(ports: List[str]) -> List[Dict[str, int]]:
    out: List[Dict[str, int]] = []
    for p in ports or ["any"]:
        s = (p or "").strip().lower()
        if s in ("any", "*"):
            out.append({"from": 1, "to": 65535})
        elif "-" in s:
            try:
                a, b = s.split("-", 1)
                out.append({"from": int(a), "to": int(b)})
            except Exception:
                continue
        else:
            try:
                n = int(s)
                out.append({"from": n, "to": n})
            except Exception:
                continue

    out.sort(key=lambda r: (r["from"], r["to"]))
    merged: List[Dict[str, int]] = []
    for rng in out:
        if not merged or rng["from"] > merged[-1]["to"] + 1:
            merged.append(dict(rng))
        else:
            merged[-1]["to"] = max(merged[-1]["to"], rng["to"])
    return merged


# -----------------------------
# Parsers (file-based)
# -----------------------------
def parse_cisco_file(path: Path) -> List[Dict[str, Any]]:
    """JSON rules (legacy name retained)."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else [data]
    except Exception as e:
        print(f"Warning: failed to parse JSON {path}: {e}")
        return []


def parse_paloalto_file(path: Path) -> List[Dict[str, Any]]:
    """XML rules (legacy name retained)."""
    rules: List[Dict[str, Any]] = []
    try:
        root = ET.fromstring(path.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"Warning: failed to parse XML {path}: {e}")
        return rules

    def _first_text(parent: ET.Element, tags: List[str]) -> str:
        for t in tags:
            val = parent.findtext(t)
            if val and val.strip():
                return val.strip()
        return ""

    for rule in root.findall("Rule"):
        def get_list(parent_tag: str, child_tag: str) -> List[str]:
            parent = rule.find(parent_tag)
            if parent is None:
                return []
            return [(z.text or "").strip() for z in parent.findall(child_tag) if (z.text or "").strip()]

        name = _first_text(rule, ["RuleName", "Id", "rule_name", "Name"])
        fw_name = _first_text(rule, ["FirewallName", "firewall_name"])
        site_txt = _first_text(rule, ["Site", "site"])  # optional

        rules.append({
            "site": site_txt,  # may be None → normalized later
            "rule_name": name,
            "firewall_name": fw_name,
            "src_zones": get_list("SrcZones", "Zone") or ["any"],
            "dst_zones": get_list("DstZones", "Zone") or ["any"],
            "src": get_list("Src", "Address") or ["any"],
            "dst": get_list("Dst", "Address") or ["any"],
            "protocol": (_first_text(rule, ["Protocol"]) or "any"),
            "ports": get_list("Ports", "Port") or ["any"],
            # action intentionally ignored/unsupported
        })
    return rules


# -----------------------------
# Normalization (vendor-agnostic, site-first)
# -----------------------------
def normalize_rule(rule: Dict[str, Any]) -> Dict[str, Any]:
    """
    Produce a canonical rule. Accepts both legacy and friendly new field names for *new rules*:
      Site, Source Zone(s), Source IP(s), Destination Zone(s), Destination IP(s), Port(s), Protocol
    """
    site_in = _first_present(rule, ["site", "Site"], None)
    firewall_name_in = _first_present(rule, ["firewall_name", "Firewall Name"], "")
    rule_name_in = _first_present(rule, ["rule_name", "Rule Name"], "")

    src_zones_in = _first_present(rule, ["src_zones", "Source Zone", "Source Zones"], ["any"])
    dst_zones_in = _first_present(rule, ["dst_zones", "Destination Zone", "Destination Zones"], ["any"])

    src_in = _first_present(rule, ["src_ip", "src", "Source IP", "Source Ips"], ["any"])
    dst_in = _first_present(rule, ["dst_ip", "dst", "Destination IP", "Destination Ips"], ["any"])

    protocol_in = _first_present(rule, ["protocol", "Protocol"], "any")
    ports_in = _first_present(rule, ["ports", "Port", "Ports"], ["any"])

    # Normalize simple lists
    src_zones = [str(z).strip() for z in (src_zones_in if isinstance(src_zones_in, list) else [src_zones_in])]
    dst_zones = [str(z).strip() for z in (dst_zones_in if isinstance(dst_zones_in, list) else [dst_zones_in])]

    raw_src = src_in if isinstance(src_in, list) else [src_in]
    raw_dst = dst_in if isinstance(dst_in, list) else [dst_in]
    raw_src = [str(a).strip() for a in raw_src if str(a).strip()]
    raw_dst = [str(a).strip() for a in raw_dst if str(a).strip()]

    src_addrs = _normalize_any_addresses(raw_src)
    dst_addrs = _normalize_any_addresses(raw_dst)

    src_canonical = _to_canonical_cidrs(src_addrs, collapse=True)
    dst_canonical = _to_canonical_cidrs(dst_addrs, collapse=True)

    if "protocols" in rule and isinstance(rule["protocols"], list):
        protocols = [str(p).strip().lower() for p in rule["protocols"] if str(p).strip()]
    else:
        protocols = _normalize_protocol(protocol_in)

    ports_list = ports_in if isinstance(ports_in, list) else [ports_in]
    ports = _normalize_ports(ports_list)

    firewall_name_out = str(firewall_name_in).strip()
    site_out = _normalize_site(site_in, firewall_name_out)

    return {
        "site": site_out,  # DC1/DC2/DC3/HQ
        "rule_name": str(rule_name_in).strip(),
        "firewall_name": firewall_name_out,
        "src_zones": [s.lower() for s in src_zones] or ["any"],
        "dst_zones": [s.lower() for s in dst_zones] or ["any"],
        "src_ip": src_canonical,
        "dst_ip": dst_canonical,
        "protocols": protocols,
        "ports": ports
    }


def load_and_normalize_existing(rule_files: List[str | Path]) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    for rf in rule_files:
        p = Path(rf)
        if not p.exists():
            print(f"Warning: rules file not found → {p}")
            continue

        if p.suffix.lower() == ".json":
            for r in parse_cisco_file(p):
                results.append(normalize_rule(r))
        elif p.suffix.lower() == ".xml":
            for r in parse_paloalto_file(p):
                results.append(normalize_rule(r))
        else:
            print(f"Warning: unknown rules file type (skipped) → {p}")
    return results


def load_and_normalize_new(new_rules_file: str | Path) -> List[Dict[str, Any]]:
    p = Path(new_rules_file)
    if not p.exists():
        raise FileNotFoundError(f"New rules file not found → {p}")

    raw = json.loads(p.read_text(encoding="utf-8"))
    if isinstance(raw, dict):
        raw = [raw]

    out: List[Dict[str, Any]] = []
    for r in raw:
        out.append(normalize_rule(r))
    return out