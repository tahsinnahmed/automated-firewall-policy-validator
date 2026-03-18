# module/checker.py

from __future__ import annotations

from ipaddress import ip_network
from typing import List, Dict, Any, Tuple


def _zones_overlap(a: List[str], b: List[str]) -> bool:
    a = [x.strip().lower() for x in (a or [])]
    b = [x.strip().lower() for x in (b or [])]
    if "any" in a or "any" in b:
        return True
    return bool(set(a) & set(b))


def _cidr_list_overlap(a: List[str], b: List[str]) -> bool:
    nets_a, nets_b = [], []
    for x in a or []:
        try:
            nets_a.append(ip_network(x, strict=False))
        except Exception:
            pass
    for y in b or []:
        try:
            nets_b.append(ip_network(y, strict=False))
        except Exception:
            pass
    for n1 in nets_a:
        for n2 in nets_b:
            if n1.overlaps(n2):
                return True
    return False


def _protocols_overlap(a: List[str], b: List[str]) -> bool:
    a = [p.strip().lower() for p in a or []]
    b = [p.strip().lower() for p in b or []]
    return bool(set(a) & set(b))


def _ports_overlap(a: List[Dict[str, int]], b: List[Dict[str, int]]) -> bool:
    """
    Each entry: {"from": int, "to": int}
    Overlap if any range intersects: max(start1, start2) <= min(end1, end2)
    """
    if not a or not b:
        return False

    def _as_range(d: Dict[str, int]) -> tuple | None:
        try:
            start = int(d.get("from"))
            end = int(d.get("to"))
            if start > end:
                start, end = end, start
            return (start, end)
        except Exception:
            return None

    a_ranges = [_as_range(r) for r in a]
    b_ranges = [_as_range(r) for r in b]
    a_ranges = [r for r in a_ranges if r is not None]
    b_ranges = [r for r in b_ranges if r is not None]

    for s1, e1 in a_ranges:
        for s2, e2 in b_ranges:
            if max(s1, s2) <= min(e1, e2):
                return True
    return False

# module/checker.py

def _collides(nr: Dict[str, Any], er: Dict[str, Any]) -> bool:
    # 1) Site must be the same (normalized upstream to DC1/DC2/DC3/HQ)
    nr_site = (nr.get("site") or "").strip().upper()
    er_site = (er.get("site") or "").strip().upper()
    if not nr_site or not er_site or nr_site != er_site:
        return False

    # 2) Source IP overlap
    if not _cidr_list_overlap(nr.get("src_ip"), er.get("src_ip")):
        return False

    # 3) Destination IP overlap
    if not _cidr_list_overlap(nr.get("dst_ip"), er.get("dst_ip")):
        return False

    # 4) Port overlap
    if not _ports_overlap(nr.get("ports"), er.get("ports")):
        return False

    return True

# def _collides(nr: Dict[str, Any], er: Dict[str, Any]) -> bool:
#     """
#     True if new rule (nr) collides with existing rule (er) under the SAME SITE and:
#       zones, src_ip, dst_ip, protocols, ports
#     """
#     nr_site = (nr.get("site") or "").upper()
#     er_site = (er.get("site") or "").upper()
#     if not nr_site or not er_site or nr_site != er_site:
#         return False
#
#     if not _zones_overlap(nr.get("src_zones"), er.get("src_zones")):
#         return False
#     if not _zones_overlap(nr.get("dst_zones"), er.get("dst_zones")):
#         return False
#     if not _cidr_list_overlap(nr.get("src_ip"), er.get("src_ip")):
#         return False
#     if not _cidr_list_overlap(nr.get("dst_ip"), er.get("dst_ip")):
#         return False
#     if not _protocols_overlap(nr.get("protocols"), er.get("protocols")):
#         return False
#     if not _ports_overlap(nr.get("ports"), er.get("ports")):
#         return False
#     return True


def find_collisions(existing_rules: List[Dict[str, Any]],
                    new_rules: List[Dict[str, Any]]) -> List[Tuple[Dict[str, Any], Dict[str, Any]]]:
    collisions: List[Tuple[Dict[str, Any], Dict[str, Any]]] = []
    for nr in new_rules or []:
        for er in existing_rules or []:
            if _collides(nr, er):
                collisions.append((nr, er))
    return collisions