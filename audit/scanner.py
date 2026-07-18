
from __future__ import annotations
import re
from collections import defaultdict
from dataclasses import dataclass
from typing import Iterable
from .models import AccessPoint
from .util.subprocess import run

@dataclass(slots=True)
class ScanResult:
    access_points:list[AccessPoint]
    skipped_bssids: set[str] | None = None

def run_iw_scan(interface: str) -> str:
    return run(["iw", "dev", interface, "scan"])

def parse_scan(text:str)->list[AccessPoint]:
    aps=[]
    cur=None
    for line in text.splitlines():
        s=line.strip()
        if s.startswith("BSS ") and re.match(r"BSS [0-9a-f]{2}:", s):
            if cur: aps.append(AccessPoint(**cur))
            cur={"essid":"","bssid":s.split()[1].split("(")[0],
                 "channel":0,"signal":-100,"encryption":"OPEN"}
        elif cur is None:
            continue
        elif s.startswith("SSID:"):
            cur["essid"]=s[5:].strip()
        elif s.startswith("signal:"):
            cur["signal"]=int(float(s.split()[1]))
        elif "DS Parameter set: channel" in s:
            cur["channel"]=int(s.rsplit(" ",1)[1])
        elif s.startswith("RSN:"):
            cur["encryption"]="WPA2-PSK"
    if cur: aps.append(AccessPoint(**cur))
    return aps

def filter_access_points(aps: Iterable[AccessPoint], whitelist: list[str], blacklist: list[str]) -> list[AccessPoint]:
    allowed = [re.compile(w, re.IGNORECASE) for w in whitelist]
    blocked = [re.compile(b, re.IGNORECASE) for b in blacklist]
    return [ap for ap in aps if any(w.match(ap.essid) for w in allowed) and not any(b.match(ap.essid) for b in blocked)]

def scan(interface: str, whitelist: list[str], blacklist: list[str]) -> ScanResult:
    raw=run_iw_scan(interface)
    aps=parse_scan(raw)
    return ScanResult(filter_access_points(aps,whitelist,blacklist))

def deduplicate_5g_variants(aps: list[AccessPoint]) -> tuple[list[AccessPoint], set[str]]:
    """Group networks by base name. When both 2.4GHz and _5G variants exist, keep only _5G.
    Returns (kept_aps, skipped_bssids)."""
    def base_name(essid: str) -> str:
        return essid.removesuffix("_5G")

    groups: dict[str, list[AccessPoint]] = defaultdict(list)
    for ap in aps:
        groups[base_name(ap.essid)].append(ap)

    kept: list[AccessPoint] = []
    skipped: set[str] = set()

    for name, group in groups.items():
        if len(group) == 1:
            kept.append(group[0])
            continue

        has_5g = any(ap.essid.endswith("_5G") for ap in group)
        if has_5g:
            for ap in group:
                if ap.essid.endswith("_5G"):
                    kept.append(ap)
                else:
                    skipped.add(ap.bssid)
        else:
            best = max(group, key=lambda ap: ap.signal)
            kept.append(best)
            for ap in group:
                if ap.bssid != best.bssid:
                    skipped.add(ap.bssid)

    return kept, skipped
