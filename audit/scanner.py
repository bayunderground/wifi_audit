
from __future__ import annotations
import re, subprocess
from dataclasses import dataclass
from typing import Iterable
from .models import AccessPoint

@dataclass(slots=True)
class ScanResult:
    access_points:list[AccessPoint]

def run_iw_scan(interface:str)->str:
    return subprocess.check_output(
        ["iw","dev",interface,"scan"],
        text=True,
        stderr=subprocess.STDOUT,
    )

def parse_scan(text:str)->list[AccessPoint]:
    aps=[]
    cur=None
    for line in text.splitlines():
        s=line.strip()
        if s.startswith("BSS "):
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

def filter_access_points(aps:Iterable[AccessPoint], whitelist:str, blacklist:str)->list[AccessPoint]:
    w=re.compile(whitelist)
    b=re.compile(blacklist)
    return [ap for ap in aps if w.match(ap.essid) and not b.match(ap.essid)]

def scan(interface:str, whitelist:str, blacklist:str)->ScanResult:
    raw=run_iw_scan(interface)
    aps=parse_scan(raw)
    return ScanResult(filter_access_points(aps,whitelist,blacklist))
