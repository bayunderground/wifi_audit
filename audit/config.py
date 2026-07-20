from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import yaml

@dataclass
class Interfaces:
    management: str
    monitor: str

@dataclass
class Filters:
    whitelist: list[str]
    blacklist: list[str]

@dataclass
class Capture:
    handshake_timeout: int
    revisit_interval: int
    verify: bool
    initial_scan_period: int = 180
    rescan_interval: int = 300

@dataclass
class Paths:
    captures: str
    hashes: str
    reports: str
    logs: str
    state: str

@dataclass
class Cracking:
    hashcat: str
    mask: str

@dataclass
class Logging:
    level: str

@dataclass
class Config:
    interfaces: Interfaces
    filters: Filters
    capture: Capture
    paths: Paths
    cracking: Cracking
    logging: Logging

def load_config(path: str | Path) -> Config:
    d = yaml.safe_load(open(path))
    return Config(
        Interfaces(**d["interfaces"]),
        Filters(**d["filters"]),
        Capture(**d["capture"]),
        Paths(**d["paths"]),
        Cracking(**d["cracking"]),
        Logging(**d["logging"]),
    )
