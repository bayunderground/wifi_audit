from dataclasses import dataclass,field
from enum import Enum,auto
from pathlib import Path
from datetime import datetime
class APState(Enum):
    DISCOVERED=auto();WAITING_FOR_CLIENT=auto();CAPTURING=auto();VERIFYING=auto();READY_TO_CRACK=auto();CRACKED=auto();FAILED=auto()
@dataclass(slots=True)
class AccessPoint:
    essid:str;bssid:str;channel:int;signal:int;encryption:str
@dataclass(slots=True)
class AuditTarget:
    ap:AccessPoint;state:APState;attempts:int=0;last_seen:datetime|None=None;last_attempt:datetime|None=None;handshake_path:Path|None=None;hash_path:Path|None=None;password:str|None=None
@dataclass(slots=True)
class AuditState:
    targets:dict[str,AuditTarget]=field(default_factory=dict)
