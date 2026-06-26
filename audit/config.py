from dataclasses import dataclass
import yaml
@dataclass
class Interfaces: management:str; monitor:str
@dataclass
class Filters: whitelist:str; blacklist:str
@dataclass
class Capture: handshake_timeout:int; revisit_interval:int; verify:bool
@dataclass
class Paths: captures:str; hashes:str; reports:str; logs:str; state:str
@dataclass
class Cracking: enabled:bool; hashcat:str; mask:str
@dataclass
class Logging: level:str
@dataclass
class Config: interfaces:Interfaces; filters:Filters; capture:Capture; paths:Paths; cracking:Cracking; logging:Logging
def load_config(path):
 d=yaml.safe_load(open(path))
 return Config(Interfaces(**d['interfaces']),Filters(**d['filters']),Capture(**d['capture']),Paths(**d['paths']),Cracking(**d['cracking']),Logging(**d['logging']))
