from pathlib import Path
from audit.config import load_config

def test_load_config(tmp_path):
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text("""
interfaces:
  management: wlan0
  monitor: wlan1
filters:
  whitelist: "^TP-Link_.*"
  blacklist: "^TP-Link_.*SN$"
capture:
  handshake_timeout: 90
  revisit_interval: 300
  verify: true
paths:
  captures: captures
  hashes: hashes
  reports: reports
  logs: logs
  state: state/state.json
cracking:
  enabled: false
  hashcat: hashcat
  mask: "?d?d?d?d?d?d?d?d"
logging:
  level: INFO
""")
    cfg = load_config(cfg_file)
    assert cfg.interfaces.management == "wlan0"
    assert cfg.interfaces.monitor == "wlan1"
    assert cfg.capture.revisit_interval == 300
    assert cfg.cracking.enabled is False
    assert cfg.logging.level == "INFO"
