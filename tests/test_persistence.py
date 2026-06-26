from pathlib import Path
from audit.persistence import save_raw, load_raw
from audit.models import AccessPoint, AuditTarget, APState

def test_save_and_load_dict():
    p = Path("state/test.json")
    save_raw(p, {"a": 1})
    assert load_raw(p) == {"a": 1}

def test_save_and_load_dataclass(tmp_path):
    p = tmp_path / "state.json"
    ap = AccessPoint(essid="TestNet", bssid="aa:bb:cc:dd:ee:ff", channel=6, signal=-40, encryption="WPA2-PSK")
    target = AuditTarget(ap=ap, state=APState.DISCOVERED, attempts=3)
    save_raw(p, {"aa:bb:cc:dd:ee:ff": target})
    data = load_raw(p)
    assert "aa:bb:cc:dd:ee:ff" in data
    entry = data["aa:bb:cc:dd:ee:ff"]
    assert entry["ap"]["essid"] == "TestNet"
    assert entry["state"] == "DISCOVERED"
    assert entry["attempts"] == 3

def test_load_missing_file(tmp_path):
    p = tmp_path / "missing.json"
    assert load_raw(p) == {}
