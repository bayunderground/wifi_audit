from pathlib import Path
from audit.models import AccessPoint, AuditTarget, AuditState, APState
from audit.report.report import generate_report

def test_generate_report_cracked(tmp_path):
    ap = AccessPoint("TestNet", "aa:bb:cc:dd:ee:ff", 6, -40, "WPA2-PSK")
    target = AuditTarget(ap=ap, state=APState.CRACKED, password="12345678")
    state = AuditState(targets={"aa:bb:cc:dd:ee:ff": target})
    path = generate_report(state, tmp_path)
    assert path.exists()
    content = path.read_text()
    assert "TestNet" in content
    assert "aa:bb:cc:dd:ee:ff" in content
    assert "12345678" in content

def test_generate_report_no_handshake(tmp_path):
    ap = AccessPoint("OpenNet", "11:22:33:44:55:66", 11, -70, "WPA2-PSK")
    target = AuditTarget(ap=ap, state=APState.DISCOVERED)
    state = AuditState(targets={"11:22:33:44:55:66": target})
    path = generate_report(state, tmp_path)
    content = path.read_text()
    assert "no handshake" in content

def test_generate_report_not_found(tmp_path):
    ap = AccessPoint("CrackNet", "aa:bb:cc:dd:ee:ff", 1, -50, "WPA2-PSK")
    target = AuditTarget(ap=ap, state=APState.READY_TO_CRACK, handshake_path=Path("out.pcapng"))
    state = AuditState(targets={"aa:bb:cc:dd:ee:ff": target})
    path = generate_report(state, tmp_path)
    content = path.read_text()
    assert "not found" in content

def test_generate_report_empty(tmp_path):
    state = AuditState()
    path = generate_report(state, tmp_path)
    assert path.exists()
    assert path.read_text() == ""
