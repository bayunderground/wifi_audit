import pytest
from unittest.mock import patch
from audit.scanner import parse_scan, filter_access_points, run_iw_scan, scan
from audit.util.subprocess import CommandError

SAMPLE_SCAN = """BSS aa:bb:cc:dd:ee:ff(on wlan1)
    signal: -44.00 dBm
    DS Parameter set: channel 6
    SSID: TP-Link_Main
    RSN:
BSS 11:22:33:44:55:66(on wlan1)
    signal: -70.00 dBm
    DS Parameter set: channel 11
    SSID: TP-Link_TestSN
    RSN:
"""

def test_parse_and_filter():
    aps = parse_scan(SAMPLE_SCAN)
    assert len(aps) == 2
    assert aps[0].essid == "TP-Link_Main"
    assert aps[0].encryption == "WPA2-PSK"
    f = filter_access_points(aps, r"^TP-Link_.*", [r"^TP-Link_.*SN$"])
    assert len(f) == 1
    assert f[0].essid == "TP-Link_Main"

@patch("audit.scanner.run", return_value=SAMPLE_SCAN)
def test_run_iw_scan(mock_run):
    result = run_iw_scan("wlan1")
    assert "TP-Link_Main" in result
    mock_run.assert_called_once_with(["iw", "dev", "wlan1", "scan"])

@patch("audit.scanner.run", side_effect=CommandError(["iw"], 1, "Device or resource busy"))
def test_run_iw_scan_error(mock_run):
    with pytest.raises(CommandError):
        run_iw_scan("wlan1")

def test_filter_multiple_blacklist():
    aps = parse_scan(SAMPLE_SCAN)
    f = filter_access_points(aps, r"^TP-Link_.*", [r".*SN$", r".*_Main"])
    assert len(f) == 0

@patch("audit.scanner.run_iw_scan", return_value=SAMPLE_SCAN)
def test_scan(mock_iw):
    result = scan("wlan1", r"^TP-Link_.*", [r"^TP-Link_.*SN$"])
    assert len(result.access_points) == 1
    assert result.access_points[0].essid == "TP-Link_Main"
