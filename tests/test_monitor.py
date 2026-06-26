from unittest.mock import patch, call
from audit.capture.monitor import MonitorManager, MonitorError

AIRMON_OUTPUT_ENABLED = """\
  (mac80211 monitor mode vif enabled for [phy0]wlan1 on [phy0]wlan1mon)
"""

AIRMON_OUTPUT_ALREADY = """\
  (mac80211 monitor mode already enabled for [phy0]wlan1)
"""

AIRMON_STOP_OUTPUT = """\
  (mac80211 monitor mode vif disabled for [phy0]wlan1mon)
"""

@patch("audit.capture.monitor.run")
def test_enable(mock_run):
    mock_run.side_effect = ["", "", "", "", AIRMON_OUTPUT_ENABLED]
    m = MonitorManager("wlan1")
    m.enable()
    assert m.monitor_iface == "wlan1mon"
    assert mock_run.call_count == 5
    mock_run.assert_any_call(["ip", "link", "set", "wlan1", "down"])
    mock_run.assert_any_call(["iw", "dev", "wlan1", "set", "type", "monitor"])
    mock_run.assert_any_call(["airmon-ng", "check", "kill"])
    mock_run.assert_any_call(["ip", "link", "set", "wlan1", "up"])
    mock_run.assert_any_call(["airmon-ng", "start", "wlan1"])

@patch("audit.capture.monitor.run")
def test_enable_already_enabled(mock_run):
    mock_run.side_effect = ["", "", "", "", AIRMON_OUTPUT_ALREADY]
    m = MonitorManager("wlan1")
    m.enable()
    assert m.monitor_iface == "wlan1mon"

@patch("audit.capture.monitor.run")
def test_enable_parse_fallback(mock_run):
    mock_run.side_effect = ["", "", "", "", "some unexpected output"]
    m = MonitorManager("wlan1")
    m.enable()
    assert m.monitor_iface == "wlan1mon"

@patch("audit.capture.monitor.run")
def test_disable(mock_run):
    mock_run.side_effect = ["", "", "", "", AIRMON_OUTPUT_ENABLED, AIRMON_STOP_OUTPUT, ""]
    m = MonitorManager("wlan1")
    m.enable()
    m.disable()
    assert m._monitor_iface is None
    mock_run.assert_any_call(["airmon-ng", "stop", "wlan1mon"])
    mock_run.assert_any_call(["ip", "link", "set", "wlan1", "up"])

@patch("audit.capture.monitor.run")
def test_set_channel(mock_run):
    mock_run.side_effect = ["", "", "", "", AIRMON_OUTPUT_ENABLED, ""]
    m = MonitorManager("wlan1")
    m.enable()
    m.set_channel(6)
    mock_run.assert_any_call(["iw", "dev", "wlan1mon", "set", "channel", "6"])

def test_monitor_iface_before_enable():
    m = MonitorManager("wlan1")
    try:
        m.monitor_iface
        assert False, "Should have raised"
    except MonitorError:
        pass
