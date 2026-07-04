from unittest.mock import patch, call
from audit.capture.monitor import MonitorManager, MonitorError

@patch("audit.capture.monitor.run")
def test_enable(mock_run):
    mock_run.side_effect = ["", "", ""]
    m = MonitorManager("wlan1")
    m.enable()
    assert m.monitor_iface == "wlan1"
    assert mock_run.call_count == 3
    mock_run.assert_any_call(["ip", "link", "set", "wlan1", "down"])
    mock_run.assert_any_call(["iw", "dev", "wlan1", "set", "type", "monitor"])
    mock_run.assert_any_call(["ip", "link", "set", "wlan1", "up"])

@patch("audit.capture.monitor.run")
def test_enable_sets_monitor_iface_to_interface(mock_run):
    mock_run.side_effect = ["", "", ""]
    m = MonitorManager("wlan1")
    m.enable()
    assert m.monitor_iface == "wlan1"

@patch("audit.capture.monitor.run")
def test_disable(mock_run):
    mock_run.side_effect = ["", "", "", "", "", ""]
    m = MonitorManager("wlan1")
    m.enable()
    m.disable()
    assert m._monitor_iface is None
    mock_run.assert_any_call(["ip", "link", "set", "wlan1", "down"])
    mock_run.assert_any_call(["iw", "dev", "wlan1", "set", "type", "managed"])
    mock_run.assert_any_call(["ip", "link", "set", "wlan1", "up"])

@patch("audit.capture.monitor.run")
def test_set_channel(mock_run):
    mock_run.side_effect = ["", "", "", ""]
    m = MonitorManager("wlan1")
    m.enable()
    m.set_channel(6)
    mock_run.assert_any_call(["iw", "dev", "wlan1", "set", "channel", "6"])

def test_monitor_iface_before_enable():
    m = MonitorManager("wlan1")
    try:
        m.monitor_iface
        assert False, "Should have raised"
    except MonitorError:
        pass
