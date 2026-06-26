from __future__ import annotations
import re
from ..logging import get_logger
from ..util.subprocess import run, CommandError

log = get_logger(__name__)

class MonitorError(Exception):
    pass

class MonitorManager:
    def __init__(self, interface: str):
        self.interface = interface
        self._monitor_iface: str | None = None

    @property
    def monitor_iface(self) -> str:
        if self._monitor_iface is None:
            raise MonitorError("Monitor mode not enabled")
        return self._monitor_iface

    def enable(self):
        log.info("Enabling monitor mode on %s", self.interface)
        run(["ip", "link", "set", self.interface, "down"])
        run(["iw", "dev", self.interface, "set", "type", "monitor"])
        run(["airmon-ng", "check", "kill"])
        run(["ip", "link", "set", self.interface, "up"])
        output = run(["airmon-ng", "start", self.interface])
        self._monitor_iface = self._parse_monitor_iface(output)
        log.info("Monitor interface: %s", self._monitor_iface)

    def disable(self):
        log.info("Disabling monitor mode on %s", self.monitor_iface)
        run(["airmon-ng", "stop", self.monitor_iface])
        run(["ip", "link", "set", self.interface, "up"])
        self._monitor_iface = None

    def set_channel(self, channel: int):
        log.info("Setting channel %d on %s", channel, self.monitor_iface)
        run(["iw", "dev", self.monitor_iface, "set", "channel", str(channel)])

    def _parse_monitor_iface(self, output: str) -> str:
        match = re.search(r"on \[\w+\](\w+)", output)
        if match:
            return match.group(1)
        return self.interface + "mon"
