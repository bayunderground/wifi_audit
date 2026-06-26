from __future__ import annotations
from pathlib import Path
from ..logging import get_logger
from ..util.subprocess import run, Popen

log = get_logger(__name__)

class CaptureSession:
    def __init__(self, monitor_iface: str, bssid: str, channel: int, capture_path: Path):
        self.monitor_iface = monitor_iface
        self.bssid = bssid
        self.channel = channel
        self.capture_path = Path(capture_path)
        self._backend: Popen | None = None

    def start(self):
        log.info("Capturing %s on channel %d", self.bssid, self.channel)
        self._backend = Popen([
            "hcxdumptool",
            "-i", self.monitor_iface,
            "--bssid", self.bssid,
            "--channel", str(self.channel),
            "-w", str(self.capture_path),
        ])
        self._backend.start()

    def stop(self):
        if self._backend is not None:
            log.info("Stopping capture for %s", self.bssid)
            self._backend.stop()
            self._backend = None

    def handshake_detected(self) -> bool:
        if not self.capture_path.exists():
            return False
        try:
            output = run(["hcxpcapngtool", "--all", str(self.capture_path)])
            for line in output.splitlines():
                for key in ("PMKID:", "EAPOL:"):
                    idx = line.find(key)
                    if idx != -1:
                        val = line[idx + len(key):].strip().split()[0]
                        if val != "0":
                            return True
            return False
        except (OSError, ValueError):
            return False
