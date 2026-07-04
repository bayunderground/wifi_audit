from __future__ import annotations
import tempfile
from pathlib import Path
from ..logging import get_logger
from ..util.subprocess import run, Popen

log = get_logger(__name__)

def _channel_arg(channel: int) -> str:
    return f"{channel}a" if channel <= 14 else f"{channel}b"

def _compile_bpf(bssid: str) -> str:
    hex_bssid = bssid.replace(":", "")
    output = run(["hcxdumptool", f"--bpfc=wlan addr3 {hex_bssid}"])
    return output.strip()

class CaptureSession:
    def __init__(self, monitor_iface: str, bssid: str, channel: int, capture_path: Path):
        self.monitor_iface = monitor_iface
        self.bssid = bssid
        self.channel = channel
        self.capture_path = Path(capture_path)
        self._backend: Popen | None = None
        self._bpf_path: Path | None = None

    def start(self):
        log.info("Capturing %s on channel %d", self.bssid, self.channel)
        bpf_code = _compile_bpf(self.bssid)
        bpf_file = tempfile.NamedTemporaryFile(
            mode="w", suffix=".bpf", delete=False,
        )
        bpf_file.write(bpf_code + "\n")
        bpf_file.close()
        self._bpf_path = Path(bpf_file.name)

        self._backend = Popen([
            "hcxdumptool",
            "-i", self.monitor_iface,
            "-c", _channel_arg(self.channel),
            "--bpf", str(self._bpf_path),
            "-w", str(self.capture_path),
        ])
        self._backend.start()

    def stop(self):
        if self._backend is not None:
            log.info("Stopping capture for %s", self.bssid)
            self._backend.stop()
            self._backend = None
        if self._bpf_path is not None:
            self._bpf_path.unlink(missing_ok=True)
            self._bpf_path = None

    def handshake_detected(self) -> bool:
        if not self.capture_path.exists() or self.capture_path.stat().st_size == 0:
            return False
        try:
            output = run(["hcxpcapngtool", "--all", str(self.capture_path)])
            for line in output.splitlines():
                for key in ("PMKID total", "EAPOL pairs (useful)"):
                    idx = line.find(key)
                    if idx != -1:
                        val = line.split(":")[-1].strip()
                        try:
                            if int(val) > 0:
                                return True
                        except ValueError:
                            pass
            return False
        except (OSError, ValueError):
            return False
