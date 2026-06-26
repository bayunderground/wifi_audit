from __future__ import annotations
import subprocess as _subprocess
from ..logging import get_logger

log = get_logger(__name__)

class CommandError(Exception):
    def __init__(self, cmd: list[str], returncode: int, stderr: str):
        self.cmd = cmd
        self.returncode = returncode
        self.stderr = stderr
        super().__init__(f"Command {cmd!r} failed (rc={returncode}): {stderr}")

def run(cmd: list[str], timeout: int | None = None) -> str:
    log.debug("Running: %s", cmd)
    result = _subprocess.run(
        cmd,
        text=True,
        capture_output=True,
        timeout=timeout,
    )
    if result.returncode != 0:
        raise CommandError(cmd, result.returncode, result.stderr.strip())
    return result.stdout

class Popen:
    def __init__(self, cmd: list[str]):
        self.cmd = cmd
        self._proc: _subprocess.Popen | None = None

    def start(self):
        log.debug("Starting background: %s", self.cmd)
        self._proc = _subprocess.Popen(
            self.cmd,
            text=True,
            stdout=_subprocess.DEVNULL,
            stderr=_subprocess.DEVNULL,
        )

    def stop(self, timeout: int = 10):
        if self._proc is None:
            return
        self._proc.terminate()
        try:
            self._proc.wait(timeout=timeout)
        except _subprocess.TimeoutExpired:
            self._proc.kill()
            self._proc.wait()
        self._proc = None

    @property
    def running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None
