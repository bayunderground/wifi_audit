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
