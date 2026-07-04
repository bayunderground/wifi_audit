from __future__ import annotations
from ..logging import get_logger
from ..util.subprocess import run, CommandError

log = get_logger(__name__)

class VerificationError(Exception):
    pass

def verify_capture(capture_file: str) -> bool:
    log.info("Verifying capture: %s", capture_file)
    try:
        output = run(["hcxpcapngtool", "--all", capture_file])
    except CommandError as e:
        raise VerificationError(f"hcxpcapngtool failed: {e.stderr}") from e
    for line in output.splitlines():
        for key in ("PMKID total", "EAPOL pairs (useful)"):
            idx = line.find(key)
            if idx != -1:
                val = line.split(":")[-1].strip()
                try:
                    if int(val) > 0:
                        log.info("Valid hash found in %s", capture_file)
                        return True
                except ValueError:
                    pass
    log.info("No valid hash in %s", capture_file)
    return False
