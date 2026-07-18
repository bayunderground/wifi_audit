from __future__ import annotations
import re
import subprocess as _subprocess
from ..logging import get_logger

log = get_logger(__name__)

class HashcatError(Exception):
    pass

def crack(hash_file: str, mask: str, custom_charsets: dict[int, str] | None = None, potfile: str | None = None) -> str | None:
    log.info("Cracking %s with mask %s", hash_file, mask)
    cmd = ["hashcat", "-m", "22000"]
    if potfile is not None:
        cmd.extend(["--potfile-path", potfile])
    if custom_charsets:
        cmd.extend(["-a", "3"])
        for idx, charset in sorted(custom_charsets.items()):
            cmd.extend([f"-{idx}", charset])
    cmd.extend([hash_file, mask])
    log.debug("Command: %s", " ".join(cmd))
    result = _subprocess.run(cmd, text=True, capture_output=True, timeout=300)
    output = result.stdout + result.stderr
    log.debug("Exit code: %d", result.returncode)
    if result.stdout:
        log.debug("Stdout tail: %s", result.stdout[-500:])
    if result.stderr:
        log.debug("Stderr tail: %s", result.stderr[-500:])
    if result.returncode > 1:
        raise HashcatError(f"hashcat failed (rc={result.returncode}): {result.stderr.strip() or result.stdout.strip()}")
    match = re.search(r":([^:\s]+)\s*$", output, re.MULTILINE)
    if match:
        password = match.group(1)
        if "://" in password or password.startswith("//"):
            log.info("Ignoring URL in output: %s", password)
        else:
            log.info("Password found: %s", password)
            return password
    log.info("Password not found")
    return None
