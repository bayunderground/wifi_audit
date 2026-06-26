from __future__ import annotations
import re
from ..logging import get_logger
from ..util.subprocess import run, CommandError

log = get_logger(__name__)

class HashcatError(Exception):
    pass

def crack(hash_file: str, mask: str) -> str | None:
    log.info("Cracking %s with mask %s", hash_file, mask)
    try:
        output = run(["hashcat", "-m", "22000", hash_file, mask])
    except CommandError as e:
        raise HashcatError(f"hashcat failed: {e.stderr}") from e
    match = re.search(r":([^:\s]+)\s*$", output, re.MULTILINE)
    if match:
        password = match.group(1)
        log.info("Password found: %s", password)
        return password
    log.info("Password not found")
    return None
