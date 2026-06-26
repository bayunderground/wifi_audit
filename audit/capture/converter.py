from __future__ import annotations
from ..logging import get_logger
from ..util.subprocess import run, CommandError

log = get_logger(__name__)

class ConversionError(Exception):
    pass

def convert_to_22000(capture_file: str, output_file: str):
    log.info("Converting %s to %s", capture_file, output_file)
    try:
        run(["hcxpcapngtool", "-o", output_file, capture_file])
    except CommandError as e:
        raise ConversionError(f"Conversion failed: {e.stderr}") from e
