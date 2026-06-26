from __future__ import annotations
import logging
from pathlib import Path

def setup_logging(cfg: object, logs_path: str = "logs") -> None:
    Path(logs_path).mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=getattr(logging, cfg.level),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(f"{logs_path}/audit.log"),
        ],
    )

def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
