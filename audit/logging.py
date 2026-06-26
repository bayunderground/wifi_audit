import logging
from pathlib import Path
def setup_logging(cfg):
 Path('logs').mkdir(exist_ok=True)
 logging.basicConfig(level=getattr(logging,cfg.level),format='%(asctime)s %(levelname)s %(name)s %(message)s',handlers=[logging.StreamHandler(),logging.FileHandler('logs/audit.log')])
def get_logger(name): return logging.getLogger(name)
