from audit.config import load_config
from audit.logging import setup_logging,get_logger
from audit.persistence import load_state
cfg=load_config('config/config.yaml')
setup_logging(cfg.logging)
log=get_logger(__name__)
state=load_state(cfg.paths.state)
log.info('Initialized with %d targets',len(state.targets))
