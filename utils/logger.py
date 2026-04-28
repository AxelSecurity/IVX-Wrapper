import logging
import sys
import json
from datetime import datetime

class JSONFormatter(logging.Formatter):
    def format(self, record):
        log_record = {
            "timestamp": datetime.fromtimestamp(record.created).isoformat(),
            "level": record.levelname,
            "message": record.getMessage(),
        }
        if hasattr(record, "extra_info"):
            log_record.update(record.extra_info)
        return json.dumps(log_record)

def setup_logger():
    logger = logging.getLogger("ivx_wrapper")
    logger.setLevel(logging.INFO)
    
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JSONFormatter())
    
    if not logger.handlers:
        logger.addHandler(handler)
    
    return logger

logger = setup_logger()
    
