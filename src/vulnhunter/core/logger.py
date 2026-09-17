"""Logging configuration for VulnHunter."""

import logging
from rich.logging import RichHandler

def setup_logger(verbosity: int = 0) -> logging.Logger:
    """Configure and return logger with appropriate verbosity."""
    logger = logging.getLogger("vulnhunter")
    
    if verbosity == 0:
        level = logging.WARNING
    elif verbosity == 1:
        level = logging.INFO
    else:
        level = logging.DEBUG

    logger.setLevel(level)

    # Avoid duplicate handlers if setup is called multiple times
    if not logger.handlers:
        handler = RichHandler(
            show_time=False,
            show_path=False,
            markup=True,
            rich_tracebacks=True,
        )
        handler.setLevel(level)
        formatter = logging.Formatter("%(message)s")
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger

logger = logging.getLogger("vulnhunter")
