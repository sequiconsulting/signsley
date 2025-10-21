#!/usr/bin/env python3
"""
Logging configuration for Signsley Python Backend
"""

import logging
import sys
from loguru import logger
import os

def setup_logging(level: str = "INFO"):
    """Setup application logging using loguru"""
    
    # Remove default loguru handler
    logger.remove()
    
    # Add console handler with nice formatting
    logger.add(
        sys.stdout,
        level=level,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>",
        colorize=True
    )
    
    # Add file handler if LOG_FILE environment variable is set
    log_file = os.getenv("LOG_FILE")
    if log_file:
        logger.add(
            log_file,
            level=level,
            format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} - {message}",
            rotation="10 MB",
            retention="30 days",
            compression="zip"
        )
    
    # Intercept standard library logging and redirect to loguru
    class InterceptHandler(logging.Handler):
        def emit(self, record):
            # Get corresponding Loguru level if it exists
            try:
                level = logger.level(record.levelname).name
            except ValueError:
                level = record.levelno

            # Find caller from where originated the logged message
            frame, depth = logging.currentframe(), 2
            while frame.f_code.co_filename == logging.__file__:
                frame = frame.f_back
                depth += 1

            logger.opt(depth=depth, exception=record.exc_info).log(
                level, record.getMessage()
            )

    # Replace standard library root logger
    logging.basicConfig(handlers=[InterceptHandler()], level=0)
    
    # Set specific loggers
    for name in ["uvicorn", "uvicorn.access", "fastapi"]:
        logging.getLogger(name).handlers = [InterceptHandler()]
    
    logger.info("Logging configured successfully")
    return logger