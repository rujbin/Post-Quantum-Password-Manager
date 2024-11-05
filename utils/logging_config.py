# src/utils/logging_config.py

import logging
from logging.handlers import RotatingFileHandler
import os

def setup_logging(log_file: str = "logs/password_manager.log", level: str = "INFO"):
    """
    Konfiguriert das Logging für die Anwendung.

    :param log_file: Pfad zur Log-Datei
    :param level: Logging-Level
    """
    try:
        os.makedirs(os.path.dirname(log_file), exist_ok=True)

        numeric_level = getattr(logging, level.upper(), None)
        if not isinstance(numeric_level, int):
            numeric_level = logging.INFO

        handler = RotatingFileHandler(
            log_file,
            maxBytes=5 * 1024 * 1024,  # 5 MB
            backupCount=5
        )

        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)

        logging.basicConfig(
            level=numeric_level,
            handlers=[handler],
        )

        logging.getLogger().addHandler(logging.StreamHandler())
        logging.info("Logging erfolgreich konfiguriert")

    except Exception as e:
        print(f"Fehler bei der Logging-Konfiguration: {e}")
        raise
