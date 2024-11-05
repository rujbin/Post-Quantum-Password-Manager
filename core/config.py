# src/core/config.py

import os
import logging
import configparser
from typing import Any, Dict, List, Optional


class ConfigError(Exception):
    """Ausnahme für Konfigurationsfehler."""
    pass


class Config:
    """
    Konfigurationsmanager für den Passwort-Manager.

    Verwaltet Anwendungskonfigurationen aus einer INI-Datei.
    """

    DEFAULT_CONFIG = {
        'Security': {
            'iterations': '500000',
            'key_length': '32',
            'encryption_algorithm': 'AES-256-GCM',
            'password_min_length': '12',
            'password_complexity_required': 'True'
        },
        'Database': {
            'path': 'passwords.db',
            'backup_directory': 'backups',
            'max_backups': '5',
            'backup_interval_days': '7'
        },
        'Logging': {
            'level': 'INFO',
            'file': 'logs/password_manager.log',
            'max_file_size_mb': '10',
            'backup_count': '3'
        }
    }

    def __init__(self, config_path: str = 'config.ini'):
        """
        Initialisiert die Konfiguration.

        :param config_path: Pfad zur Konfigurationsdatei.
        """
        self.config_path = config_path
        self.config = configparser.ConfigParser()
        self._load_or_create_config()

    def _load_or_create_config(self):
        """
        Lädt bestehende Konfiguration oder erstellt Standardkonfiguration.
        """
        if not os.path.exists(self.config_path):
            self._create_default_config()

        self.config.read(self.config_path)
        self._validate_config()

    def _create_default_config(self):
        """
        Erstellt eine Standardkonfigurationsdatei.
        """
        for section, settings in self.DEFAULT_CONFIG.items():
            self.config[section] = settings

        with open(self.config_path, 'w') as configfile:
            self.config.write(configfile)

        logging.info(f"Standardkonfiguration in {self.config_path} erstellt")

    def _validate_config(self):
        """
        Überprüft und ergänzt fehlende Konfigurationssektionen.
        """
        modified = False
        for section, settings in self.DEFAULT_CONFIG.items():
            if not self.config.has_section(section):
                self.config[section] = settings
                logging.warning(f"Sektion {section} wurde zur Konfiguration hinzugefügt")
                modified = True

            for key, value in settings.items():
                if not self.config.has_option(section, key):
                    self.config.set(section, key, value)
                    logging.warning(f"Option {key} in Sektion {section} wurde mit Standardwert ergänzt")
                    modified = True

        if modified:
            with open(self.config_path, 'w') as configfile:
                self.config.write(configfile)

    def get(self, section: str, key: str, fallback: Any = None) -> Any:
        """
        Holt einen Konfigurationswert.

        :param section: Konfigurationssektion.
        :param key: Konfigurationsschlüssel.
        :param fallback: Standardwert, falls Schlüssel nicht existiert.
        :return: Konfigurationswert.
        """
        try:
            return self.config.get(section, key, fallback=fallback)
        except (configparser.NoSectionError, configparser.NoOptionError):
            logging.warning(f"Konfigurationswert nicht gefunden: {section}.{key}")
            return fallback

    def getint(self, section: str, key: str, fallback: int = 0) -> int:
        """
        Holt einen Konfigurationswert als Integer.

        :param section: Konfigurationssektion.
        :param key: Konfigurationsschlüssel.
        :param fallback: Standardwert, falls Schlüssel nicht existiert.
        :return: Integer-Wert.
        """
        try:
            return self.config.getint(section, key)
        except (configparser.NoSectionError, configparser.NoOptionError, ValueError):
            logging.warning(f"Konfigurationswert nicht gefunden oder ungültig: {section}.{key}")
            return fallback

    def getboolean(self, section: str, key: str, fallback: bool = False) -> bool:
        """
        Holt einen Konfigurationswert als Boolean.

        :param section: Konfigurationssektion.
        :param key: Konfigurationsschlüssel.
        :param fallback: Standardwert, falls Schlüssel nicht existiert.
        :return: Boolean-Wert.
        """
        try:
            return self.config.getboolean(section, key)
        except (configparser.NoSectionError, configparser.NoOptionError, ValueError):
            logging.warning(f"Konfigurationswert nicht gefunden oder ungültig: {section}.{key}")
            return fallback

    def set(self, section: str, key: str, value: Any) -> None:
        """
        Setzt einen Konfigurationswert.

        :param section: Konfigurationssektion.
        :param key: Konfigurationsschlüssel.
        :param value: Zu setzender Wert.
        """
        try:
            if not self.config.has_section(section):
                self.config.add_section(section)

            self.config.set(section, key, str(value))

            with open(self.config_path, 'w') as configfile:
                self.config.write(configfile)

            logging.info(f"Konfigurationswert gesetzt: {section}.{key} = {value}")
        except Exception as e:
            logging.error(f"Fehler beim Setzen des Konfigurationswerts: {e}")
            raise ConfigError(f"Konnte Konfigurationswert nicht setzen: {e}")

    def get_database_config(self) -> Dict[str, Any]:
        """
        Holt Datenbank-Konfigurationseinstellungen.

        :return: Dictionary mit Datenbankkonfigurationen.
        """
        return {
            'path': self.get('Database', 'path', 'passwords.db'),
            'backup_directory': self.get('Database', 'backup_directory', 'backups'),
            'max_backups': self.getint('Database', 'max_backups', 5),
            'backup_interval_days': self.getint('Database', 'backup_interval_days', 7)
        }

    def get_security_config(self) -> Dict[str, Any]:
        """
        Holt Sicherheitskonfigurationseinstellungen.

        :return: Dictionary mit Sicherheitskonfigurationen.
        """
        return {
            'iterations': self.getint('Security', 'iterations', 500000),
            'key_length': self.getint('Security', 'key_length', 32),
            'encryption_algorithm': self.get('Security', 'encryption_algorithm', 'AES-256-GCM'),
            'password_min_length': self.getint('Security', 'password_min_length', 12),
            'password_complexity_required': self.getboolean('Security', 'password_complexity_required', True)
        }

    def get_logging_config(self) -> Dict[str, Any]:
        """
        Holt Logging-Konfigurationseinstellungen.

        :return: Dictionary mit Logging-Konfigurationen.
        """
        return {
            'level': self.get('Logging', 'level', 'INFO'),
            'file': self.get('Logging', 'file', 'logs/password_manager.log'),
            'max_file_size_mb': self.getint('Logging', 'max_file_size_mb', 10),
            'backup_count': self.getint('Logging', 'backup_count', 3)
        }

    def validate_config(self) -> List[str]:
        """
        Validiert die Konfigurationseinstellungen.

        :return: Liste von Warnungen oder Fehlern.
        """
        warnings = []

        # Validiere Datenbankkonfiguration
        db_config = self.get_database_config()
        if not os.path.isabs(db_config['path']):
            warnings.append(f"Datenbankpfad ist kein absoluter Pfad: {db_config['path']}")

        # Validiere Sicherheitskonfiguration
        security_config = self.get_security_config()
        if security_config['iterations'] < 100000:
            warnings.append(f"Zu wenige Iterationen für Schlüsselableitung: {security_config['iterations']}")

        if security_config['key_length'] < 16:
            warnings.append(f"Schlüssellänge zu kurz: {security_config['key_length']}")

        # Validiere Logging-Konfiguration
        logging_config = self.get_logging_config()
        log_file = logging_config['file']
        log_dir = os.path.dirname(log_file)

        if not os.path.exists(log_dir):
            try:
                os.makedirs(log_dir)
                logging.info(f"Logging-Verzeichnis erstellt: {log_dir}")
            except Exception as e:
                warnings.append(f"Konnte Logging-Verzeichnis nicht erstellen: {e}")

        return warnings

    def reset_to_defaults(self):
        """
        Setzt die Konfiguration auf Standardwerte zurück.
        """
        try:
            # Entferne bestehende Konfiguration
            self.config = configparser.ConfigParser()
            # Erstelle Standardkonfiguration
            self._create_default_config()
            logging.info("Konfiguration auf Standardwerte zurückgesetzt")
            print("Konfiguration erfolgreich auf Standardwerte zurückgesetzt.")
        except Exception as e:
            logging.error(f"Fehler beim Zurücksetzen der Konfiguration: {e}")
            print(f"Fehler beim Zurücksetzen der Konfiguration: {e}")

    def __str__(self) -> str:
        config_str = "Passwort-Manager Konfiguration\n"
        config_str += "=" * 40 + "\n"

        for section in self.config.sections():
            config_str += f"\n[{section}]\n"
            for key, value in self.config.items(section):
                config_str += f"{key} = {value}\n"

        return config_str
