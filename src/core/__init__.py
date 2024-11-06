# src/core/__init__.py

"""
Core-Modul des Passwort-Managers

Enthält Kernfunktionalitäten wie Konfiguration und Hauptlogik.
"""

# Versionsinformationen und Metadaten
__version__ = "1.0.0"

# Importiere wichtige Klassen für einfachen Zugriff
from .config import Config
from .exceptions import (
    PasswordManagerError,
    ConfigError,
    SecurityError,
    DatabaseError,
    EncryptionError,
    DecryptionError,
    AuthenticationError,
    PasswordError,
    BackupError,
    DataImportError,  # Aktualisiert
    DataExportError,  # Aktualisiert
)

from .password_manager import PasswordManager

# Definiere, welche Module exportiert werden sollen
__all__ = [
    'Config',
    'PasswordManager',
    'PasswordManagerError',
    'ConfigError',
    'DatabaseError',
    'SecurityError',
    'ValidationError',
    'AuthenticationError',
    'EncryptionError',
    'DecryptionError',
    'BackupError',
    'ImportError',
    'ExportError',
    'PasswordError',
    'ConfigValidationError',
    'DatabaseConnectionError',
    'DatabaseQueryError',
]
