"""
UI-Modul des Passwort-Managers

Dieses Paket enthält alle Benutzeroberflächen-Komponenten des Passwort-Managers.
"""

from typing import Dict, Any
import logging
from PyQt5 import QtWidgets

# Version des UI-Moduls
__version__ = "1.0.0"

# Importiere UI-Komponenten für einfacheren Zugriff
from .main_window import MainWindow
from .password_dialog import PasswordDialog
from .password_generator_dialog import PasswordGeneratorDialog

# UI-Konfiguration
UI_CONFIG = {
    'window_title': 'Sicherer Passwort-Manager',
    'min_width': 800,
    'min_height': 600,
    'default_style': 'Fusion'
}

def setup_ui_environment() -> None:
    """
    Initialisiert die UI-Umgebung mit grundlegenden Einstellungen
    """
    try:
        # Setze den Anwendungsstil
        QtWidgets.QApplication.setStyle(UI_CONFIG['default_style'])
        
        # Aktiviere High-DPI-Skalierung
        QtWidgets.QApplication.setAttribute(QtWidgets.Qt.AA_EnableHighDpiScaling, True)
        QtWidgets.QApplication.setAttribute(QtWidgets.Qt.AA_UseHighDpiPixmaps, True)
        
        logging.info("UI-Umgebung erfolgreich initialisiert")
    except Exception as e:
        logging.error(f"Fehler bei der UI-Initialisierung: {e}")
        raise

def get_ui_config() -> Dict[str, Any]:
    """
    Gibt die UI-Konfiguration zurück

    :return: Dictionary mit UI-Konfigurationseinstellungen
    """
    return UI_CONFIG.copy()

# Definiere verfügbare UI-Komponenten
__all__ = [
    'MainWindow',
    'PasswordDialog',
    'PasswordGeneratorDialog',
    'setup_ui_environment',
    'get_ui_config',
    'UI_CONFIG'
]

# Initialisierungscode
logging.getLogger(__name__).addHandler(logging.NullHandler())