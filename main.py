import sys
import logging
from pathlib import Path

from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QMessageBox

# Lokale Importe
from ui.main_window import MainWindow
from ui.styles import GLOBAL_STYLE  # Import des Stylesheets
from utils.logging_config import setup_logging

def configure_application():
    """Konfiguriert die PyQt-Anwendung"""
    app = QtWidgets.QApplication(sys.argv)
    
    # Fusion-Stil für ein modernes Aussehen
    app.setStyle('Fusion')
    
    # Globales Stylesheet anwenden
    app.setStyleSheet(GLOBAL_STYLE)
    
    return app

def main():
    try:
        # Logging-Verzeichnis erstellen
        log_dir = Path('logs')
        log_dir.mkdir(exist_ok=True)
        
        # Logging konfigurieren
        setup_logging()
        
        # Anwendung konfigurieren
        app = configure_application()
        
        # Hauptfenster erstellen
        window = MainWindow()
        window.show()
        
        # Anwendung ausführen
        sys.exit(app.exec_())
    
    except Exception as e:
        # Kritischer Fehler
        logging.critical(f"Anwendung abgestürzt: {e}", exc_info=True)
        
        # Fallback-Fehlerbehandlung
        error_dialog = QMessageBox()
        error_dialog.setIcon(QMessageBox.Critical)
        error_dialog.setText("Schwerwiegender Fehler")
        error_dialog.setInformativeText(f"Die Anwendung ist auf einen schwerwiegenden Fehler gestoßen:\n\n{str(e)}")
        error_dialog.setWindowTitle("Anwendungsfehler")
        error_dialog.exec_()
        
        sys.exit(1)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        logging.info("Anwendung durch Benutzer beendet")
        sys.exit(0)
