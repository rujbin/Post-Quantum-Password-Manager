# src/ui/main_window.py

import logging
from PyQt5 import QtWidgets, QtGui
from core.password_manager import PasswordManager
from core.exceptions import PasswordManagerError
from ui.password_dialog import PasswordDialog
from ui.password_generator_dialog import PasswordGeneratorDialog
from ui.styles import GLOBAL_STYLE


class MainWindow(QtWidgets.QMainWindow):
    """Hauptfenster des Passwort-Managers"""

    def __init__(self):
        super().__init__()
        self.pm = PasswordManager()
        self.setup_ui()
        self.setup_connections()

    def setup_ui(self):
        """Initialisiert die Benutzeroberfläche"""
        # Grundlegende Fenstereinstellungen
        self.setWindowTitle("Sicherer Passwort-Manager")
        self.setGeometry(100, 100, 800, 600)
        self.setStyleSheet(GLOBAL_STYLE)

        # Zentrales Widget und Layout
        central_widget = QtWidgets.QWidget()
        self.setCentralWidget(central_widget)
        layout = QtWidgets.QVBoxLayout(central_widget)

        # Tabs erstellen
        self.tabs = QtWidgets.QTabWidget()
        self.tabs.addTab(self.create_password_tab(), "Passwörter")
        self.tabs.addTab(self.create_settings_tab(), "Einstellungen")
        layout.addWidget(self.tabs)

        # Statusleiste
        self.status_bar = self.statusBar()
        self.status_bar.showMessage("Bereit")

        # Menüleiste
        self.create_menu_bar()

    def setup_connections(self):
        """Verbindet die Signale mit den Slots"""
        self.initialize_button.clicked.connect(self.initialize)
        self.unlock_button.clicked.connect(self.unlock)
        self.generate_button.clicked.connect(self.generate_password)
        self.save_button.clicked.connect(self.save_password)
        self.view_button.clicked.connect(self.view_passwords)
        self.backup_button.clicked.connect(self.backup_database)
        self.restore_button.clicked.connect(self.restore_database)

    def create_password_tab(self):
        """Erstellt den Tab für Passwörter"""
        password_widget = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout()

        # Master-Passwort-Bereich
        master_group = QtWidgets.QGroupBox("Master-Passwort")
        master_layout = QtWidgets.QVBoxLayout()
        self.master_password_input = QtWidgets.QLineEdit()
        self.master_password_input.setEchoMode(QtWidgets.QLineEdit.Password)
        self.initialize_button = QtWidgets.QPushButton("Initialisieren")
        self.unlock_button = QtWidgets.QPushButton("Entsperren")
        master_layout.addWidget(self.master_password_input)
        master_layout.addWidget(self.initialize_button)
        master_layout.addWidget(self.unlock_button)
        master_group.setLayout(master_layout)

        # Neues Passwort-Bereich
        new_password_group = QtWidgets.QGroupBox("Neues Passwort")
        new_password_layout = QtWidgets.QGridLayout()

        self.website_input = QtWidgets.QLineEdit()
        self.username_input = QtWidgets.QLineEdit()
        self.password_input = QtWidgets.QLineEdit()
        self.password_input.setEchoMode(QtWidgets.QLineEdit.Password)

        new_password_layout.addWidget(QtWidgets.QLabel("Website:"), 0, 0)
        new_password_layout.addWidget(self.website_input, 0, 1)
        new_password_layout.addWidget(QtWidgets.QLabel("Benutzername:"), 1, 0)
        new_password_layout.addWidget(self.username_input, 1, 1)
        new_password_layout.addWidget(QtWidgets.QLabel("Passwort:"), 2, 0)
        new_password_layout.addWidget(self.password_input, 2, 1)

        button_layout = QtWidgets.QHBoxLayout()
        self.generate_button = QtWidgets.QPushButton("Passwort generieren")
        self.save_button = QtWidgets.QPushButton("Passwort speichern")
        self.view_button = QtWidgets.QPushButton("Passwörter anzeigen")

        button_layout.addWidget(self.generate_button)
        button_layout.addWidget(self.save_button)
        button_layout.addWidget(self.view_button)

        new_password_group.setLayout(new_password_layout)

        layout.addWidget(master_group)
        layout.addWidget(new_password_group)
        layout.addLayout(button_layout)
        layout.addStretch()

        password_widget.setLayout(layout)
        return password_widget

    def create_settings_tab(self):
        """Erstellt den Tab für Einstellungen"""
        settings_widget = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout()

        # Datenbank-Backup-Bereich
        backup_group = QtWidgets.QGroupBox("Datenbank-Backup")
        backup_layout = QtWidgets.QVBoxLayout()
        self.backup_button = QtWidgets.QPushButton("Backup erstellen")
        self.restore_button = QtWidgets.QPushButton("Backup wiederherstellen")
        backup_layout.addWidget(self.backup_button)
        backup_layout.addWidget(self.restore_button)
        backup_group.setLayout(backup_layout)

        layout.addWidget(backup_group)
        layout.addStretch()

        settings_widget.setLayout(layout)
        return settings_widget

    def create_menu_bar(self):
        """Erstellt die Menüleiste"""
        menubar = self.menuBar()

        # Datei-Menü
        file_menu = menubar.addMenu("Datei")

        backup_action = QtWidgets.QAction("Datenbank sichern", self)
        backup_action.setStatusTip("Erstellt ein Backup der Passwort-Datenbank")
        backup_action.triggered.connect(self.backup_database)

        check_encryption_action = QtWidgets.QAction("Datenbankverschlüsselung prüfen", self)
        check_encryption_action.setStatusTip("Prüft, ob die Passwörter in der Datenbank verschlüsselt sind")
        check_encryption_action.triggered.connect(self.check_database_encryption)

        exit_action = QtWidgets.QAction("Beenden", self)
        exit_action.setStatusTip("Anwendung beenden")
        exit_action.triggered.connect(self.close)

        file_menu.addAction(backup_action)
        file_menu.addAction(check_encryption_action)
        file_menu.addSeparator()
        file_menu.addAction(exit_action)

        # Hilfe-Menü
        help_menu = menubar.addMenu("Hilfe")

        about_action = QtWidgets.QAction("Über", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)

    def initialize(self):
        """Initialisiert den Passwort-Manager"""
        try:
            master_password = self.master_password_input.text()
            if not master_password:
                QtWidgets.QMessageBox.warning(
                    self,
                    "Fehler",
                    "Master-Passwort darf nicht leer sein"
                )
                return

            self.pm.initialize(master_password)
            self.status_bar.showMessage("Passwort-Manager erfolgreich initialisiert")
            QtWidgets.QMessageBox.information(
                self,
                "Erfolg",
                "Passwort-Manager erfolgreich initialisiert!"
            )
        except PasswordManagerError as e:
            self.status_bar.showMessage(f"Initialisierung fehlgeschlagen: {str(e)}")
            QtWidgets.QMessageBox.warning(self, "Fehler", str(e))
        except Exception as e:
            self.status_bar.showMessage(f"Initialisierung fehlgeschlagen: {str(e)}")
            QtWidgets.QMessageBox.critical(self, "Fehler", str(e))

    def unlock(self):
        """Entsperrt den Passwort-Manager"""
        try:
            master_password = self.master_password_input.text()
            if not master_password:
                QtWidgets.QMessageBox.warning(
                    self,
                    "Fehler",
                    "Master-Passwort darf nicht leer sein"
                )
                return

            self.pm.unlock(master_password)
            self.status_bar.showMessage("Passwort-Manager erfolgreich entsperrt")
            QtWidgets.QMessageBox.information(
                self,
                "Erfolg",
                "Passwort-Manager erfolgreich entsperrt!"
            )
        except Exception as e:
            self.status_bar.showMessage(f"Entsperren fehlgeschlagen: {str(e)}")
            QtWidgets.QMessageBox.critical(self, "Fehler", str(e))

    def save_password(self):
        """Speichert ein neues Passwort"""
        try:
            website = self.website_input.text()
            username = self.username_input.text()
            password = self.password_input.text()

            if not all([website, username, password]):
                QtWidgets.QMessageBox.warning(
                    self,
                    "Fehler",
                    "Bitte füllen Sie alle Felder aus"
                )
                return

            self.pm.save_password(website, username, password)
            self.status_bar.showMessage("Passwort erfolgreich gespeichert")
            QtWidgets.QMessageBox.information(
                self,
                "Erfolg",
                "Passwort erfolgreich gespeichert!"
            )

            # Eingabefelder leeren
            self.website_input.clear()
            self.username_input.clear()
            self.password_input.clear()
        except Exception as e:
            self.status_bar.showMessage(f"Speichern fehlgeschlagen: {str(e)}")
            QtWidgets.QMessageBox.critical(self, "Fehler", str(e))

    def view_passwords(self):
        """Zeigt die gespeicherten Passwörter an"""
        try:
            passwords = self.pm.get_passwords()
            dialog = PasswordDialog(passwords, self)
            dialog.exec_()
        except Exception as e:
            self.status_bar.showMessage(f"Passwörter können nicht angezeigt werden: {str(e)}")
            QtWidgets.QMessageBox.critical(self, "Fehler", str(e))

    def generate_password(self):
        """Öffnet den Passwort-Generator"""
        dialog = PasswordGeneratorDialog(self)
        if dialog.exec_() == QtWidgets.QDialog.Accepted:
            self.password_input.setText(dialog.password_display.text())

    def backup_database(self):
        """Erstellt ein Datenbank-Backup"""
        try:
            backup_path, _ = QtWidgets.QFileDialog.getSaveFileName(
                self,
                "Datenbank-Backup speichern",
                "",
                "SQLite Datenbank (*.db)"
            )

            if backup_path:
                self.pm.backup_database(backup_path)

                QtWidgets.QMessageBox.information(
                    self,
                    "Backup erfolgreich",
                    f"Datenbank erfolgreich gesichert nach:\n{backup_path}"
                )
                logging.info(f"Datenbank-Backup erstellt: {backup_path}")
        except Exception as e:
            logging.error(f"Backup-Fehler: {e}")
            QtWidgets.QMessageBox.critical(
                self,
                "Backup-Fehler",
                f"Fehler beim Erstellen des Backups: {str(e)}"
            )

    def restore_database(self):
        """Stellt die Datenbank aus einem Backup wieder her"""
        try:
            backup_path, _ = QtWidgets.QFileDialog.getOpenFileName(
                self,
                "Datenbank-Backup wiederherstellen",
                "",
                "SQLite Datenbank (*.db)"
            )

            if backup_path:
                self.pm.restore_database(backup_path)

                QtWidgets.QMessageBox.information(
                    self,
                    "Wiederherstellung erfolgreich",
                    f"Datenbank erfolgreich wiederhergestellt aus:\n{backup_path}"
                )
                logging.info(f"Datenbank wiederhergestellt aus: {backup_path}")
        except Exception as e:
            logging.error(f"Wiederherstellungs-Fehler: {e}")
            QtWidgets.QMessageBox.critical(
                self,
                "Wiederherstellungs-Fehler",
                f"Fehler bei der Wiederherstellung: {str(e)}"
            )

    def check_database_encryption(self):
        """Überprüft, ob die Passwörter in der Datenbank verschlüsselt sind"""
        try:
            if not self.pm.master_key:
                QtWidgets.QMessageBox.warning(
                    self,
                    "Fehler",
                    "Bitte entsperren Sie den Passwort-Manager zuerst."
                )
                return

            is_encrypted = self.pm.check_database_encryption()
            if is_encrypted:
                QtWidgets.QMessageBox.information(
                    self,
                    "Datenbankverschlüsselung",
                    "Die Passwörter in der Datenbank sind verschlüsselt."
                )
            else:
                QtWidgets.QMessageBox.warning(
                    self,
                    "Datenbankverschlüsselung",
                    "Die Passwörter in der Datenbank sind NICHT verschlüsselt!"
                )
        except Exception as e:
            logging.error(f"Fehler bei der Überprüfung der Datenbankverschlüsselung: {e}")
            QtWidgets.QMessageBox.critical(
                self,
                "Fehler",
                f"Fehler bei der Überprüfung der Datenbankverschlüsselung: {str(e)}"
            )

    def show_about(self):
        """Zeigt den Über-Dialog"""
        QtWidgets.QMessageBox.about(
            self,
            "Über",
            "Sicherer Passwort-Manager\nVersion 1.0\n\n"
            "Ein sicherer Weg, Ihre Passwörter zu verwalten.\n\n"
            "Entwickelt mit Python und PyQt5"
        )

    def closeEvent(self, event: QtGui.QCloseEvent):
        """Handler für das Schließen des Fensters"""
        try:
            self.pm.close()
            event.accept()
        except Exception as e:
            logging.error(f"Fehler beim Schließen: {e}")
            QtWidgets.QMessageBox.critical(
                self,
                "Fehler",
                f"Fehler beim Schließen der Anwendung: {str(e)}"
            )
            event.ignore()
