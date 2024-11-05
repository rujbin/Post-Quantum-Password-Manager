# src/ui/password_dialog.py

import logging  # Importiere das logging-Modul
from PyQt5 import QtWidgets, QtCore
from functools import partial

class PasswordDialog(QtWidgets.QDialog):
    def __init__(self, passwords, parent: QtWidgets.QWidget = None):
        super().__init__(parent)  # Übergibt den korrekten Elternteil
        self.setWindowTitle("Gespeicherte Passwörter")
        self.resize(600, 400)
        
        layout = QtWidgets.QVBoxLayout(self)
        
        # Tabelle zur Anzeige der Passwörter
        self.table = QtWidgets.QTableWidget(self)
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["Website", "Benutzername", "Passwort", "Aktion"])
        self.table.setRowCount(len(passwords))
        self.table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        
        for row, password_entry in enumerate(passwords):
            self.table.setItem(row, 0, QtWidgets.QTableWidgetItem(password_entry['website']))
            self.table.setItem(row, 1, QtWidgets.QTableWidgetItem(password_entry['username']))
            
            # Passwort wird als geschützter Text angezeigt und das tatsächliche Passwort wird im UserRole gespeichert
            password_item = QtWidgets.QTableWidgetItem("••••••••")
            password_item.setData(QtCore.Qt.UserRole, password_entry['password'])  # Speichert das tatsächliche Passwort
            self.table.setItem(row, 2, password_item)
            
            # Kopier-Button hinzufügen
            copy_button = QtWidgets.QPushButton("Kopieren")
            copy_button.clicked.connect(partial(self.copy_password, row))
            self.table.setCellWidget(row, 3, copy_button)
        
        self.table.resizeColumnsToContents()
        layout.addWidget(self.table)

    def copy_password(self, row):
        # Zugriff auf das Passwort aus der Tabelle
        password_item = self.table.item(row, 2)
        actual_password = password_item.data(QtCore.Qt.UserRole)
        logging.debug(f"Kopiere Passwort für Zeile {row}: {actual_password}")  # Logging verwenden
        
        if actual_password:
            clipboard = QtWidgets.QApplication.clipboard()
            clipboard.setText(actual_password)
            QtWidgets.QMessageBox.information(self, "Erfolg", "Passwort kopiert!")
            logging.info(f"Passwort für Zeile {row} kopiert.")  # Logging verwenden
        else:
            QtWidgets.QMessageBox.warning(self, "Fehler", "Kein Passwort verfügbar zum Kopieren.")
            logging.warning(f"Kein Passwort zum Kopieren für Zeile {row}.")  # Logging verwenden
