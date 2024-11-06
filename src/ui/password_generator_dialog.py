# src/ui/password_generator_dialog.py

import logging
import string
import secrets
from PyQt5 import QtWidgets


class PasswordGeneratorDialog(QtWidgets.QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Passwort-Generator")
        self.setup_ui()

    def setup_ui(self):
        layout = QtWidgets.QVBoxLayout()

        # Passwortlänge
        length_layout = QtWidgets.QHBoxLayout()
        self.length_label = QtWidgets.QLabel("Länge:")
        self.length_spinbox = QtWidgets.QSpinBox()
        self.length_spinbox.setRange(8, 64)
        self.length_spinbox.setValue(16)
        length_layout.addWidget(self.length_label)
        length_layout.addWidget(self.length_spinbox)

        # Zeichentypen
        self.uppercase_cb = QtWidgets.QCheckBox("Großbuchstaben")
        self.lowercase_cb = QtWidgets.QCheckBox("Kleinbuchstaben")
        self.numbers_cb = QtWidgets.QCheckBox("Zahlen")
        self.symbols_cb = QtWidgets.QCheckBox("Sonderzeichen")

        # Standard aktiviert
        self.uppercase_cb.setChecked(True)
        self.lowercase_cb.setChecked(True)
        self.numbers_cb.setChecked(True)
        self.symbols_cb.setChecked(True)

        # Generiertes Passwort Anzeige
        self.password_display = QtWidgets.QLineEdit()
        self.password_display.setReadOnly(True)

        # Buttons
        button_layout = QtWidgets.QHBoxLayout()
        self.generate_btn = QtWidgets.QPushButton("Generieren")
        self.copy_btn = QtWidgets.QPushButton("Kopieren")
        self.accept_btn = QtWidgets.QPushButton("Übernehmen")
        button_layout.addWidget(self.generate_btn)
        button_layout.addWidget(self.copy_btn)
        button_layout.addWidget(self.accept_btn)

        # Alle Widgets zum Layout hinzufügen
        layout.addLayout(length_layout)
        layout.addWidget(self.uppercase_cb)
        layout.addWidget(self.lowercase_cb)
        layout.addWidget(self.numbers_cb)
        layout.addWidget(self.symbols_cb)
        layout.addWidget(self.password_display)
        layout.addLayout(button_layout)

        self.setLayout(layout)

        # Signale verbinden
        self.generate_btn.clicked.connect(self.generate_password)
        self.copy_btn.clicked.connect(self.copy_password)
        self.accept_btn.clicked.connect(self.accept)

    def generate_password(self):
        try:
            length = self.length_spinbox.value()
            chars = ''

            if self.uppercase_cb.isChecked():
                chars += string.ascii_uppercase
            if self.lowercase_cb.isChecked():
                chars += string.ascii_lowercase
            if self.numbers_cb.isChecked():
                chars += string.digits
            if self.symbols_cb.isChecked():
                chars += string.punctuation

            if not chars:
                QtWidgets.QMessageBox.warning(self, "Fehler", "Bitte wählen Sie mindestens einen Zeichentyp")
                return

            password = ''.join(secrets.choice(chars) for _ in range(length))
            self.password_display.setText(password)

        except Exception as e:
            logging.error(f"Passwortgenerierung fehlgeschlagen: {e}")
            QtWidgets.QMessageBox.critical(self, "Fehler", "Passwort konnte nicht generiert werden")

    def copy_password(self):
        if self.password_display.text():
            QtWidgets.QApplication.clipboard().setText(self.password_display.text())
            QtWidgets.QMessageBox.information(self, "Kopiert", "Passwort in Zwischenablage kopiert!")
