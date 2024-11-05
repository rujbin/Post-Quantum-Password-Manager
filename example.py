import sys
import sqlite3
import secrets
import logging
import string
from cryptography.fernet import Fernet
import base64
import configparser
from datetime import datetime
import json
import csv
from typing import Dict, Any
from pathlib import Path
from typing import Tuple, List, Optional

# Kryptografie-Bibliotheken
from Crypto.Cipher import AES
from Cryptodome.Random import get_random_bytes
import hashlib
from argon2 import PasswordHasher
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# PyQt5 Bibliotheken
from PyQt5 import QtWidgets, QtCore, QtGui
from PyQt5.QtCore import Qt

# Logging-Konfiguration
logging.basicConfig(
    filename='password_manager.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)


# Eigene Ausnahmen
class PasswordManagerError(Exception):
    """Basis-Ausnahme für Passwort-Manager-Fehler"""
    pass


class DatabaseError(PasswordManagerError):
    """Datenbankbezogene Fehler"""
    pass


class SecurityError(PasswordManagerError):
    """Sicherheitsbezogene Fehler"""
    pass


class Config:
    def __init__(self):
        self.config = configparser.ConfigParser()
        self.config.read('config.ini')
        self.initialize_config()

    def initialize_config(self):
        if not self.config.has_section('Security'):
            self.config['Security'] = {
                'iterations': '500000',
                'key_length': '32'
            }
            with open('config.ini', 'w') as configfile:
                self.config.write(configfile)


class PasswordManager:
    def __init__(self, db_path: str = "passwords.db"):
        self.db_path = db_path
        self.master_key: Optional[str] = None
        self.salt: Optional[bytes] = None
        self.key: Optional[bytes] = None
        self.db_key: Optional[bytes] = None
        self.config = Config()
        self.iterations = self.config.config.getint('Security', 'iterations')
        self.fernet = None

    def connect_db(self) -> sqlite3.Connection:
        """Establishes a database connection."""
        try:
            return sqlite3.connect(self.db_path)
        except sqlite3.Error as e:
            logging.error(f"Database connection failed: {e}")
            raise DatabaseError("Failed to connect to database")

    def generate_key(self, master_password: str) -> bytes:
        """Generates an encryption key from the master password"""
        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=self.salt,
                iterations=self.iterations,
                backend=default_backend()
            )
            return kdf.derive(master_password.encode())
        except Exception as e:
            logging.error(f"Key generation failed: {e}")
            raise SecurityError("Key generation failed")

    def initialize(self, master_password: str):
        """
        Initializes the password manager with a master password.
        Creates the encrypted database and sets up encryption keys.
        """
        try:
            # Create and initialize encrypted database
            with self.connect_db() as conn:
                cursor = conn.cursor()

                # Drop existing tables if they exist
                cursor.execute("DROP TABLE IF EXISTS metadata")
                cursor.execute("DROP TABLE IF EXISTS passwords")

                # Create metadata table with explicit column definitions
                cursor.execute('''CREATE TABLE metadata (
                    id INTEGER PRIMARY KEY,
                    salt BLOB NOT NULL,
                    encrypted_key BLOB NOT NULL,
                    nonce BLOB NOT NULL,
                    tag BLOB NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )''')

                # Create passwords table
                cursor.execute('''CREATE TABLE passwords (
                    id INTEGER PRIMARY KEY,
                    encrypted_data BLOB NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )''')

                # Generate encryption keys
                self.master_key = master_password
                self.salt = get_random_bytes(16)
                self.key = self.generate_key(master_password)

                # Generate database encryption key
                self.db_key = Fernet.generate_key()
                self.fernet = Fernet(self.db_key)

                # Encrypt database key with master key
                cipher = AES.new(self.key, AES.MODE_GCM)
                encrypted_key, tag = cipher.encrypt_and_digest(self.db_key)

                # Insert metadata
                cursor.execute("""INSERT INTO metadata 
                                (id, salt, encrypted_key, nonce, tag) 
                                VALUES (1, ?, ?, ?, ?)""",
                               (self.salt, encrypted_key, cipher.nonce, tag))

                conn.commit()

            logging.info("Password manager successfully initialized with encryption")

        except sqlite3.Error as e:
            logging.error(f"SQLite Error during initialization: {e}")
            raise SecurityError(f"Could not initialize password manager: {e}")
        except Exception as e:
            logging.error(f"Initialization failed: {e}")
            raise SecurityError(f"Could not initialize password manager: {e}")

    def unlock_database(self, master_password: str):
        """Unlocks the encrypted database using the master password"""
        try:
            with self.connect_db() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT salt, encrypted_key, nonce, tag FROM metadata WHERE id = 1")
                result = cursor.fetchone()

            if not result:
                raise SecurityError("Database not initialized")

            salt, encrypted_key, nonce, tag = result
            self.salt = salt
            self.key = self.generate_key(master_password)

            # Decrypt database key
            cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
            self.db_key = cipher.decrypt_and_verify(encrypted_key, tag)
            self.fernet = Fernet(self.db_key)

            logging.info("Database successfully unlocked")

        except ValueError as e:
            logging.error(f"Invalid master password or corrupted data: {e}")
            raise SecurityError("Invalid master password")
        except Exception as e:
            logging.error(f"Failed to unlock database: {e}")
            raise SecurityError(f"Could not unlock database: {e}")

        finally:
            # Clear sensitive data if an error occurred
            if not self.fernet:
                self.master_key = None
                self.salt = None
                self.key = None
                self.db_key = None

    def save_password(self, website: str, username: str, password: str) -> None:
        if not self.fernet:
            raise SecurityError("Database not unlocked")
        try:
        # Create data dictionary
            data = {
                'website': website,
                'username': username,
                'password': password,
                'timestamp': datetime.now().isoformat()
            }
        # Convert to JSON and encrypt
            json_data = json.dumps(data).encode()
            encrypted_data = self.fernet.encrypt(json_data)

            with self.connect_db() as conn:
                cursor = conn.cursor()
                cursor.execute(
                "INSERT INTO passwords (encrypted_data) VALUES (?)",
                (encrypted_data,)
            )
                conn.commit()

            logging.info(f"Password entry saved for {website}")

        except Exception as e:
            logging.error(f"Failed to save password: {e}")
            raise PasswordManagerError(f"Could not save password: {e}")


    def view_passwords(self) -> List[Tuple[str, str, str, str]]:
        if not self.fernet:
            raise SecurityError("Database not unlocked")

        try:
            with self.connect_db() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT encrypted_data FROM passwords")

                passwords = []
                for row in cursor.fetchall():
                    try:
                    # Decrypt data
                        decrypted_data = self.fernet.decrypt(row[0])
                        data = json.loads(decrypted_data.decode())

                        passwords.append((
                        data['website'],
                        data['username'],
                        data['password'],
                        data['timestamp']
                    ))
                    except Exception as e:
                        logging.error(f"Failed to decrypt password entry: {e}")

                return sorted(passwords, key=lambda x: x[0].lower())

        except Exception as e:
            logging.error(f"Failed to retrieve passwords: {e}")
            raise PasswordManagerError(f"Could not retrieve passwords: {e}")


    def delete_password(self, website: str, username: str) -> None:
        """Deletes a password entry"""
        if not self.fernet:
            raise SecurityError("Database not unlocked")

        try:
            with self.connect_db() as conn:
                cursor = conn.cursor()

            # Get all entries and find matching one
                cursor.execute("SELECT rowid, encrypted_data FROM passwords")
                for row in cursor.fetchall():
                    try:
                        decrypted_data = self.fernet.decrypt(row[1])
                        data = json.loads(decrypted_data.decode())

                        if data['website'] == website and data['username'] == username:
                            cursor.execute("DELETE FROM passwords WHERE rowid = ?", (row[0],))
                            conn.commit()
                            logging.info(f"Password entry deleted for {website}")
                            return
                    except Exception as e:
                        logging.error(f"Failed to process entry during deletion: {e}")
        except Exception as e:
            logging.error(f"Failed to delete password: {e}")
            raise PasswordManagerError(f"Could not delete password: {e}")

    def change_master_password(self, old_password: str, new_password: str) -> None:
        """Changes the master password and re-encrypts the database key"""
        if not self.verify_master_password(old_password):
            raise SecurityError("Invalid current master password")

        try:
            # Generate new encryption key
            new_salt = get_random_bytes(16)
            new_key = self.generate_key(new_password)

            # Re-encrypt database key with new master key
            cipher = AES.new(new_key, AES.MODE_GCM)
            encrypted_db_key, tag = cipher.encrypt_and_digest(self.db_key)

            # Update database
            with self.connect_db() as conn:
                cursor = conn.cursor()
                cursor.execute("""UPDATE metadata 
                                    SET salt = ?, 
                                        encrypted_db_key = ?,
                                        nonce = ?,
                                        tag = ?
                                    WHERE id = 1""",
                               (new_salt, encrypted_db_key, cipher.nonce, tag))
                conn.commit()

            # Update instance variables
            self.salt = new_salt
            self.key = new_key
            self.master_key = new_password

            logging.info("Master password successfully changed")

        except Exception as e:
            logging.error(f"Failed to change master password: {e}")
            raise SecurityError(f"Could not change master password: {e}")

    def verify_master_password(self, master_password: str) -> bool:
        """Verifies if the provided master password is correct"""
        try:
            with self.connect_db() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT salt, encrypted_db_key, nonce, tag FROM metadata WHERE id = 1")
                result = cursor.fetchone()

                if not result:
                    return False

                salt, encrypted_db_key, nonce, tag = result
                test_key = self.generate_key(master_password)

                # Try to decrypt database key
                cipher = AES.new(test_key, AES.MODE_GCM, nonce=nonce)
                try:
                    cipher.decrypt_and_verify(encrypted_db_key, tag)
                    return True
                except ValueError:
                    return False

        except Exception as e:
            logging.error(f"Password verification failed: {e}")
            return False

    def backup_database(self, backup_path: str) -> None:
        """Creates an encrypted backup of the database"""
        if not self.fernet:
            raise SecurityError("Database not unlocked")

        try:
            import shutil
            shutil.copy2(self.db_path, backup_path)
            logging.info(f"Database backup created at {backup_path}")
        except Exception as e:
            logging.error(f"Database backup failed: {e}")
            raise DatabaseError(f"Could not create database backup: {e}")

    def restore_database(self, backup_path: str) -> None:
        """Restores the database from a backup"""
        if not Path(backup_path).exists():
            raise DatabaseError("Backup file does not exist")

        try:
            import shutil
            shutil.copy2(backup_path, self.db_path)
            logging.info(f"Database restored from {backup_path}")
        except Exception as e:
            logging.error(f"Database restoration failed: {e}")
            raise DatabaseError(f"Could not restore database: {e}")

    def close(self) -> None:
        """Securely closes the password manager"""
        self.master_key = None
        self.salt = None
        self.key = None
        self.db_key = None
        self.fernet = None
        logging.info("Password manager securely closed")

    def export_passwords(self, export_path: str, include_passwords: bool = False) -> None:
        """Exports passwords to a CSV file"""
        if not self.fernet:
            raise SecurityError("Database not unlocked")

        try:
            passwords = self.view_passwords()

            with open(export_path, 'w', newline='') as csvfile:
                writer = csv.writer(csvfile)
                # Write header
                writer.writerow(
                    ['Website', 'Username', 'Password' if include_passwords else 'Password Hidden', 'Created At'])

                # Write data
                for website, username, password, timestamp in passwords:
                    writer.writerow([
                        website,
                        username,
                        password if include_passwords else '*****',
                        timestamp
                    ])

            logging.info(f"Passwords exported to {export_path}")

        except Exception as e:
            logging.error(f"Password export failed: {e}")
            raise PasswordManagerError(f"Could not export passwords: {e}")

    def import_passwords(self, import_path: str) -> None:
        """Imports passwords from a CSV file"""
        if not self.fernet:
            raise SecurityError("Database not unlocked")

        try:
            with open(import_path, 'r', newline='') as csvfile:
                reader = csv.DictReader(csvfile)

                for row in reader:
                    if 'Website' in row and 'Username' in row and 'Password' in row:
                        self.save_password(
                            row['Website'],
                            row['Username'],
                            row['Password']
                        )

            logging.info(f"Passwords imported from {import_path}")

        except Exception as e:
            logging.error(f"Password import failed: {e}")
            raise PasswordManagerError(f"Could not import passwords: {e}")

    def check_password_strength(self, password: str) -> Dict[str, Any]:
        """Checks the strength of a password"""
        results = {
            'length': len(password) >= 12,
            'uppercase': any(c.isupper() for c in password),
            'lowercase': any(c.islower() for c in password),
            'numbers': any(c.isdigit() for c in password),
            'special': any(not c.isalnum() for c in password),
            'score': 0
        }

        # Calculate score
        score = 0
        score += 1 if results['length'] else 0
        score += 1 if results['uppercase'] else 0
        score += 1 if results['lowercase'] else 0
        score += 1 if results['numbers'] else 0
        score += 1 if results['special'] else 0

        results['score'] = score
        results['strength'] = {
            0: 'Very Weak',
            1: 'Weak',
            2: 'Moderate',
            3: 'Strong',
            4: 'Very Strong',
            5: 'Excellent'
        }[score]

        return results

    def generate_secure_password(self, length: int = 16) -> str:
        """Generates a secure random password"""
        if length < 12:
            raise ValueError("Password length must be at least 12 characters")

        # Define character sets
        uppercase = string.ascii_uppercase
        lowercase = string.ascii_lowercase
        digits = string.digits
        special = "!@#$%^&*()_+-=[]{}|;:,.<>?"

        # Ensure at least one character from each set
        password = [
            secrets.choice(uppercase),
            secrets.choice(lowercase),
            secrets.choice(digits),
            secrets.choice(special)
        ]

        # Fill the rest with random characters
        # Fill the rest with random characters
        all_chars = uppercase + lowercase + digits + special
        password.extend(secrets.choice(all_chars) for _ in range(length - 4))

        # Shuffle the password
        password_list = list(password)
        secrets.SystemRandom().shuffle(password_list)

        return ''.join(password_list)

    def search_passwords(self, query: str) -> List[Tuple[str, str, str, str]]:
        """Searches for passwords matching the query"""
        if not self.fernet:
            raise SecurityError("Database not unlocked")

        try:
            all_passwords = self.view_passwords()
            query = query.lower()

            return [
                password for password in all_passwords
                if query in password[0].lower() or  # website
                   query in password[1].lower()  # username
            ]

        except Exception as e:
            logging.error(f"Password search failed: {e}")
            raise PasswordManagerError(f"Could not search passwords: {e}")

    def get_password_count(self) -> int:
        """Returns the total number of stored passwords"""
        if not self.fernet:
            raise SecurityError("Database not unlocked")

        try:
            with self.connect_db() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM passwords")
                return cursor.fetchone()[0]
        except Exception as e:
            logging.error(f"Failed to get password count: {e}")
            raise DatabaseError(f"Could not get password count: {e}")

    def get_database_info(self) -> Dict[str, Any]:
        """Returns information about the password database"""
        try:
            with self.connect_db() as conn:
                cursor = conn.cursor()

                # Get creation date
                cursor.execute("SELECT created_at FROM metadata WHERE id = 1")
                created_at = cursor.fetchone()[0]

                # Get database size
                db_size = Path(self.db_path).stat().st_size

                # Get password count
                password_count = self.get_password_count() if self.fernet else 0

                return {
                    'created_at': created_at,
                    'db_size': db_size,
                    'password_count': password_count,
                    'db_path': self.db_path,
                    'is_locked': self.fernet is None
                }

        except Exception as e:
            logging.error(f"Failed to get database info: {e}")
            raise DatabaseError(f"Could not get database info: {e}")

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()

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

class PasswordDialog(QtWidgets.QDialog):
    def __init__(self, passwords, password_manager):
        super().__init__()
        self.setWindowTitle("Gespeicherte Passwörter")
        self.setGeometry(200, 200, 600, 400)
        self.password_manager = password_manager
        self.setup_ui(passwords)

    def setup_ui(self, passwords):
        layout = QtWidgets.QVBoxLayout()

        # Suchleiste
        self.search_input = QtWidgets.QLineEdit()
        self.search_input.setPlaceholderText("Suchen...")
        self.search_input.textChanged.connect(self.filter_passwords)
        layout.addWidget(self.search_input)

        # Tabelle
        self.table_widget = QtWidgets.QTableWidget()
        self.table_widget.setColumnCount(4)
        self.table_widget.setHorizontalHeaderLabels(["Website", "Benutzername", "Passwort", "Erstellt am"])
        self.populate_table(passwords)
        layout.addWidget(self.table_widget)

        # Buttons
        button_layout = QtWidgets.QHBoxLayout()
        self.copy_button = QtWidgets.QPushButton("Passwort kopieren")
        self.copy_button.clicked.connect(self.copy_password)
        self.delete_button = QtWidgets.QPushButton("Löschen")
        self.delete_button.clicked.connect(self.delete_password)
        button_layout.addWidget(self.copy_button)
        button_layout.addWidget(self.delete_button)
        layout.addLayout(button_layout)

        self.setLayout(layout)

    def populate_table(self, passwords):
        self.table_widget.setRowCount(len(passwords))
        for row_idx, (website, username, password, created_at) in enumerate(passwords):
            self.table_widget.setItem(row_idx, 0, QtWidgets.QTableWidgetItem(website))
            self.table_widget.setItem(row_idx, 1, QtWidgets.QTableWidgetItem(username))
            # Passwort maskieren
            password_item = QtWidgets.QTableWidgetItem('•' * len(password))
            password_item.setData(QtCore.Qt.UserRole, password)
            self.table_widget.setItem(row_idx, 2, password_item)
            self.table_widget.setItem(row_idx, 3, QtWidgets.QTableWidgetItem(created_at))

    def filter_passwords(self):
        search_text = self.search_input.text().lower()
        for row in range(self.table_widget.rowCount()):
            show_row = False
            for col in range(self.table_widget.columnCount()):
                item = self.table_widget.item(row, col)
                if item and search_text in item.text().lower():
                    show_row = True
                    break
            self.table_widget.setRowHidden(row, not show_row)

    def copy_password(self):
        selected_row = self.table_widget.currentRow()
        if selected_row >= 0:
            password_item = self.table_widget.item(selected_row, 2)
            if password_item:
                password = password_item.data(QtCore.Qt.UserRole)
                QtWidgets.QApplication.clipboard().setText(password)
                QtWidgets.QMessageBox.information(self, "Kopiert", "Passwort in Zwischenablage kopiert!")
            else:
                QtWidgets.QMessageBox.warning(self, "Fehler", "Bitte wählen Sie eine Zeile aus.")

    def delete_password(self):
        try:
            selected_row = self.table_widget.currentRow()

            if selected_row < 0:
                QtWidgets.QMessageBox.warning(
                    self,
                    "Keine Auswahl",
                    "Bitte wählen Sie einen Passwort-Eintrag zum Löschen aus."
                )
                return

            # Website und Benutzername für Bestätigungsmeldung abrufen
            website = self.table_widget.item(selected_row, 0).text()
            username = self.table_widget.item(selected_row, 1).text()

            # Bestätigungsdialog anzeigen
            reply = QtWidgets.QMessageBox.question(
                self,
                'Löschung bestätigen',
                f'Sind Sie sicher, dass Sie den Passwort-Eintrag löschen möchten?\n\nWebsite: {website}\nBenutzername: {username}',
                QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No,
                QtWidgets.QMessageBox.No
            )

            # Löschung durchführen, wenn Benutzer bestätigt
            if reply == QtWidgets.QMessageBox.Yes:
                try:
                    # Verbindung zur Datenbank herstellen
                    with sqlite3.connect(self.password_manager.db_path) as conn:
                        cursor = conn.cursor()
                        cursor.execute(
                            "DELETE FROM passwords WHERE website = ? AND username = ?",
                            (website, username)
                        )
                        conn.commit()

                    # Zeile aus Tabelle entfernen
                    self.table_widget.removeRow(selected_row)

                    QtWidgets.QMessageBox.information(
                        self,
                        "Erfolg",
                        "Passwort-Eintrag erfolgreich gelöscht!"
                    )

                    logging.info(f"Passwort-Eintrag gelöscht für Website: {website}")

                except sqlite3.Error as e:
                    logging.error(f"Datenbankfehler beim Löschen des Passworts: {e}")
                    QtWidgets.QMessageBox.critical(
                        self,
                        "Fehler",
                        f"Fehler beim Löschen des Passwort-Eintrags aus der Datenbank: {e}"
                    )

        except Exception as e:
            logging.error(f"Fehler während des Löschvorgangs: {e}")
            QtWidgets.QMessageBox.critical(
                self,
                "Fehler",
                f"Ein unerwarteter Fehler ist aufgetreten: {str(e)}"
            )
class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.pm = PasswordManager()
        self.setup_ui()

    def setup_ui(self):
        self.setWindowTitle("Sicherer Passwort-Manager")
        self.setGeometry(100, 100, 800, 600)

        # Zentrales Widget und Layout erstellen
        central_widget = QtWidgets.QWidget()
        self.setCentralWidget(central_widget)
        layout = QtWidgets.QVBoxLayout(central_widget)

        # Tabs erstellen
        tabs = QtWidgets.QTabWidget()
        tabs.addTab(self.create_password_tab(), "Passwörter")
        tabs.addTab(self.create_settings_tab(), "Einstellungen")
        layout.addWidget(tabs)

        # Statusleiste
        self.status_bar = self.statusBar()
        self.status_bar.showMessage("Bereit")

        # Menüleiste
        self.create_menu_bar()

    def create_password_tab(self):
        password_widget = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout()

        # Master-Passwort-Bereich
        master_group = QtWidgets.QGroupBox("Master-Passwort")
        master_layout = QtWidgets.QVBoxLayout()
        self.master_password_input = QtWidgets.QLineEdit()
        self.master_password_input.setEchoMode(QtWidgets.QLineEdit.Password)
        self.initialize_button = QtWidgets.QPushButton("Initialisieren")
        self.initialize_button.clicked.connect(self.initialize)
        master_layout.addWidget(self.master_password_input)
        master_layout.addWidget(self.initialize_button)
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

        self.generate_button.clicked.connect(self.generate_password)
        self.save_button.clicked.connect(self.save_password)
        self.view_button.clicked.connect(self.view_passwords)

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
        menubar = self.menuBar()

        # Datei-Menü
        file_menu = menubar.addMenu("Datei")

        backup_action = QtWidgets.QAction("Datenbank sichern", self)
        backup_action.setStatusTip("Erstellt ein Backup der Passwort-Datenbank")
        backup_action.triggered.connect(self.backup_database)

        exit_action = QtWidgets.QAction("Beenden", self)
        exit_action.setStatusTip("Anwendung beenden")
        exit_action.triggered.connect(self.close)

        file_menu.addAction(backup_action)
        file_menu.addSeparator()
        file_menu.addAction(exit_action)

        # Hilfe-Menü
        help_menu = menubar.addMenu("Hilfe")

        about_action = QtWidgets.QAction("Über", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)

    def backup_database(self):
        try:
            # Backup-Pfad wählen
            backup_path, _ = QtWidgets.QFileDialog.getSaveFileName(
                self,
                "Datenbank-Backup speichern",
                "",
                "SQLite Datenbank (*.db)"
            )

            if backup_path:
                # Kopiere die aktuelle Datenbank zum Backup-Pfad
                import shutil
                shutil.copy2(self.pm.db_path, backup_path)

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

    def show_about(self):
        QtWidgets.QMessageBox.about(
            self,
            "Über",
            "Sicherer Passwort-Manager\nVersion 1.0\n\n"
            "Ein sicherer Weg, Ihre Passwörter zu verwalten.\n\n"
            "Entwickelt mit Python und PyQt5"
        )

    def generate_password(self):
        dialog = PasswordGeneratorDialog(self)
        if dialog.exec_() == QtWidgets.QDialog.Accepted:
            self.password_input.setText(dialog.password_display.text())

    def initialize(self):
        try:
            master_password = self.master_password_input.text()
            if not master_password:
                raise ValueError("Master-Passwort darf nicht leer sein")

            self.pm.master_key = master_password
            self.pm.initialize(master_password)

            self.status_bar.showMessage("Passwort-Manager erfolgreich initialisiert")
            QtWidgets.QMessageBox.information(
                self,
                "Erfolg",
                "Passwort-Manager erfolgreich initialisiert!"
            )
        except Exception as e:
            self.status_bar.showMessage(f"Initialisierung fehlgeschlagen: {str(e)}")
            QtWidgets.QMessageBox.critical(self, "Fehler", str(e))

    def save_password(self):
        try:
            website = self.website_input.text()
            username = self.username_input.text()
            password = self.password_input.text()

            if not all([website, username, password]):
                raise ValueError("Alle Felder müssen ausgefüllt werden")

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
        try:
            passwords = self.pm.view_passwords()
            dialog = PasswordDialog(passwords, self.pm)
            dialog.exec_()
        except Exception as e:
            self.status_bar.showMessage(f"Passwörter können nicht angezeigt werden: {str(e)}")
            QtWidgets.QMessageBox.critical(self, "Fehler", str(e))

def main():
    app = QtWidgets.QApplication(sys.argv)

    # Anwendungsstil
    app.setStyle('Fusion')

    # Globales Stylesheet
    app.setStyleSheet("""
        QMainWindow {
            background-color: #f0f0f0;
        }
        QPushButton {
            background-color: #0078d7;
            color: white;
            border: none;
            padding: 6px 12px;
            border-radius: 4px;
            min-width: 80px;
        }
        QPushButton:hover {
            background-color: #1984e0;
        }
        QPushButton:pressed {
            background-color: #006cc1;
        }
        QLineEdit {
            padding: 5px;
            border: 1px solid #ccc;
            border-radius: 3px;
            background-color: white;
        }
        QGroupBox {
            font-weight: bold;
            border: 1px solid #ccc;
            border-radius: 5px;
            margin-top: 10px;
            padding-top: 10px;
        }
        QTableWidget {
            border: 1px solid #ccc;
            background-color: white;
            gridline-color: #f0f0f0;
        }
        QHeaderView::section {
            background-color: #f8f8f8;
            padding: 5px;
            border: 1px solid #ccc;
            font-weight: bold;
        }
        QTabWidget::pane {
            border: 1px solid #ccc;
            background: white;
        }
        QTabBar::tab {
            background: #f0f0f0;
            border: 1px solid #ccc;
            padding: 5px 10px;
        }
        QTabBar::tab:selected {
            background: white;
            border-bottom: 2px solid #0078d7;
        }
    """)

    try:
        # Logging-Verzeichnis erstellen, falls nicht vorhanden
        log_dir = Path('logs')
        log_dir.mkdir(exist_ok=True)

        # Hauptfenster erstellen
        window = MainWindow()
        window.show()

        # Anwendung ausführen
        sys.exit(app.exec_())

    except Exception as e:
        # Kritischer Fehler
        logging.critical(f"Anwendung abgestürzt: {e}")
        QtWidgets.QMessageBox.critical(
            None,
            "Schwerwiegender Fehler",
            f"Die Anwendung ist auf einen schwerwiegenden Fehler gestoßen und muss geschlossen werden.\n\nFehler: {str(e)}"
        )
        sys.exit(1)

# Haupteinstiegspunkt
if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        logging.info("Anwendung durch Benutzer beendet")
        sys.exit(0)
    except Exception as e:
        logging.critical(f"Unbehandelte Ausnahme: {e}")
        sys.exit(1)
