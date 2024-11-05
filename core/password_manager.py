# src/core/password_manager.py

import logging
import json
from typing import List, Dict, Any, Optional
from datetime import datetime

from .config import Config
from .exceptions import (
    PasswordManagerError,
    SecurityError,
    DatabaseError,
    EncryptionError,
    DecryptionError,
    AuthenticationError,
    PasswordError,
    BackupError,
    ImportError,
    ExportError,
)

from utils.crypto import CryptoManager
from utils.database import DatabaseManager


class PasswordManager:
    """
    Hauptklasse des Passwort-Managers.

    Verwaltet die Verschlüsselung, Speicherung und Verwaltung von Passwörtern.
    """

    def __init__(self):
        self.config = Config()
        self.security_config = self.config.get_security_config()
        self.database_config = self.config.get_database_config()

        self.db_manager = DatabaseManager(db_path=self.database_config['path'])
        self.crypto_manager: Optional[CryptoManager] = None
        self.master_password: Optional[str] = None
        self.master_key: Optional[bytes] = None
        self.db_key: Optional[bytes] = None
        self.salt: Optional[bytes] = None

    def initialize(self, master_password: str):
        """
        Initialisiert den Passwort-Manager mit einem Master-Passwort.
        Erstellt die Datenbank und verschlüsselt den Datenbankschlüssel mit dem abgeleiteten Master-Schlüssel.
        """
        try:
            self.master_password = master_password
            self.crypto_manager = CryptoManager(
                master_password=master_password,
                iterations=self.security_config['iterations'],
                key_length=self.security_config['key_length']
            )
            self.salt = self.crypto_manager.generate_salt()
            self.master_key = self.crypto_manager.derive_key(self.salt)

            # Generiere einen zufälligen Datenbankschlüssel
            self.db_key = self.crypto_manager.generate_random_key()

            # Verschlüssele den Datenbankschlüssel mit dem Master-Schlüssel
            encrypted_key, nonce = self.crypto_manager.encrypt(self.db_key, self.master_key)

            # Initialisiere die Datenbank
            self.db_manager.initialize_database()

            # Prüfe, ob bereits ein Eintrag in der metadata-Tabelle existiert
            query_check = "SELECT COUNT(*) FROM metadata"
            result = self.db_manager.execute_query(query_check)
            count = result[0][0] if result else 0

            if count == 0:
                # Speichere die Metadaten (Salt, verschlüsselter Schlüssel, Nonce)
                query_insert = """INSERT INTO metadata (id, salt, encrypted_key, nonce)
                                  VALUES (?, ?, ?, ?)"""
                self.db_manager.execute_query(query_insert, (1, self.salt, encrypted_key, nonce))
                logging.info("Passwort-Manager erfolgreich initialisiert")
            else:
                logging.info("Passwort-Manager ist bereits initialisiert")

        except Exception as e:
            logging.error(f"Fehler bei der Initialisierung: {e}")
            raise PasswordManagerError(f"Konnte Passwort-Manager nicht initialisieren: {e}")

    def unlock(self, master_password: str):
        """
        Entsperrt den Passwort-Manager mit dem Master-Passwort.
        """
        try:
            self.master_password = master_password
            self.crypto_manager = CryptoManager(
                master_password=master_password,
                iterations=self.security_config['iterations'],
                key_length=self.security_config['key_length']
            )

            # Lade den Salt, den verschlüsselten Datenbankschlüssel und den Nonce aus der Datenbank
            query = "SELECT salt, encrypted_key, nonce FROM metadata WHERE id = ?"
            result = self.db_manager.execute_query(query, (1,))
            if not result:
                raise AuthenticationError("Ungültiges Master-Passwort oder Datenbank nicht initialisiert")

            self.salt, encrypted_key, nonce = result[0]
            self.master_key = self.crypto_manager.derive_key(self.salt)

            # Entschlüssele den Datenbankschlüssel
            self.db_key = self.crypto_manager.decrypt(encrypted_key, self.master_key, nonce)

            logging.info("Passwort-Manager erfolgreich entsperrt")

        except AuthenticationError as e:
            logging.error(f"Authentifizierungsfehler: {e}")
            raise
        except Exception as e:
            logging.error(f"Fehler beim Entsperren: {e}")
            raise PasswordManagerError(f"Konnte Passwort-Manager nicht entsperren: {e}")

    def save_password(self, website: str, username: str, password: str):
        """
        Speichert ein neues Passwort verschlüsselt in der Datenbank.
        """
        if not self.db_key:
            raise SecurityError("Passwort-Manager ist nicht entsperrt")

        try:
            # Passwort verschlüsseln
            data = {
                'website': website,
                'username': username,
                'password': password,
                'timestamp': datetime.now().isoformat()
            }
            json_data = json.dumps(data).encode('utf-8')
            encrypted_data, nonce = self.crypto_manager.encrypt(json_data, self.db_key)

            # Daten in die Datenbank einfügen
            query = """INSERT INTO passwords (website, username, encrypted_password, nonce)
                       VALUES (?, ?, ?, ?)"""
            self.db_manager.execute_query(query, (website, username, encrypted_data, nonce))

            logging.info(f"Passwort für {website} gespeichert")

        except Exception as e:
            logging.error(f"Fehler beim Speichern des Passworts: {e}")
            raise PasswordManagerError(f"Konnte Passwort nicht speichern: {e}")

    def get_passwords(self) -> List[Dict[str, Any]]:
        """
        Ruft alle gespeicherten Passwörter ab und entschlüsselt sie.
        """
        if not self.db_key:
            raise SecurityError("Passwort-Manager ist nicht entsperrt")

        try:
            query = "SELECT website, username, encrypted_password, nonce FROM passwords"
            results = self.db_manager.execute_query(query)

            passwords = []
            for website, username, encrypted_password, nonce in results:
                decrypted_data = self.crypto_manager.decrypt(encrypted_password, self.db_key, nonce)
                data = json.loads(decrypted_data.decode('utf-8'))
                passwords.append(data)

            return passwords

        except Exception as e:
            logging.error(f"Fehler beim Abrufen der Passwörter: {e}")
            raise PasswordManagerError(f"Konnte Passwörter nicht abrufen: {e}")

    def delete_password(self, website: str, username: str):
        """
        Löscht ein Passwort aus der Datenbank.
        """
        if not self.db_key:
            raise SecurityError("Passwort-Manager ist nicht entsperrt")

        try:
            query = "DELETE FROM passwords WHERE website = ? AND username = ?"
            self.db_manager.execute_query(query, (website, username))

            logging.info(f"Passwort für {website} gelöscht")

        except Exception as e:
            logging.error(f"Fehler beim Löschen des Passworts: {e}")
            raise PasswordManagerError(f"Konnte Passwort nicht löschen: {e}")

    def change_master_password(self, old_password: str, new_password: str):
        """
        Ändert das Master-Passwort und aktualisiert die Verschlüsselung des Datenbankschlüssels.
        """
        if not self.master_key or not self.db_key:
            raise SecurityError("Passwort-Manager ist nicht entsperrt")

        if old_password != self.master_password:
            raise AuthenticationError("Altes Master-Passwort ist ungültig")

        try:
            # Neuer CryptoManager mit neuem Passwort
            new_crypto_manager = CryptoManager(
                master_password=new_password,
                iterations=self.security_config['iterations'],
                key_length=self.security_config['key_length']
            )
            new_salt = new_crypto_manager.generate_salt()
            new_master_key = new_crypto_manager.derive_key(new_salt)

            # Verschlüssele den Datenbankschlüssel mit dem neuen Master-Schlüssel
            encrypted_key, nonce = new_crypto_manager.encrypt(self.db_key, new_master_key)

            # Aktualisiere den Salt, den verschlüsselten Schlüssel und den Nonce in der Metadaten-Tabelle
            query = "UPDATE metadata SET salt = ?, encrypted_key = ?, nonce = ? WHERE id = ?"
            self.db_manager.execute_query(query, (new_salt, encrypted_key, nonce, 1))

            # Aktualisiere die Instanzvariablen
            self.master_password = new_password
            self.crypto_manager = new_crypto_manager
            self.salt = new_salt
            self.master_key = new_master_key

            logging.info("Master-Passwort erfolgreich geändert")

        except Exception as e:
            logging.error(f"Fehler beim Ändern des Master-Passworts: {e}")
            raise PasswordManagerError(f"Konnte Master-Passwort nicht ändern: {e}")

    def backup_database(self, backup_path: str):
        """
        Erstellt ein Backup der Datenbank.
        """
        try:
            self.db_manager.backup_database(backup_path)
            logging.info(f"Datenbank-Backup erstellt: {backup_path}")
        except Exception as e:
            logging.error(f"Fehler beim Erstellen des Backups: {e}")
            raise BackupError(f"Konnte Backup nicht erstellen: {e}")

    def restore_database(self, backup_path: str):
        """
        Stellt die Datenbank aus einem Backup wieder her.
        """
        try:
            self.db_manager.restore_database(backup_path)
            logging.info(f"Datenbank aus Backup wiederhergestellt: {backup_path}")
        except Exception as e:
            logging.error(f"Fehler bei der Wiederherstellung der Datenbank: {e}")
            raise BackupError(f"Konnte Datenbank nicht wiederherstellen: {e}")

    def export_passwords(self, export_path: str):
        """
        Exportiert die Passwörter in eine JSON-Datei.
        """
        if not self.db_key:
            raise SecurityError("Passwort-Manager ist nicht entsperrt")

        try:
            passwords = self.get_passwords()
            with open(export_path, 'w') as f:
                json.dump(passwords, f, indent=4)
            logging.info(f"Passwörter exportiert nach: {export_path}")
        except Exception as e:
            logging.error(f"Fehler beim Exportieren der Passwörter: {e}")
            raise ExportError(f"Konnte Passwörter nicht exportieren: {e}")

    def import_passwords(self, import_path: str):
        """
        Importiert Passwörter aus einer JSON-Datei.
        """
        if not self.db_key:
            raise SecurityError("Passwort-Manager ist nicht entsperrt")

        try:
            with open(import_path, 'r') as f:
                passwords = json.load(f)

            for data in passwords:
                json_data = json.dumps(data).encode('utf-8')
                encrypted_data, nonce = self.crypto_manager.encrypt(json_data, self.db_key)

                query = """INSERT INTO passwords (website, username, encrypted_password, nonce)
                           VALUES (?, ?, ?, ?)"""
                self.db_manager.execute_query(query, (data['website'], data['username'], encrypted_data, nonce))

            logging.info(f"Passwörter importiert aus: {import_path}")

        except Exception as e:
            logging.error(f"Fehler beim Importieren der Passwörter: {e}")
            raise ImportError(f"Konnte Passwörter nicht importieren: {e}")

    def generate_password(self, length: int = 16) -> str:
        """
        Generiert ein sicheres Passwort.

        :param length: Länge des zu generierenden Passworts.
        :return: Generiertes Passwort als String.
        """
        import secrets
        import string

        if length < self.security_config['password_min_length']:
            raise PasswordError(f"Passwort muss mindestens {self.security_config['password_min_length']} Zeichen lang sein")

        characters = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(secrets.choice(characters) for _ in range(length))

        # Überprüfe die Komplexität
        if self.security_config['password_complexity_required']:
            if not any(c.islower() for c in password):
                password += secrets.choice(string.ascii_lowercase)
            if not any(c.isupper() for c in password):
                password += secrets.choice(string.ascii_uppercase)
            if not any(c.isdigit() for c in password):
                password += secrets.choice(string.digits)
            if not any(c in string.punctuation for c in password):
                password += secrets.choice(string.punctuation)

        logging.info("Sicheres Passwort generiert")
        return password

    def close(self):
        """
        Schließt den Passwort-Manager und löscht sensible Daten aus dem Speicher.
        """
        self.master_password = None
        self.master_key = None
        self.salt = None
        self.crypto_manager = None
        self.db_key = None
        logging.info("Passwort-Manager geschlossen")
