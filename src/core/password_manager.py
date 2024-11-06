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
    DataImportError,
    DataExportError,
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
        self.salt: Optional[bytes] = None

    def initialize(self, master_password: str):
        """
        Initialisiert den Passwort-Manager mit einem Master-Passwort.
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

            # Initialisiere die Datenbank (Tabellen erstellen, falls nicht vorhanden)
            self.db_manager.initialize_database()

            # Überprüfe, ob der Passwort-Manager bereits initialisiert ist
            query_check = "SELECT COUNT(*) FROM metadata WHERE id = ?"
            result = self.db_manager.execute_query(query_check, (1,))

            if result and result[0][0] > 0:
                logging.warning("Passwort-Manager wurde bereits initialisiert.")
                raise PasswordManagerError("Der Passwort-Manager wurde bereits initialisiert. Bitte entsperren Sie ihn mit Ihrem Master-Passwort.")

            # Speichere den Salt-Wert in der Metadaten-Tabelle
            query_insert = """INSERT INTO metadata (id, salt)
                              VALUES (?, ?)"""
            self.db_manager.execute_query(query_insert, (1, self.salt))

            logging.info("Passwort-Manager erfolgreich initialisiert")

        except PasswordManagerError as e:
            logging.error(f"Fehler bei der Initialisierung: {e}")
            raise
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

            # Lade den Salt aus der Datenbank
            query = "SELECT salt FROM metadata WHERE id = ?"
            result = self.db_manager.execute_query(query, (1,))
            if not result:
                raise AuthenticationError("Ungültiges Master-Passwort oder Datenbank nicht initialisiert")

            self.salt = result[0][0]
            self.master_key = self.crypto_manager.derive_key(self.salt)

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
        if not self.master_key:
            raise SecurityError("Passwort-Manager ist nicht entsperrt")

        try:
            # Passwort verschlüsseln
            data = {
                'password': password
            }
            json_data = json.dumps(data).encode('utf-8')
            encrypted_data, iv = self.crypto_manager.encrypt(json_data, self.master_key)

            # Daten in die Datenbank einfügen
            query = """INSERT INTO passwords (website, username, encrypted_password, iv)
                       VALUES (?, ?, ?, ?)"""
            self.db_manager.execute_query(query, (website, username, encrypted_data, iv))

            logging.info(f"Passwort für {website} gespeichert")

        except Exception as e:
            logging.error(f"Fehler beim Speichern des Passworts: {e}")
            raise PasswordManagerError(f"Konnte Passwort nicht speichern: {e}")

    def get_passwords(self) -> List[Dict[str, Any]]:
        """
        Ruft alle gespeicherten Passwörter ab und entschlüsselt sie.
        """
        if not self.master_key:
            raise SecurityError("Passwort-Manager ist nicht entsperrt")

        try:
            query = "SELECT website, username, encrypted_password, iv FROM passwords"
            results = self.db_manager.execute_query(query)

            passwords = []
            for website, username, encrypted_password, iv in results:
                decrypted_data = self.crypto_manager.decrypt(encrypted_password, self.master_key, iv)
                data = json.loads(decrypted_data.decode('utf-8'))
                data.update({
                    'website': website,
                    'username': username,
                })
                passwords.append(data)

            return passwords

        except Exception as e:
            logging.error(f"Fehler beim Abrufen der Passwörter: {e}")
            raise PasswordManagerError(f"Konnte Passwörter nicht abrufen: {e}")

    def check_database_encryption(self) -> bool:
        """
        Prüft, ob die Passwörter in der Datenbank verschlüsselt sind.
        Gibt eine entsprechende Meldung aus.
        :return: True, wenn die Passwörter verschlüsselt gespeichert sind, False sonst.
        """
        if not self.master_key:
            raise SecurityError("Passwort-Manager ist nicht entsperrt")

        try:
            # Versuche, ein Passwort aus der Datenbank abzurufen
            query = "SELECT encrypted_password, iv FROM passwords LIMIT 1"
            result = self.db_manager.execute_query(query)
            if not result:
                logging.info("Keine Passwörter in der Datenbank vorhanden.")
                print("Keine Passwörter in der Datenbank vorhanden.")
                return False

            encrypted_password, iv = result[0]

            # Versuche, die Daten zu entschlüsseln
            decrypted_data = self.crypto_manager.decrypt(encrypted_password, self.master_key, iv)
            # Wenn die Entschlüsselung erfolgreich war, sind die Passwörter verschlüsselt
            logging.info("Die Passwörter in der Datenbank sind verschlüsselt.")
            print("Die Passwörter in der Datenbank sind verschlüsselt.")
            return True

        except Exception as e:
            # Wenn die Entschlüsselung fehlschlägt, sind die Passwörter möglicherweise nicht verschlüsselt
            logging.warning("Die Passwörter in der Datenbank sind NICHT verschlüsselt oder das Master-Passwort ist falsch.")
            print("Die Passwörter in der Datenbank sind NICHT verschlüsselt oder das Master-Passwort ist falsch.")
            return False

    def backup_database(self, backup_path: str):
        """
        Erstellt ein Backup der Datenbank.
        """
        try:
            original = Path(self.database_config['path'])
            backup = Path(backup_path)
            original.replace(backup)
            logging.info(f"Datenbank-Backup erstellt: {backup}")
        except Exception as e:
            logging.error(f"Fehler beim Backup der Datenbank: {e}")
            raise BackupError(f"Konnte Datenbank-Backup nicht erstellen: {e}")

    def restore_database(self, backup_path: str):
        """
        Stellt die Datenbank aus einem Backup wieder her.
        """
        try:
            backup = Path(backup_path)
            original = Path(self.database_config['path'])
            backup.replace(original)
            logging.info(f"Datenbank aus Backup wiederhergestellt: {backup}")
        except Exception as e:
            logging.error(f"Fehler bei der Wiederherstellung der Datenbank: {e}")
            raise BackupError(f"Konnte Datenbank nicht wiederherstellen: {e}")

    def close(self):
        """
        Schließt den Passwort-Manager und löscht sensible Daten aus dem Speicher.
        """
        self.master_password = None
        self.master_key = None
        self.salt = None
        self.crypto_manager = None
        logging.info("Passwort-Manager geschlossen")
