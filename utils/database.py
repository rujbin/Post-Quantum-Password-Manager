# src/utils/database.py

import sqlite3
import logging
from pathlib import Path
from typing import Optional


class DatabaseManager:
    """
    Verwaltet die Datenbankoperationen.
    """

    def __init__(self, db_path: str = "passwords.db"):
        self.db_path = db_path
        self.connection: Optional[sqlite3.Connection] = None

    def connect(self):
        """
        Stellt eine Verbindung zur Datenbank her.
        """
        try:
            self.connection = sqlite3.connect(self.db_path)
            logging.info("Datenbankverbindung erfolgreich hergestellt")
        except sqlite3.Error as e:
            logging.error(f"Datenbankverbindung fehlgeschlagen: {e}")
            raise

    def close(self):
        """
        Schließt die Datenbankverbindung.
        """
        if self.connection:
            self.connection.close()
            logging.info("Datenbankverbindung geschlossen")

    def initialize_database(self):
        """
        Initialisiert die Datenbankstruktur.
        """
        try:
            self.connect()
            cursor = self.connection.cursor()

            # Tabellen erstellen
            cursor.execute('''CREATE TABLE IF NOT EXISTS metadata (
                id INTEGER PRIMARY KEY,
                salt BLOB NOT NULL,
                encrypted_key BLOB NOT NULL,
                nonce BLOB NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )''')

            cursor.execute('''CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY,
                website TEXT NOT NULL,
                username TEXT NOT NULL,
                encrypted_password BLOB NOT NULL,
                nonce BLOB NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )''')

            self.connection.commit()
            logging.info("Datenbank erfolgreich initialisiert")

        except sqlite3.Error as e:
            logging.error(f"Fehler bei der Initialisierung der Datenbank: {e}")
            raise

        finally:
            self.close()

    def execute_query(self, query: str, params: tuple = ()):
        """
        Führt eine Datenbankabfrage aus.

        :param query: SQL-Abfrage
        :param params: Parameter für die Abfrage
        :return: Ergebnis der Abfrage
        """
        try:
            self.connect()
            cursor = self.connection.cursor()
            cursor.execute(query, params)
            self.connection.commit()
            result = cursor.fetchall()
            return result

        except sqlite3.Error as e:
            logging.error(f"Datenbankabfrage fehlgeschlagen: {e}")
            raise

        finally:
            self.close()

    def backup_database(self, backup_path: str):
        """
        Erstellt ein Backup der Datenbank.

        :param backup_path: Pfad zum Backup
        """
        try:
            self.close()
            Path(backup_path).parent.mkdir(parents=True, exist_ok=True)
            with open(self.db_path, 'rb') as src, open(backup_path, 'wb') as dst:
                dst.write(src.read())
            logging.info(f"Datenbank-Backup erstellt: {backup_path}")

        except Exception as e:
            logging.error(f"Fehler beim Erstellen des Datenbank-Backups: {e}")
            raise

    def restore_database(self, backup_path: str):
        """
        Stellt die Datenbank aus einem Backup wieder her.

        :param backup_path: Pfad zum Backup
        """
        try:
            self.close()
            with open(backup_path, 'rb') as src, open(self.db_path, 'wb') as dst:
                dst.write(src.read())
            logging.info(f"Datenbank wiederhergestellt aus: {backup_path}")

        except Exception as e:
            logging.error(f"Fehler bei der Wiederherstellung der Datenbank: {e}")
            raise
