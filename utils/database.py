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
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )''')

            cursor.execute('''CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY,
                website TEXT NOT NULL,
                username TEXT NOT NULL,
                encrypted_password BLOB NOT NULL,
                iv BLOB NOT NULL,
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

    # Backup- und Restore-Methoden bleiben unverändert
