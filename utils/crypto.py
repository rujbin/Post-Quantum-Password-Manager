# src/utils/crypto.py

import os
import logging
from typing import Tuple
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

class CryptoManager:
    """
    Verwaltet die Verschlüsselung und Entschlüsselung von Daten.
    """

    def __init__(self, master_password: str, iterations: int = 500000, key_length: int = 32, encryption_algorithm: str = "AES-256-GCM"):
        self.master_password = master_password
        self.iterations = iterations
        self.key_length = key_length
        self.encryption_algorithm = encryption_algorithm
        self.backend = default_backend()
        self.salt = None
        self.key = None

    def derive_key(self, salt: bytes) -> bytes:
        """
        Leitet einen Schlüssel vom Master-Passwort ab.

        :param salt: Salt für die Schlüsselableitung
        :return: Abgeleiteter Schlüssel
        """
        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=self.key_length,
                salt=salt,
                iterations=self.iterations,
                backend=self.backend
            )
            return kdf.derive(self.master_password.encode())
        except Exception as e:
            logging.error(f"Fehler bei der Schlüsselableitung: {e}")
            raise

    def generate_salt(self) -> bytes:
        """
        Generiert einen neuen Salt-Wert.

        :return: Salt
        """
        return os.urandom(16)

    def encrypt(self, data: bytes, key: bytes) -> Tuple[bytes, bytes]:
        """
        Verschlüsselt die Daten mit dem angegebenen Schlüssel.

        :param data: Zu verschlüsselnde Daten
        :param key: Verschlüsselungsschlüssel
        :return: Tuple aus verschlüsselten Daten und Nonce
        """
        try:
            aesgcm = AESGCM(key)
            nonce = os.urandom(12)  # 96-bit Nonce für GCM
            encrypted_data = aesgcm.encrypt(nonce, data, None)
            return encrypted_data, nonce
        except Exception as e:
            logging.error(f"Fehler bei der Verschlüsselung: {e}")
            raise

    def decrypt(self, encrypted_data: bytes, key: bytes, nonce: bytes) -> bytes:
        """
        Entschlüsselt die Daten mit dem angegebenen Schlüssel und Nonce.

        :param encrypted_data: Verschlüsselte Daten
        :param key: Entschlüsselungsschlüssel
        :param nonce: Nonce, die bei der Verschlüsselung verwendet wurde
        :return: Entschlüsselte Daten
        """
        try:
            aesgcm = AESGCM(key)
            decrypted_data = aesgcm.decrypt(nonce, encrypted_data, None)
            return decrypted_data
        except Exception as e:
            logging.error(f"Fehler bei der Entschlüsselung: {e}")
            raise
