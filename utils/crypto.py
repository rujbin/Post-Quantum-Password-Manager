# src/utils/crypto.py

import os
import logging
from typing import Tuple
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class CryptoManager:
    """
    Verwaltet die Verschlüsselung und Entschlüsselung von Daten.
    """

    def __init__(self, master_password: str, iterations: int = 500000, key_length: int = 32):
        self.master_password = master_password
        self.iterations = iterations
        self.key_length = key_length
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
        :return: Tuple aus verschlüsselten Daten und IV
        """
        try:
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=self.backend)
            encryptor = cipher.encryptor()

            # Padding anwenden
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(data) + padder.finalize()

            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
            return encrypted_data, iv
        except Exception as e:
            logging.error(f"Fehler bei der Verschlüsselung: {e}")
            raise

    def decrypt(self, encrypted_data: bytes, key: bytes, iv: bytes) -> bytes:
        """
        Entschlüsselt die Daten mit dem angegebenen Schlüssel und IV.

        :param encrypted_data: Verschlüsselte Daten
        :param key: Entschlüsselungsschlüssel
        :param iv: Initialisierungsvektor
        :return: Entschlüsselte Daten
        """
        try:
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

            # Padding entfernen
            unpadder = padding.PKCS7(128).unpadder()
            data = unpadder.update(padded_data) + unpadder.finalize()
            return data
        except Exception as e:
            logging.error(f"Fehler bei der Entschlüsselung: {e}")
            raise
