# src/core/exceptions.py

class PasswordManagerError(Exception):
    """Basisklasse für alle Passwort-Manager-Fehler."""
    pass

class ConfigError(PasswordManagerError):
    """Fehler im Zusammenhang mit der Konfiguration."""
    pass

class ValidationError(PasswordManagerError):
    """Fehler bei der Validierung von Eingaben."""
    pass

class SecurityError(PasswordManagerError):
    """Fehler im Zusammenhang mit Sicherheitsaspekten."""
    pass

class DatabaseError(PasswordManagerError):
    """Fehler im Zusammenhang mit Datenbankoperationen."""
    pass

class EncryptionError(PasswordManagerError):
    """Fehler während der Verschlüsselung."""
    pass

class DecryptionError(PasswordManagerError):
    """Fehler während der Entschlüsselung."""
    pass

class AuthenticationError(PasswordManagerError):
    """Fehler bei der Authentifizierung."""
    pass

class PasswordError(PasswordManagerError):
    """Fehler im Zusammenhang mit Passwortoperationen."""
    pass

class BackupError(PasswordManagerError):
    """Fehler während der Backup-Operation."""
    pass

class DataImportError(PasswordManagerError):
    """Fehler während des Datenimports."""
    pass

class DataExportError(PasswordManagerError):
    """Fehler während des Datenexports."""
    pass
