# src/core/exceptions.py

"""
exceptions.py

Enthält alle benutzerdefinierten Ausnahmen für den Passwort-Manager.
"""

class PasswordManagerError(Exception):
    """Basisklasse für alle Passwort-Manager-spezifischen Ausnahmen"""
    def __init__(self, message: str = None, *args, **kwargs):
        self.message = message or "Ein Fehler ist im Passwort-Manager aufgetreten"
        super().__init__(self.message, *args, **kwargs)


class ConfigError(PasswordManagerError):
    """Ausnahmen im Zusammenhang mit der Konfiguration"""
    def __init__(self, message: str = None, *args, **kwargs):
        self.message = message or "Ein Konfigurationsfehler ist aufgetreten"
        super().__init__(self.message, *args, **kwargs)


class DatabaseError(PasswordManagerError):
    """Ausnahmen im Zusammenhang mit der Datenbank"""
    def __init__(self, message: str = None, *args, **kwargs):
        self.message = message or "Ein Datenbankfehler ist aufgetreten"
        super().__init__(self.message, *args, **kwargs)


class SecurityError(PasswordManagerError):
    """Ausnahmen im Zusammenhang mit der Sicherheit"""
    def __init__(self, message: str = None, *args, **kwargs):
        self.message = message or "Ein Sicherheitsfehler ist aufgetreten"
        super().__init__(self.message, *args, **kwargs)


class ValidationError(PasswordManagerError):
    """Ausnahmen im Zusammenhang mit der Validierung"""
    def __init__(self, message: str = None, *args, **kwargs):
        self.message = message or "Ein Validierungsfehler ist aufgetreten"
        super().__init__(self.message, *args, **kwargs)


class AuthenticationError(SecurityError):
    """Ausnahmen im Zusammenhang mit der Authentifizierung"""
    def __init__(self, message: str = None, *args, **kwargs):
        self.message = message or "Ein Authentifizierungsfehler ist aufgetreten"
        super().__init__(self.message, *args, **kwargs)


class EncryptionError(SecurityError):
    """Ausnahmen im Zusammenhang mit der Verschlüsselung"""
    def __init__(self, message: str = None, *args, **kwargs):
        self.message = message or "Ein Verschlüsselungsfehler ist aufgetreten"
        super().__init__(self.message, *args, **kwargs)


class DecryptionError(SecurityError):
    """Ausnahmen im Zusammenhang mit der Entschlüsselung"""
    def __init__(self, message: str = None, *args, **kwargs):
        self.message = message or "Ein Entschlüsselungsfehler ist aufgetreten"
        super().__init__(self.message, *args, **kwargs)


class BackupError(PasswordManagerError):
    """Ausnahmen im Zusammenhang mit Backups"""
    def __init__(self, message: str = None, *args, **kwargs):
        self.message = message or "Ein Backup-Fehler ist aufgetreten"
        super().__init__(self.message, *args, **kwargs)


class ImportError(PasswordManagerError):
    """Ausnahmen im Zusammenhang mit dem Import"""
    def __init__(self, message: str = None, *args, **kwargs):
        self.message = message or "Ein Import-Fehler ist aufgetreten"
        super().__init__(self.message, *args, **kwargs)


class ExportError(PasswordManagerError):
    """Ausnahmen im Zusammenhang mit dem Export"""
    def __init__(self, message: str = None, *args, **kwargs):
        self.message = message or "Ein Export-Fehler ist aufgetreten"
        super().__init__(self.message, *args, **kwargs)


class PasswordError(ValidationError):
    """Ausnahmen im Zusammenhang mit Passwörtern"""
    def __init__(self, message: str = None, *args, **kwargs):
        self.message = message or "Ein Passwort-Fehler ist aufgetreten"
        super().__init__(self.message, *args, **kwargs)


class ConfigValidationError(ValidationError):
    """Ausnahmen im Zusammenhang mit der Konfigurationsvalidierung"""
    def __init__(self, message: str = None, *args, **kwargs):
        self.message = message or "Ein Konfigurationsvalidierungsfehler ist aufgetreten"
        super().__init__(self.message, *args, **kwargs)


class DatabaseConnectionError(DatabaseError):
    """Ausnahmen im Zusammenhang mit Datenbankverbindungen"""
    def __init__(self, message: str = None, *args, **kwargs):
        self.message = message or "Ein Datenbankverbindungsfehler ist aufgetreten"
        super().__init__(self.message, *args, **kwargs)


class DatabaseQueryError(DatabaseError):
    """Ausnahmen im Zusammenhang mit Datenbankabfragen"""
    def __init__(self, message: str = None, *args, **kwargs):
        self.message = message or "Ein Datenbankabfragefehler ist aufgetreten"
        super().__init__(self.message, *args, **kwargs)
