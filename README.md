Der Sichere Passwort-Manager ist eine benutzerfreundliche Anwendung zur Verwaltung, Speicherung und Generierung sicherer Passwörter.  
Entwickelt mit Python und PyQt5, bietet er robuste Sicherheitsfunktionen, um Ihre sensiblen Daten zu schützen.

## Funktionen

1. Sichere Speicherung: Verschlüsselte Speicherung Ihrer Passwörter mit AES-256-GCM.
2. Passwort-Generator: Erstellen Sie starke, zufällige Passwörter nach Ihren Vorgaben.
3. Benutzerfreundliche UI: Intuitive Oberfläche zur einfachen Verwaltung Ihrer Passwörter.
4. Backup und Restore: Erstellen und Wiederherstellen von verschlüsselten Datenbank-Backups.
5. Konfigurierbare Einstellungen: Passen Sie Sicherheits- und Datenbankparameter über eine Konfigurationsdatei an.
6. Robustes Logging: Verfolgen Sie Aktivitäten und Fehler sicher und effizient.

# Sicherheitsüberlegungen
Der Passwort-Manager implementiert verschiedene Sicherheitsmaßnahmen, darunter:  

* Verschlüsselte Speicherung: Passwörter werden mit AES-256-GCM verschlüsselt gespeichert.
* Starke Schlüsselableitung: Verwendung von PBKDF2HMAC mit 500.000 Iterationen zur Ableitung des Schlüssels aus dem Master-Passwort.
* Sichere Konfiguration: Einstellungen werden über eine config.ini verwaltet, die restriktive Zugriffsrechte haben sollte.
* Robustes Logging: Ereignisse und Fehler werden sicher geloggt, ohne sensible Daten preiszugeben.
* Datenbankverschlüsselung: Nutzung von SQLCipher zur vollständigen Verschlüsselung der SQLite-Datenbankdatei.

## To-Dos  
1. Automatisches Leeren der Zwischenablage: Implementieren einer Funktion, die die Zwischenablage nach dem Kopieren von Passwörtern automatisch leert.
2. Zwei-Faktor-Authentifizierung (2FA)
3. Regelmäßige Sicherheitsüberprüfungen: Regelmäßige Sicherheitsüberprüfungen und Penetrationstests.
4. Benutzeraufklärung: Informieren Sie die Benutzer über bewährte Sicherheitspraktiken. ( Über eine Blog-Webseite)
