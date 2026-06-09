# Sicherheitsaudit – Password Phrase Producer

**Datum:** 2026-06-09
**Umfang:** Vollständiger Code-Audit der kryptografischen Kernkomponenten, der Vaults (Passwort-Tresor, Daten-Tresor, Authenticator/TOTP), der Speicher- und Synchronisationsoperationen sowie der Plattformkonfiguration für **Android** und **Windows**.
**Bewertete Codebasis:** .NET 9 MAUI App (`net9.0-android`, `net9.0-windows`, iOS/MacCatalyst mitbetrachtet).

> Hinweis zur Genauigkeit: Die Tresor-Inhalte werden **nicht** im Klartext gespeichert. Alle Einträge werden mit AES-256-GCM unter einem aus dem Master-Passwort abgeleiteten Schlüssel verschlüsselt; bei aktiviertem App-Lock kommt eine zweite Verschlüsselungsschicht hinzu. Die folgenden Befunde betreffen die *Stärke* und *Robustheit* dieses Schutzes, nicht dessen Fehlen.

---

## Zusammenfassung (Management Summary)

Die App verwendet grundsätzlich solide, moderne Bausteine (AES-256-GCM als AEAD, PBKDF2 mit zufälligem Salt pro Geheimnis, hardwaregestützte Biometrie-Schlüssel, zeitkonstante Vergleiche). Es wurden **keine** im Klartext abgelegten Passwörter, **keine** im Repository eingecheckten Geheimnisse/Keystores und **kein** Logging von Geheimnissen gefunden.

Die gravierendste Schwäche liegt **nicht** im Tresor selbst, sondern im **Passwort-Generator**: Er nutzt einen nicht-kryptografischen Zufallsgenerator, und der „Seed“-Modus reduziert den gesamten Schlüsselraum auf 32 Bit. Daneben gibt es mehrere Härtungsdefizite auf Plattformebene (Android-Backup, Screenshot-/Task-Switcher-Schutz) und bei der Schlüsselableitung (Iterationszahl, fehlende Brute-Force-Bremse, fehlende Passwortrichtlinie).

| ID | Schweregrad | Kurzbeschreibung |
|----|-------------|------------------|
| H1 | **Hoch** | Generierte Passwörter nutzen `System.Random` (nicht kryptografisch); Seed-Modus auf 2³² begrenzt → vorhersagbar |
| H2 | **Hoch** | `android:allowBackup="true"` → verschlüsselte Tresordateien per ADB/Cloud-Backup extrahierbar |
| H3 | **Hoch** | Kein `FLAG_SECURE`; Tresorinhalt im Task-Switcher/in Screenshots/bei Screen-Recording sichtbar |
| M1 | Mittel | PBKDF2-SHA256 mit nur 200.000 Iterationen (unter OWASP-Empfehlung; kein Argon2id) |
| M2 | Mittel | Kein Brute-Force-Schutz/Rate-Limiting/Lockout beim Entsperren |
| M3 | Mittel | Keine Mindeststärke/-länge für das Master-Passwort |
| M4 | Mittel | Passwörter werden in die Zwischenablage kopiert ohne Auto-Löschung / „sensitive“-Markierung |
| M5 | Mittel | Biometrie-gewickelter Schlüssel nutzt AES-CBC (ohne Integritätsschutz); Windows ohne TPM-KSP |
| M6 | Mittel | iOS/Fallback-Biometrie „verschlüsselt“ den Schlüssel gar nicht (Klartext in SecureStorage) |
| L1–L9 | Niedrig/Info | Verifier-Design, fehlende AAD, Schlüssel im Managed-Memory, hartkodierter Timeout u. a. |

---

## Architektur-Überblick

Es existieren mehrere voneinander getrennte Schutzschichten und sogar mehrere parallele Master-Passwort-Systeme:

1. **AppLockService** (`Services/Security/AppLockService.cs`)
   Globales App-Login. Erzeugt einen zufälligen **Master Encryption Key (MEK)**, der mit einem aus dem App-Passwort via PBKDF2 abgeleiteten **KEK** verschlüsselt (AES-GCM) in `SecureStorage` liegt. Metadaten (Salt, Verifier, verschlüsselter MEK, biometrisch verschlüsselter MEK) liegen unter dem Schlüssel `AppLockMetadata_V1`.

2. **SecureFileService** (`Services/Storage/SecureFileService.cs`)
   Transparente Dateiverschlüsselung mit dem MEK des AppLockService. **Wichtig:** Ist der App-Lock konfiguriert und entsperrt, wird jede Datei zusätzlich mit dem MEK verschlüsselt; ist er **nicht** konfiguriert, werden Dateien einschichtig geschrieben (siehe unten).

3. **PasswordVaultService / DataVaultService** (`Services/Vault/…`)
   Eigene Master-Passwörter mit eigenem Salt/Verifier/Iterationen. Tresordatei `vault.json.enc` enthält JSON `{CipherText, PasswordSalt, PasswordVerifier, Pbkdf2Iterations}`. Der `CipherText` ist AES-256-GCM unter dem aus dem Tresor-Passwort abgeleiteten Schlüssel.

4. **TotpEncryptionService** (`Services/Security/TotpEncryptionService.cs`)
   Eigenständige Verschlüsselung der TOTP-Geheimnisse mit eigenem Master-Key in `totp.key`.

5. **SynchronizationService** (`Services/Synchronization/SynchronizationService.cs`)
   Gemeinsame, mit einem Sync-Passwort (PBKDF2 → AES-GCM) verschlüsselte Austauschdatei. Der Sync-Schlüssel wird mit dem AppLock-MEK gewickelt in `SecureStorage` abgelegt.

**Beobachtung (Info):** Drei nahezu identische, aber getrennte Passwort-/KDF-Implementierungen (PasswordVault, DataVault, Totp) plus AppLock erhöhen die Wartungslast und das Risiko, dass Härtungen nur an einzelnen Stellen ankommen. Eine Konsolidierung auf einen gemeinsamen Krypto-Kern wird empfohlen.

---

## Detailbefunde

### H1 — Nicht-kryptografischer Zufallsgenerator im Passwort-Generator  *(Hoch)*

**Dateien:**
`PasswordGenerationTechniques/RandomPasswordTechnique/RandomPasswordTechnique.cs`,
`…/DicewareTechnique/AdaptiveDicewareTechnique.cs`,
`…/SymbolInjectionTechnique/SymbolInterleavingTechnique.cs`

```csharp
private static Random CreateRandom(string? seed)
{
    if (string.IsNullOrWhiteSpace(seed))
        return Random.Shared;                       // (1) nicht kryptografisch

    byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(seed));
    int seedValue = BitConverter.ToInt32(hash, 0);  // (2) nur 32 Bit Seed!
    return new Random(seedValue);
}
```

**Problem:**
1. Ohne Seed wird `Random.Shared` (xoshiro256**) verwendet. Dieser PRNG ist **nicht kryptografisch sicher** und für die Erzeugung von Geheimnissen ungeeignet – die tatsächliche Sicherheit der erzeugten Passwörter ist niedriger als ihre Länge/Zeichenmenge suggeriert.
2. Im Seed-Modus wird der gesamte Generatorzustand aus **32 Bit** (`int`) initialisiert. Damit existieren – unabhängig von der gewählten Passwortlänge – **höchstens ~4,29 Mrd. (2³²) mögliche Ausgaben**. Ein Angreifer kann den kompletten Ausgaberaum offline durchprobieren. Ist der Seed eine merkbare Phrase, ist das Passwort zusätzlich direkt aus dieser reproduzierbar.

**Auswirkung:** Mit diesem Generator erstellte Passwörter (für reale Konten!) sind potenziell vorhersagbar bzw. erheblich schwächer als angenommen.

**Empfehlung:** Für die nicht-seed-basierte Erzeugung ausschließlich `System.Security.Cryptography.RandomNumberGenerator` verwenden (z. B. `RandomNumberGenerator.GetInt32`). Den 32-Bit-Seed-Modus entweder entfernen oder klar als „nur deterministisch, nicht für hochsensible Passwörter“ kennzeichnen und – falls deterministisch gewünscht – auf eine vollwertige KDF (Argon2id/PBKDF2 über den gesamten Hash) als Stromquelle umstellen statt `new Random(int)`.

---

### H2 — `android:allowBackup="true"`  *(Hoch)*

**Datei:** `Platforms/Android/AndroidManifest.xml`

```xml
<application android:allowBackup="true" ... >
```

**Problem:** Mit aktiviertem Backup können die App-Privatdaten – einschließlich der verschlüsselten Tresordatei `vault.json.enc` und `totp.key` – über `adb backup` bzw. Google Auto-Backup extrahiert werden. Zwar sind die Inhalte verschlüsselt, doch dadurch gelangen sie aus dem App-Sandkasten heraus und können **offline** (siehe M1: nur 200k PBKDF2-Iterationen) angegriffen werden. Auch das Wiederherstellen manipulierter Backups wird ermöglicht.

**Empfehlung:** `android:allowBackup="false"` setzen oder gezielt sensible Dateien per `android:dataExtractionRules` (API 31+) bzw. `android:fullBackupContent` von Backups ausschließen.

---

### H3 — Kein Screenshot-/Task-Switcher-Schutz (`FLAG_SECURE`)  *(Hoch)*

**Dateien:** `Platforms/Android/MainActivity.cs`, `App.xaml.cs` (`OnSleep`)

`OnSleep` setzt bewusst **keinen** Sperrbildschirm/Overlay und behält den App-Zustand für den Task-Switcher bei; `MainActivity` setzt **kein** `WindowManagerFlags.Secure`.

**Problem:** Entsperrte Tresorinhalte (Passwörter, Benutzernamen, TOTP-Codes) erscheinen in der Android-„Letzte-Apps“-Vorschau, lassen sich per Screenshot abgreifen und sind für Screen-Recording-/Screen-Sharing-Malware sichtbar.

**Empfehlung:** Für sensible Seiten `Window.AddFlags(WindowManagerFlags.Secure)` setzen; im Hintergrund (`OnSleep`) ein blickdichtes Overlay/Splash anzeigen, damit die Vorschau keine Geheimnisse zeigt. Auf Windows analog das Fenster bei Inaktivität verschleiern.

---

### M1 — Schwache KDF-Parametrisierung (PBKDF2-SHA256, 200.000 Iterationen)  *(Mittel)*

**Dateien:** AppLockService, PasswordVaultService, DataVaultService, TotpEncryptionService, SynchronizationService (jeweils `Pbkdf2Iterations = 200_000`, `HashAlgorithmName.SHA256`).

**Problem:** Die OWASP-Empfehlung für PBKDF2-HMAC-SHA256 liegt bei **600.000** Iterationen (Stand 2023). 200.000 sind im Jahr 2026 für ein Master-Passwort, das *alle* Geheimnisse schützt, zu niedrig – besonders relevant, weil verschlüsselte Dateien das Gerät verlassen können (H2, Sync). PBKDF2-SHA256 ist zudem GPU-/ASIC-freundlich.

**Empfehlung:** Auf **Argon2id** (speicherhart) umstellen – ideal für einen Passwort-Manager. Falls Argon2id kurzfristig nicht umsetzbar ist, PBKDF2-Iterationen mindestens auf 600.000 anheben. Die Iterationszahl wird bereits pro Tresor gespeichert, sodass eine versionierte Migration möglich ist.

---

### M2 — Kein Brute-Force-Schutz beim Entsperren  *(Mittel)*

**Datei:** `Views/Security/AppLoginPage.xaml.cs` (analog Tresor-Login)

**Problem:** Falsche Passworteingaben werden ohne Verzögerung, Zählung, exponentielles Backoff oder Sperre nach n Versuchen abgelehnt. Ein Angreifer mit Gerätezugriff kann unbegrenzt on-device raten (nur durch die PBKDF2-Kosten gebremst).

**Empfehlung:** Fehlversuche zählen, progressive Verzögerung einführen und optional nach mehreren Fehlversuchen den lokalen Schlüssel/Tresor löschen (zerstörerische Sperre wie bei iOS-„Daten löschen“). Zustand manipulationssicher persistieren.

---

### M3 — Keine Passwortrichtlinie für das Master-Passwort  *(Mittel)*

**Datei:** `Views/Security/SetupAppPasswordPage.xaml.cs`

**Problem:** Akzeptiert jedes nicht-leere Passwort (auch „1“). Es gibt keine Mindestlänge/Stärkemessung. Die App enthält bereits einen `PasswordEntropyAnalyzer` – dieser wird beim Setzen des Master-Passworts nicht genutzt.

**Empfehlung:** Mindestlänge erzwingen (z. B. ≥ 12 Zeichen), Stärke per vorhandenem Entropy-Analyzer anzeigen und sehr schwache Passwörter ablehnen.

---

### M4 — Zwischenablage ohne Auto-Löschung  *(Mittel)*

**Dateien:** `Views/VaultPage.xaml.cs`, `Views/VaultEntryDetailPage.xaml.cs`, `Views/DataVaultPage.xaml.cs`, `ViewModels/AuthenticatorViewModel.cs`

```csharp
await Clipboard.Default.SetTextAsync(entry.Password);
```

**Problem:** Passwörter/TOTP-Codes werden in die Zwischenablage kopiert, ohne sie nach einer Zeitspanne automatisch zu löschen und ohne sie als sensibel zu markieren. Andere Apps (Android < 13) bzw. die Zwischenablage-Historie können sie auslesen.

**Empfehlung:** Nach ~20–30 s automatisch löschen (sofern der Inhalt unverändert ist). Auf Android 13+ `ClipDescription`-Extra `EXTRA_IS_SENSITIVE` setzen, damit der Inhalt nicht in der Clipboard-Vorschau erscheint.

---

### M5 — Biometrie-Wrapping ohne AEAD; Windows ohne TPM  *(Mittel)*

**Datei:** `Services/Security/BiometricAuthenticationService.cs`

- **Android & Windows** umhüllen den Master-/Tresor-Schlüssel mit **AES/CBC/PKCS7** – also **ohne** Integritätsschutz (kein GCM/HMAC). Manipulationen am gespeicherten Blob werden nicht kryptografisch erkannt.
- **Windows** verwendet `MicrosoftSoftwareKeyStorageProvider` (Software-KSP), nicht den TPM-gebundenen `MicrosoftPlatformCryptoProvider` – trotz Code-Kommentar, der TPM erwähnt.

**Empfehlung:** AES-GCM (oder Encrypt-then-MAC) verwenden. Unter Windows den Platform-/TPM-KSP nutzen, um die Schlüssel hardwaregebunden und nicht exportierbar zu machen. Der Android-Schlüssel ist immerhin mit `SetUserAuthenticationRequired(true)` und `SetInvalidatedByBiometricEnrollment(true)` korrekt gehärtet (positiv).

---

### M6 — iOS/Fallback-Biometrie speichert den Schlüssel im Klartext  *(Mittel – für Android/Windows nicht relevant, aber vorhanden)*

**Datei:** `BiometricAuthenticationService.cs` (`#else`-Zweig)

```csharp
public async Task<byte[]> EncryptAsync(byte[] data, ...)
{
    var authObj = await AuthenticateAsync(...);
    ...
    return data;   // gibt den Schlüssel UNVERSCHLÜSSELT zurück
}
```

**Problem:** Auf iOS/anderen Plattformen wird der Master-Schlüssel „biometrisch verschlüsselt“, indem er **unverändert** zurückgegeben und so im Klartext in `SecureStorage` (Keychain) abgelegt wird. Bei Keychain-Kompromittierung (Jailbreak) liegt der Schlüssel offen. Für deine Nutzung (Android + Windows) **nicht akut**, sollte aber vor einem iOS-Release behoben werden (Keychain Access Control / SecAccessControl mit `.biometryCurrentSet`).

---

### Niedrig / Informativ

- **L1 – Verifier-Design:** Der Verifier ist `SHA256(abgeleiteter Schlüssel)` und liegt neben dem Salt (in der Tresordatei und/oder SecureStorage). Er bietet einem Offline-Angreifer einen schnellen Prüf-Orakel pro PBKDF2-Versuch. Da PBKDF2 ohnehin der teure Schritt ist, ist der Zusatznutzen für den Angreifer gering, aber der Verifier ist redundant (das GCM-Tag authentifiziert bereits). Besser: separaten Verifier-Schlüssel via HKDF ableiten oder ganz auf das GCM-Tag stützen.
- **L2 – Keine Schlüsseltrennung:** Derselbe abgeleitete Schlüssel dient gleichzeitig als AES-Schlüssel und als Eingabe des Verifier-Hashes. Best Practice: per HKDF getrennte Teilschlüssel (Enc-Key vs. Auth/Verifier-Key).
- **L3 – Keine Associated Data (AAD) in AES-GCM:** Es findet keine Kontext-/Versionsbindung statt (Vault vs. DataVault vs. Sync vs. TOTP). Da die Schlüssel verschieden sind, ist das Risiko gering; AAD (z. B. Dateiformat-Version, Tresortyp) würde Domain-Separation und Downgrade-Schutz verbessern.
- **L4 – Schlüssel im Managed Memory:** Master-/abgeleitete Schlüssel liegen als `byte[]` vor und lassen sich in .NET nicht zuverlässig nullen (GC kann verschieben/kopieren). `GetUnlockedKey()` gibt Kopien zurück, die von Aufrufern nicht gelöscht werden. Erwäge `Array.Clear` durchgängig nach Gebrauch.
- **L5 – GCM-Nonce-Wiederverwendungsrisiko:** Zufällige 96-Bit-Nonces mit langlebigem Sync-Schlüssel – Kollisionsrisiko erst nach ~2³² Schreibvorgängen; praktisch unkritisch, aber bei sehr häufiger Synchronisation beachten (deterministischer Zähler-Nonce wäre robuster).
- **L6 – Platzhalter-Paketname:** `com.companyname.passwordphraseproducer` in `PasswordPhraseProducer.csproj` – vor Veröffentlichung auf eine eigene, registrierte Application-ID ändern (Namespace-Squatting/Verwechslung vermeiden).
- **L7 – Fehlermeldungen an die UI:** Sync-Fehler werden mit `ex.Message` im Dialog angezeigt (`PasswordVaultService.AddOrUpdateEntryAsync` u. a.) – kann Pfade/Interna preisgeben. Generische Meldung anzeigen, Details nur ins Debug-Log.
- **L8 – Sperr-Timeout hartkodiert:** 5 Minuten (`AppLockService._lockTimeout`); der MEK verbleibt während der Karenzzeit im RAM. Konfigurierbar machen (inkl. „sofort sperren“).
- **L9 – Robustheit des Sync-Parsers:** `ReadJsonFromStreamAsync` enthält Legacy-/Fallback-Pfade ohne Magic-Header; bei nicht-seekbaren Streams werden Teilpuffer zusammengesetzt. Funktional, aber zusätzliche Validierung/Längenobergrenzen reduzieren DoS-/Korruptionsrisiken (`length` aus der Datei steuert eine Pufferallokation).

---

## Positiv hervorzuheben (was gut gemacht ist)

- **AES-256-GCM (AEAD)** für alle ruhenden Daten – authentifizierte Verschlüsselung, kein selbstgebautes CBC bei den Tresoren.
- **Pro Geheimnis zufälliges Salt** und **CSPRNG** (`RandomNumberGenerator`) für Salts, Nonces, MEK und TOTP-Master-Key.
- **Zeitkonstanter Vergleich** (`CryptographicOperations.FixedTimeEquals`) bei der Passwortprüfung.
- **Zwei-Schichten-Verschlüsselung** bei aktiviertem App-Lock (Tresorschlüssel + MEK).
- **Hardwaregestützte Android-Biometrie** mit `SetUserAuthenticationRequired` und Invalidierung bei neuer Biometrie-Registrierung.
- **Keine Geheimnisse im Repository** (keine Keystores/Zertifikate/PFX) und **kein Logging** von Passwörtern/Schlüsseln.

---

## Priorisierte Maßnahmenliste

1. **(H1)** Passwort-Generator auf `RandomNumberGenerator` umstellen; 32-Bit-Seed-Modus entfernen oder kryptografisch korrekt deterministisch machen.
2. **(H2)** `android:allowBackup="false"` bzw. Backup-Ausschlussregeln setzen.
3. **(H3)** `FLAG_SECURE` und blickdichtes Hintergrund-Overlay für sensible Seiten.
4. **(M1)** Argon2id einführen (oder PBKDF2 ≥ 600.000) mit versionierter Migration.
5. **(M2/M3)** Brute-Force-Bremse + Master-Passwort-Richtlinie (Mindestlänge/Stärke).
6. **(M4)** Zwischenablage automatisch leeren + als sensibel markieren.
7. **(M5/M6)** Biometrie-Wrapping auf AEAD + Windows-TPM-KSP; iOS-Klartextpfad beheben.
8. **(L1–L9)** Schlüsseltrennung via HKDF, AAD-Bindung, Speicherhygiene, konfigurierbares Timeout, generische Fehlermeldungen.
