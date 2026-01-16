# Password Phrase Producer

A cross-platform .NET MAUI application that helps you **create strong passwords and passphrases**, manage secure vaults, and run a built-in authenticator. It blends multiple deterministic and random generation techniques with an entropy analyzer, while keeping sensitive data encrypted at rest and optionally protected by biometrics.

---

## ✨ Highlights

- **Multi-mode password & passphrase generator** with an entropy analyzer and guided suggestions.
- **Password Vault** for login credentials (encrypted at rest, optional biometrics).
- **Data Vault** for additional secure entries (separate encrypted store).
- **Authenticator (TOTP)** with manual entry or QR scanning.
- **Encrypted sync file** for merging vault/authenticator data across devices.
- **Cross-platform UI** built with .NET MAUI for Android, iOS, macOS (Catalyst), and Windows.

---

## 🔐 Password generation modes

The app ships with a catalog of generation techniques. Each mode has a dedicated UI and runs through the same entropy analysis pipeline.

- **1 Word Password** – deterministic hash for a single word.
- **Alternate Words** – alternating word concatenation.
- **TBV1 / TBV1 With Errors / TBV2 / TBV3** – triple verification patterns with different safety levels.
- **Mirror Lock** – mirrored phrase with a checksum.
- **Segment Rotation** – rotate text segments for structural variation.
- **Diceware Seeded** – diceware phrases with optional deterministic seed.
- **Symbol Mixer** – inject symbols and tune capitalization.
- **Pattern Cascade** – repeatable word/number cascades.
- **Caesar Cipher** – classic Caesar shift ciphering.
- **Random Password** – configurable random characters and length.
- **Base64 Encoder** – Base64 encoding for passwords.
- **Word Substitution** – leet-style and smart substitutions.

---

## 🧠 Entropy analysis

Every generated password/phrase is evaluated with an entropy analyzer that considers length, character set size, and variety. The analyzer returns:

- **Entropy and score**
- **Strength label**
- **Suggested improvements**

---

## 🗃️ Vaults & security

The app offers two separate encrypted vaults:

- **Password Vault** – store credentials with category filtering, search, and biometric unlock.
- **Data Vault** – store other secure items in a separate encrypted store.

Security highlights:

- **PBKDF2** with a high iteration count for master keys.
- **AES-GCM encryption** for vault files, TOTP secrets, and sync content.
- Optional **biometric unlock** (per vault or at the app-lock layer).

---

## 🔑 Authenticator (TOTP)

The authenticator module supports:

- **Time-based one-time passwords (TOTP)**
- **Manual entry** (issuer, account, secret)
- **QR scanning** via the camera

---

## 🔄 Encrypted sync file

Synchronization is built around a single encrypted file that contains:

- Password Vault entries
- Data Vault entries
- Authenticator entries

The file is encrypted with an AES-GCM key derived from a sync password, allowing you to place it in a cloud-synced folder and merge changes across devices safely.

---

## 🧰 Tech stack

- **.NET MAUI** single-project app
- **Otp.NET** for TOTP
- **ZXing + Camera.MAUI** for QR scanning
- **CommunityToolkit.Maui** for UI helpers

---

## 🏗️ Build & run

> Note: You need the **.NET 9 SDK** and the **MAUI workload** for your target platform(s).

```bash
# Restore and build the MAUI app
DOTNET_CLI_TELEMETRY_OPTOUT=1 dotnet build "Password Phrase Producer/PasswordPhraseProducer.csproj"
```

### Platform examples

```bash
# Android
DOTNET_CLI_TELEMETRY_OPTOUT=1 dotnet build "Password Phrase Producer/PasswordPhraseProducer.csproj" -f net9.0-android

# Windows (only on Windows hosts)
DOTNET_CLI_TELEMETRY_OPTOUT=1 dotnet build "Password Phrase Producer/PasswordPhraseProducer.csproj" -f net9.0-windows10.0.19041.0
```

---

## 📦 Continuous delivery packages

The GitHub Actions workflow produces installable artifacts for **Android** and **Windows**.

### Android (APK)

To receive an installable and updatable APK you must provide a persistent Android keystore through encrypted GitHub secrets:

| Secret | Description |
| --- | --- |
| `ANDROID_KEYSTORE_BASE64` | Base64 encoded keystore file. |
| `ANDROID_KEYSTORE_PASSWORD` | Password used to protect the keystore. |
| `ANDROID_KEY_ALIAS` | Alias of the key used for signing. |
| `ANDROID_KEY_PASSWORD` | Password for the signing key. |

The workflow restores the keystore, signs the APK during `dotnet publish`, and increments both the display and internal version numbers so that newer builds can be installed as updates on devices.

### Windows (portable ZIP)

Windows builds are published as self-contained, portable bundles. The workflow zips the published output (`Password Phrase Producer.exe` plus all required dependencies) into a single archive named `Password-Phrase-Producer_<version>_windows_x64_portable.zip`. Users simply extract the ZIP and launch the executable—no installer or code-signing certificate is required.

### Versioning

Both Android and Windows builds derive their version numbers from the GitHub Actions run number (`1.0.<run_number>`), allowing each build to install as an update without removing the previous version.

---

## 📁 Project structure

```
Password Phrase Producer/
├── PasswordGenerationTechniques/  # Generators + techniques
├── Services/                      # Vaults, security, sync, entropy
├── ViewModels/                    # MVVM logic
├── Views/                         # XAML UI
├── Models/                        # Data models and DTOs
└── Resources/                     # App icons, fonts, images
```

---

## 📝 License

This project is licensed under the terms of the repository's license file.
