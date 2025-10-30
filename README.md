# Password-Phrase-Producer

A versatile tool for generating secure passwords with various customizable modes, including complex patterns based on user input.

## Continuous delivery packages

The GitHub Actions workflow now produces installable artifacts for Android and Windows that can be updated in-place as long as the signing material stays the same.

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
