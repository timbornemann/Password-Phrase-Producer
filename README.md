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

### Windows (MSIX)

Windows artifacts are now delivered as a single MSIX package that supports updating without manual uninstalling. Provide a code-signing certificate by configuring the following secrets:

| Secret | Description |
| --- | --- |
| `WINDOWS_PFX_BASE64` | Base64 encoded `.pfx` certificate used to sign the MSIX. Ensure that the subject matches `CN=Password Phrase Producer` so that it aligns with the package manifest. |
| `WINDOWS_PFX_PASSWORD` | Password that protects the certificate. |

If the certificate is absent the workflow still produces an unsigned MSIX, which Windows will require you to trust manually before installing.

### Versioning

Both Android and Windows builds derive their version numbers from the GitHub Actions run number (`1.0.<run_number>`), allowing each build to install as an update without removing the previous version.
