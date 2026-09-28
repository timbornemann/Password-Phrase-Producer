# Windows installation

Download the `*-Setup.exe` from the latest GitHub release and run it as your normal Windows user.
The installer contains the required .NET and Windows App SDK runtimes. An administrator account is not required.

After the initial installation, use **Einstellungen → App-Updates → Aktualisieren und neu starten**.
Updates only replace program files. They do not uninstall the app or remove its data.

The program is installed under `%LOCALAPPDATA%\Timbornemann.PasswordPhraseProducer`.
Existing data stays under `%LOCALAPPDATA%\Password Phrase Producer\com.passwordphraseproducer.app`.
Preserve both `Data` and `Settings`; the latter contains the protected keys needed to read the vault files.

Users of the former portable ZIP or PowerShell installer should close the old app and run the new Setup once.
The new version uses the existing data automatically. Do not run the retired uninstall script for an update.
The new Start menu shortcut replaces the previous shortcut; old extracted program folders are no longer needed.

The historical MSIX package has a separate Windows storage identity. Export from that installation before
switching and import into the new Setup installation. Do not uninstall MSIX until the import has been verified.

If an interrupted update damages program files, run the same or a newer Setup again to repair the installation.
Keep the data directory intact. Setup may display a SmartScreen prompt because Authenticode signing is optional.

See [release and recovery documentation](../UPDATES.md).
