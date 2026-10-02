using System.Text.Json;
using Password_Phrase_Producer.Models;
using Password_Phrase_Producer.Services.Security;
using Password_Phrase_Producer.Services.Storage;

namespace Password_Phrase_Producer.Services.LocalTransfer;

internal sealed record LocalBackupContents(bool PasswordVault, bool DataVault, bool Authenticator)
{
    internal string Description => string.Join(", ", new[]
    {
        PasswordVault ? "Passwort-Tresor" : null,
        DataVault ? "Datentresor" : null,
        Authenticator ? "Authenticator" : null
    }.Where(value => value is not null));
}

internal static class LocalBackupVerifier
{
    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true
    };

    internal static LocalBackupContents Verify(byte[] data, string phrase)
    {
        if (data.Length is < 1 or > BackupInput.MaxBytes)
            throw new InvalidDataException("Die Sicherung ist leer oder größer als 128 MiB.");
        var backup = JsonSerializer.Deserialize<FullBackupDto>(data, Options)
                     ?? throw new InvalidDataException("Ungültiges Gesamtbackup.");
        if (backup.Version != 3)
            throw new InvalidDataException("Lokaler Transfer akzeptiert nur Gesamtbackup-Version 3.");
        FullBackupIntegrity.Verify(backup, phrase, Options);

        if (backup.PasswordVault is not null)
            BackupInput.VerifyDecryptable(backup.PasswordVault, phrase, bytes =>
            {
                var snapshot = JsonSerializer.Deserialize<PasswordVaultSnapshotDto>(bytes, Options);
                if (snapshot?.Entries is null) throw new InvalidDataException("Ungültiger Passwort-Tresor-Snapshot.");
                foreach (var entry in snapshot.Entries) _ = entry.ToModel();
            });
        if (backup.DataVault is not null)
            BackupInput.VerifyDecryptable(backup.DataVault, phrase, bytes =>
            {
                var snapshot = JsonSerializer.Deserialize<PasswordVaultSnapshotDto>(bytes, Options);
                if (snapshot?.Entries is null) throw new InvalidDataException("Ungültiger Datentresor-Snapshot.");
                foreach (var entry in snapshot.Entries) _ = entry.ToModel();
            });
        if (backup.AuthenticatorEncrypted is not null)
            BackupInput.VerifyDecryptable(backup.AuthenticatorEncrypted, phrase, bytes =>
            {
                var snapshot = JsonSerializer.Deserialize<TotpSnapshotDto>(bytes, Options);
                if (snapshot?.Entries is null) throw new InvalidDataException("Ungültiger Authenticator-Snapshot.");
                foreach (var entry in snapshot.Entries) _ = entry.ToModel();
            });

        return new LocalBackupContents(backup.PasswordVault is not null, backup.DataVault is not null,
            backup.AuthenticatorEncrypted is not null);
    }
}
