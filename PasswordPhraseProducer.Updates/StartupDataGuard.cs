using System.Text.Json;

namespace PasswordPhraseProducer.Updates;

public static class StartupDataGuard
{
    public static readonly string[] DataFiles = ["vault.json.enc", "data-vault.json.enc", "totp_data.json.enc", "totp.key"];

    public static void RequireNewStore(string path)
    {
        if (File.Exists(path))
            throw new InvalidDataException("Vorhandene Tresordaten dürfen nicht durch eine neue Einrichtung ersetzt werden. Bitte stelle die fehlenden Schlüssel aus einer Sicherung wieder her.");
    }

    public static async Task VerifyAsync(string dataDirectory, Func<string, Task<string?>> readSecureValue)
    {
        var metadata = await readSecureValue("AppLockMetadata_V1");
        var hasFiles = DataFiles.Any(name => File.Exists(Path.Combine(dataDirectory, name)));
        if (string.IsNullOrEmpty(metadata))
        {
            if (hasFiles) throw new InvalidDataException("Vorhandene Daten können ohne die App-Schlüssel nicht geöffnet werden.");
            return;
        }
        try
        {
            using var json = JsonDocument.Parse(metadata);
            foreach (var key in new[] { "Salt", "Verifier", "EncryptedMasterKey" })
                if (Convert.FromBase64String(json.RootElement.GetProperty(key).GetString()!).Length == 0)
                    throw new FormatException();
            if (json.RootElement.GetProperty("Iterations").GetInt32() <= 0) throw new FormatException();
            if (File.Exists(Path.Combine(dataDirectory, "totp_data.json.enc")) && !File.Exists(Path.Combine(dataDirectory, "totp.key")))
                throw new FormatException();
            // V2 stores the password metadata in totp.key so a password change
            // cannot strand the encrypted key between separate writes.
        }
        catch (Exception ex) when (ex is JsonException or FormatException or KeyNotFoundException or InvalidOperationException or ArgumentException)
        {
            throw new InvalidDataException("Die gespeicherten Schlüsselmetadaten sind unvollständig oder beschädigt.", ex);
        }
    }
}
