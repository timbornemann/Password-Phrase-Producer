using System.Security.Cryptography;
using System.Text.Json;

namespace Password_Phrase_Producer.Services.Security;

// The biometric wrapper must belong to both the current random TOTP master key
// and the current password-protected key file. A password change rebinds it.
public sealed class TotpBiometricKeyRecord
{
    public int Version { get; set; } = 1;
    public string EncryptedKey { get; set; } = string.Empty;
    public string KeyFileHash { get; set; } = string.Empty;
    public string MasterKeyHash { get; set; } = string.Empty;

    public static TotpBiometricKeyRecord Create(byte[] encryptedKey, byte[] keyFile, byte[] masterKey)
    {
        ArgumentNullException.ThrowIfNull(encryptedKey);
        ArgumentNullException.ThrowIfNull(keyFile);
        ArgumentNullException.ThrowIfNull(masterKey);
        if (masterKey.Length != 32 || encryptedKey.Length is < 32 or > 512)
            throw new ArgumentException("Ungültiger Authenticator-Schlüssel.");

        return new TotpBiometricKeyRecord
        {
            EncryptedKey = Convert.ToBase64String(encryptedKey),
            KeyFileHash = Convert.ToBase64String(SHA256.HashData(keyFile)),
            MasterKeyHash = Convert.ToBase64String(SHA256.HashData(masterKey))
        };
    }

    public static bool TryParse(string? json, out TotpBiometricKeyRecord? record)
    {
        record = null;
        if (string.IsNullOrEmpty(json) || json.Length > 4096)
            return false;

        try
        {
            var candidate = JsonSerializer.Deserialize<TotpBiometricKeyRecord>(json);
            if (candidate is null || candidate.Version != 1 ||
                Convert.FromBase64String(candidate.EncryptedKey).Length is < 32 or > 512 ||
                Convert.FromBase64String(candidate.KeyFileHash).Length != 32 ||
                Convert.FromBase64String(candidate.MasterKeyHash).Length != 32)
                return false;
            record = candidate;
            return true;
        }
        catch (Exception ex) when (ex is JsonException or FormatException or ArgumentNullException)
        {
            return false;
        }
    }

    public bool MatchesKeyFile(byte[] keyFile) => MatchesHash(KeyFileHash, keyFile);

    public bool MatchesMasterKey(byte[] masterKey) => masterKey.Length == 32 && MatchesHash(MasterKeyHash, masterKey);

    public void RebindKeyFile(byte[] keyFile) => KeyFileHash = Convert.ToBase64String(SHA256.HashData(keyFile));

    public string Serialize() => JsonSerializer.Serialize(this);

    private static bool MatchesHash(string expectedBase64, byte[] value)
    {
        var expected = Convert.FromBase64String(expectedBase64);
        var actual = SHA256.HashData(value);
        return expected.Length == actual.Length && CryptographicOperations.FixedTimeEquals(expected, actual);
    }
}
