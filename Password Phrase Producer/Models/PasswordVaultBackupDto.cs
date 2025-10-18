namespace Password_Phrase_Producer.Models;

public class PasswordVaultBackupDto
{
    public string EncryptionKey { get; set; } = string.Empty;

    public string FileName { get; set; } = "vault.json.enc";

    public string CipherText { get; set; } = string.Empty;

    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
}
