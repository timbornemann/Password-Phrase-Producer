namespace Password_Phrase_Producer.Models;

public class PasswordVaultBackupDto
{
    public string CipherText { get; set; } = string.Empty;

    public string PasswordSalt { get; set; } = string.Empty;

    public string PasswordVerifier { get; set; } = string.Empty;

    public int Pbkdf2Iterations { get; set; }

    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
}
