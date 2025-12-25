namespace Password_Phrase_Producer.Models;

public class PortableBackupDto
{
    public string Salt { get; set; } = string.Empty;

    public string Verifier { get; set; } = string.Empty;

    public int Iterations { get; set; }

    public string CipherText { get; set; } = string.Empty;

    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
}

