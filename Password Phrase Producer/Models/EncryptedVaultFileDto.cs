using System.Text.Json.Serialization;

namespace Password_Phrase_Producer.Models;

public sealed class EncryptedVaultFileDto
{
    [JsonPropertyName("version")]
    public int Version { get; set; } = 1;

    [JsonPropertyName("cipherText")]
    public string CipherText { get; set; } = string.Empty;

    [JsonPropertyName("passwordSalt")]
    public string? PasswordSalt { get; set; }
        = string.Empty;

    [JsonPropertyName("passwordVerifier")]
    public string? PasswordVerifier { get; set; }
        = string.Empty;

    [JsonPropertyName("pbkdf2Iterations")]
    public int? Pbkdf2Iterations { get; set; } = 200_000;
}
