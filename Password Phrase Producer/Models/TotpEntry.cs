using System;

namespace Password_Phrase_Producer.Models;

public enum TotpAlgorithm
{
    Sha1,
    Sha256,
    Sha512
}

public class TotpEntry
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Issuer { get; set; } = string.Empty;
    public string AccountName { get; set; } = string.Empty;
    public byte[]? Secret { get; set; }
    public TotpAlgorithm Algorithm { get; set; } = TotpAlgorithm.Sha1;
    public int Digits { get; set; } = 6;
    public int Period { get; set; } = 30;
    public DateTimeOffset ModifiedAt { get; set; } = DateTimeOffset.UtcNow;
}
