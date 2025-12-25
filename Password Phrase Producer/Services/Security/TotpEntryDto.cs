using System;
using Password_Phrase_Producer.Models;

namespace Password_Phrase_Producer.Services.Security;

public class TotpEntryDto
{
    public Guid Id { get; set; }
    public string Issuer { get; set; } = string.Empty;
    public string AccountName { get; set; } = string.Empty;
    public string Secret { get; set; } = string.Empty;
    public string Algorithm { get; set; } = "Sha1";
    public int Digits { get; set; } = 6;
    public int Period { get; set; } = 30;
    public DateTimeOffset ModifiedAt { get; set; }

    public static TotpEntryDto FromModel(TotpEntry model)
    {
        return new TotpEntryDto
        {
            Id = model.Id,
            Issuer = model.Issuer,
            AccountName = model.AccountName,
            Secret = model.Secret != null ? Convert.ToBase64String(model.Secret) : string.Empty,
            Algorithm = model.Algorithm.ToString(),
            Digits = model.Digits,
            Period = model.Period,
            ModifiedAt = model.ModifiedAt
        };
    }

    public TotpEntry ToModel()
    {
        return new TotpEntry
        {
            Id = Id,
            Issuer = Issuer,
            AccountName = AccountName,
            Secret = !string.IsNullOrEmpty(Secret) ? Convert.FromBase64String(Secret) : null,
            Algorithm = Enum.TryParse<TotpAlgorithm>(Algorithm, out var alg) ? alg : TotpAlgorithm.Sha1,
            Digits = Digits,
            Period = Period,
            ModifiedAt = ModifiedAt
        };
    }
}
