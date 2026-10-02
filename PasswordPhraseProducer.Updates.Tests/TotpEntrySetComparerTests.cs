using Password_Phrase_Producer.Models;
using Password_Phrase_Producer.Services.Security;
using Xunit;

namespace PasswordPhraseProducer.Updates.Tests;

public class TotpEntrySetComparerTests
{
    [Fact]
    public void SameEntriesInDifferentOrderNeedNoWrite()
    {
        var first = Entry();
        var second = Entry();
        Assert.True(TotpEntrySetComparer.AreEquivalent(
            [first, second], [Clone(second), Clone(first)]));
    }

    [Fact]
    public void SecretAndTombstoneChangesRequireWrite()
    {
        var original = Entry();
        var changedSecret = Clone(original);
        changedSecret.Secret![0] ^= 1;
        var deleted = Clone(original);
        deleted.IsDeleted = true;

        Assert.False(TotpEntrySetComparer.AreEquivalent([original], [changedSecret]));
        Assert.False(TotpEntrySetComparer.AreEquivalent([original], [deleted]));
    }

    [Fact]
    public void DuplicateIdsRequireWrite()
    {
        var first = Entry();
        var second = Entry();
        Assert.False(TotpEntrySetComparer.AreEquivalent(
            [first, second], [Clone(first), Clone(first)]));
    }

    private static TotpEntry Entry() => new()
    {
        Id = Guid.NewGuid(),
        Issuer = "Example",
        AccountName = "user",
        Secret = [1, 2, 3, 4],
        ModifiedAt = DateTimeOffset.UtcNow
    };

    private static TotpEntry Clone(TotpEntry entry) => new()
    {
        Id = entry.Id,
        Issuer = entry.Issuer,
        AccountName = entry.AccountName,
        Secret = entry.Secret?.ToArray(),
        Algorithm = entry.Algorithm,
        Digits = entry.Digits,
        Period = entry.Period,
        ModifiedAt = entry.ModifiedAt,
        IsDeleted = entry.IsDeleted
    };
}
