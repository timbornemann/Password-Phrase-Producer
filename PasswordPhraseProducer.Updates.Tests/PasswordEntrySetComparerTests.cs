using Password_Phrase_Producer.Models;
using Password_Phrase_Producer.Services.Synchronization;
using Xunit;

namespace PasswordPhraseProducer.Updates.Tests;

public class PasswordEntrySetComparerTests
{
    [Fact]
    public void UnchangedEntriesWithDifferentOrderNeedNoWrite()
    {
        var first = Entry();
        var second = Entry();
        Assert.True(PasswordEntrySetComparer.AreEquivalent(
            [first, second], [second.Clone(), first.Clone()]));
    }

    [Fact]
    public void PasswordOrDeletionChangesRequireWrite()
    {
        var original = Entry();
        var passwordChanged = original.Clone();
        passwordChanged.Password = "different";
        var deleted = original.Clone();
        deleted.IsDeleted = true;

        Assert.False(PasswordEntrySetComparer.AreEquivalent([original], [passwordChanged]));
        Assert.False(PasswordEntrySetComparer.AreEquivalent([original], [deleted]));
    }

    private static PasswordVaultEntry Entry() => new()
    {
        Id = Guid.NewGuid(),
        Label = "Example",
        Username = "user",
        Password = "secret",
        ModifiedAt = DateTimeOffset.UtcNow
    };
}
