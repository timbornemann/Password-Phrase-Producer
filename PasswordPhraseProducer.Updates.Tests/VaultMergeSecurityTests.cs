using Password_Phrase_Producer.Services.Vault;
using Xunit;

namespace PasswordPhraseProducer.Updates.Tests;

public sealed class VaultMergeSecurityTests
{
    [Fact]
    public void DuplicateIdsFromBackupKeepOnlyNewestEntry()
    {
        var id = Guid.NewGuid();
        var now = DateTimeOffset.UtcNow;
        var existing = new[]
        {
            new TestEntry(id, now.AddHours(-2), "old-local"),
            new TestEntry(id, now.AddHours(-1), "new-local")
        };
        var incoming = new[]
        {
            new TestEntry(id, now.AddMinutes(-30), "new-backup"),
            new TestEntry(id, now.AddHours(-3), "old-backup")
        };

        var result = new VaultMergeService().MergeEntries(existing, incoming);

        Assert.Single(result.MergedEntries);
        Assert.Equal("new-backup", result.MergedEntries[0].Value);
        Assert.Equal(1, result.UpdatedCount);
    }

    private sealed record TestEntry(Guid Id, DateTimeOffset ModifiedAt, string Value) : IIdentifiable, ITimestamped;
}
