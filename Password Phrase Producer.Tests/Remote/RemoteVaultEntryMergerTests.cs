using System;
using System.Collections.Generic;
using Password_Phrase_Producer.Models;
using Password_Phrase_Producer.Services.Vault;
using Xunit;

namespace Password_Phrase_Producer.Tests.Remote;

public class RemoteVaultEntryMergerTests
{
    [Fact]
    public void MergeInPlace_PrefersNewerRemoteEntries()
    {
        var entryId = Guid.NewGuid();
        var localEntries = new List<PasswordVaultEntry>
        {
            new()
            {
                Id = entryId,
                Label = "Portal",
                Username = "local",
                Password = "old",
                Category = "Apps",
                ModifiedAt = DateTimeOffset.UtcNow.AddHours(-2)
            }
        };

        var remoteEntries = new List<PasswordVaultEntryDto>
        {
            new()
            {
                Id = entryId,
                Label = "Portal",
                Username = "remote",
                Password = "new",
                Category = "Apps",
                ModifiedAt = DateTimeOffset.UtcNow
            },
            new()
            {
                Id = Guid.NewGuid(),
                Label = "Added",
                Username = "fresh",
                Password = "fresh-pass",
                Category = "Misc",
                ModifiedAt = DateTimeOffset.UtcNow
            }
        };

        var changes = RemoteVaultEntryMerger.MergeInPlace(localEntries, remoteEntries);

        Assert.Equal(2, changes);
        Assert.Equal(2, localEntries.Count);
        Assert.Equal("remote", localEntries[0].Username);
        Assert.Equal("new", localEntries[0].Password);
        Assert.Contains(localEntries, entry => entry.Label == "Added");
    }
}
