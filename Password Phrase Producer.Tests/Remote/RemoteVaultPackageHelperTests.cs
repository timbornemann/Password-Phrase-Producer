using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using Password_Phrase_Producer.Models;
using Password_Phrase_Producer.Services.Vault;
using Xunit;

namespace Password_Phrase_Producer.Tests.Remote;

public class RemoteVaultPackageHelperTests
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true
    };

    [Fact]
    public void CreateAndDecryptPackage_RoundTripsSnapshot()
    {
        var snapshot = new RemoteVaultSnapshotDto
        {
            Entries = new List<PasswordVaultEntryDto>
            {
                new()
                {
                    Id = Guid.NewGuid(),
                    Label = "Email",
                    Username = "user@example.com",
                    Password = "secret1",
                    Category = "Work",
                    ModifiedAt = DateTimeOffset.UtcNow.AddMinutes(-10)
                },
                new()
                {
                    Id = Guid.NewGuid(),
                    Label = "Bank",
                    Username = "acc01",
                    Password = "secret2",
                    Category = "Finance",
                    ModifiedAt = DateTimeOffset.UtcNow.AddMinutes(-5)
                }
            }
        };

        var deterministicSalt = Enumerable.Range(0, 16).Select(i => (byte)i).ToArray();
        var package = RemoteVaultPackageHelper.CreatePackage(snapshot, "remote-pass", iterations: 10_000, saltSizeBytes: 16, keySizeBytes: 32, JsonOptions, deterministicSalt);
        var roundTripped = RemoteVaultPackageHelper.DecryptPackage(package, "remote-pass", defaultIterations: 10_000, keySizeBytes: 32, JsonOptions);

        Assert.Equal(snapshot.Entries.Count, roundTripped.Entries.Count);

        for (var i = 0; i < snapshot.Entries.Count; i++)
        {
            Assert.Equal(snapshot.Entries[i].Id, roundTripped.Entries[i].Id);
            Assert.Equal(snapshot.Entries[i].Label, roundTripped.Entries[i].Label);
            Assert.Equal(snapshot.Entries[i].Username, roundTripped.Entries[i].Username);
            Assert.Equal(snapshot.Entries[i].Password, roundTripped.Entries[i].Password);
            Assert.Equal(snapshot.Entries[i].Category, roundTripped.Entries[i].Category);
            Assert.Equal(snapshot.Entries[i].ModifiedAt.ToUniversalTime(), roundTripped.Entries[i].ModifiedAt.ToUniversalTime());
        }
    }
}
