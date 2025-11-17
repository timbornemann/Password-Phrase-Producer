using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using Password_Phrase_Producer.Models;
using Password_Phrase_Producer.Services.Vault;
using Xunit;

namespace Password_Phrase_Producer.Tests.Remote;

public class RemoteVaultSyncFlowTests
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true
    };

    [Fact]
    public void SyncAcrossTwoDevices_MergesChangesBothWays()
    {
        const string remotePassword = "remote-sync-pass";
        const int iterations = 12_000;
        const int keySizeBytes = 32;

        var deviceAEntries = new List<PasswordVaultEntry>
        {
            new()
            {
                Id = Guid.NewGuid(),
                Label = "Mail",
                Username = "a@example.com",
                Password = "mail-a",
                Category = "Comms",
                ModifiedAt = DateTimeOffset.UtcNow.AddMinutes(-30)
            },
            new()
            {
                Id = Guid.NewGuid(),
                Label = "Cloud",
                Username = "cloudA",
                Password = "cloud-a",
                Category = "Storage",
                ModifiedAt = DateTimeOffset.UtcNow.AddMinutes(-20)
            }
        };

        // Device A uploads
        var packageFromA = CreatePackage(deviceAEntries, remotePassword, iterations, keySizeBytes, seed: 1);

        // Device B downloads and merges
        var deviceBEntries = new List<PasswordVaultEntry>();
        ApplyPackage(deviceBEntries, packageFromA, remotePassword, iterations, keySizeBytes);

        // Device B changes one entry and adds another
        deviceBEntries[0].Password = "mail-a-updated";
        deviceBEntries[0].ModifiedAt = DateTimeOffset.UtcNow.AddMinutes(-5);
        deviceBEntries.Add(new PasswordVaultEntry
        {
            Id = Guid.NewGuid(),
            Label = "Notes",
            Username = "note-b",
            Password = "notes-pass",
            Category = "Productivity",
            ModifiedAt = DateTimeOffset.UtcNow.AddMinutes(-2)
        });

        var packageFromB = CreatePackage(deviceBEntries, remotePassword, iterations, keySizeBytes, seed: 2);

        // Device A downloads B's changes
        ApplyPackage(deviceAEntries, packageFromB, remotePassword, iterations, keySizeBytes);

        Assert.Equal(deviceBEntries.Count, deviceAEntries.Count);

        foreach (var entry in deviceAEntries)
        {
            var counterpart = deviceBEntries.Single(e => e.Id == entry.Id);
            Assert.Equal(counterpart.Label, entry.Label);
            Assert.Equal(counterpart.Username, entry.Username);
            Assert.Equal(counterpart.Password, entry.Password);
            Assert.Equal(counterpart.Category, entry.Category);
            Assert.Equal(counterpart.ModifiedAt.ToUniversalTime(), entry.ModifiedAt.ToUniversalTime());
        }
    }

    private static byte[] CreatePackage(IEnumerable<PasswordVaultEntry> entries, string password, int iterations, int keySizeBytes, int seed)
    {
        var ordered = entries
            .OrderBy(e => e.DisplayCategory, StringComparer.CurrentCultureIgnoreCase)
            .ThenBy(e => e.Label, StringComparer.CurrentCultureIgnoreCase)
            .Select(PasswordVaultEntryDto.FromModel)
            .ToList();
        var snapshot = new RemoteVaultSnapshotDto { Entries = ordered };
        var salt = Enumerable.Range(0, 16).Select(i => (byte)(i + seed)).ToArray();
        return RemoteVaultPackageHelper.CreatePackage(snapshot, password, iterations, salt.Length, keySizeBytes, JsonOptions, salt);
    }

    private static void ApplyPackage(IList<PasswordVaultEntry> localEntries, byte[] package, string password, int iterations, int keySizeBytes)
    {
        var snapshot = RemoteVaultPackageHelper.DecryptPackage(package, password, iterations, keySizeBytes, JsonOptions);
        RemoteVaultEntryMerger.MergeInPlace(localEntries, snapshot.Entries ?? Array.Empty<PasswordVaultEntryDto>());
    }
}
