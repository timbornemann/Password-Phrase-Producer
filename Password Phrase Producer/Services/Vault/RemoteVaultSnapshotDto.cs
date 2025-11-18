using System;
using System.Collections.Generic;
using Password_Phrase_Producer.Models;

namespace Password_Phrase_Producer.Services.Vault;

public sealed class RemoteVaultSnapshotDto
{
    public int Version { get; init; } = 1;

    public DateTimeOffset ExportedAt { get; init; } = DateTimeOffset.UtcNow;

    public List<PasswordVaultEntryDto> Entries { get; set; } = new();
}
