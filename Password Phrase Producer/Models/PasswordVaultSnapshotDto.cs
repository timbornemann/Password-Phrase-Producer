using System.Collections.Generic;

namespace Password_Phrase_Producer.Models;

public class PasswordVaultSnapshotDto
{
    public IList<PasswordVaultEntryDto> Entries { get; set; } = new List<PasswordVaultEntryDto>();

    public DateTimeOffset ExportedAt { get; set; } = DateTimeOffset.UtcNow;
}
