using System.Collections.Generic;

namespace Password_Phrase_Producer.Services.Security;

public class TotpSnapshotDto
{
    public List<TotpEntryDto> Entries { get; set; } = new();
    public DateTimeOffset ExportedAt { get; set; }
}
