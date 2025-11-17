using System;
using System.Collections.Generic;
using System.Linq;
using Password_Phrase_Producer.Models;

namespace Password_Phrase_Producer.Services.Vault;

internal static class RemoteVaultEntryMerger
{
    public static int MergeInPlace(IList<PasswordVaultEntry> localEntries, IEnumerable<PasswordVaultEntryDto> remoteEntries)
    {
        ArgumentNullException.ThrowIfNull(localEntries);
        ArgumentNullException.ThrowIfNull(remoteEntries);

        var indexById = localEntries
            .Select((entry, index) => new { entry.Id, Index = index })
            .ToDictionary(x => x.Id, x => x.Index);

        var changes = 0;
        foreach (var dto in remoteEntries)
        {
            if (dto is null)
            {
                continue;
            }

            var remoteModel = dto.ToModel();
            if (indexById.TryGetValue(remoteModel.Id, out var existingIndex))
            {
                if (remoteModel.ModifiedAt > localEntries[existingIndex].ModifiedAt)
                {
                    localEntries[existingIndex] = remoteModel.Clone();
                    changes++;
                }
            }
            else
            {
                localEntries.Add(remoteModel.Clone());
                indexById[remoteModel.Id] = localEntries.Count - 1;
                changes++;
            }
        }

        return changes;
    }
}
