using Password_Phrase_Producer.Models;

namespace Password_Phrase_Producer.Services.Synchronization;

internal static class PasswordEntrySetComparer
{
    internal static bool AreEquivalent(IList<PasswordVaultEntry> first, IList<PasswordVaultEntry> second)
    {
        if (first.Count != second.Count) return false;

        var byId = new Dictionary<Guid, PasswordVaultEntry>(first.Count);
        foreach (var entry in first)
        {
            if (!byId.TryAdd(entry.Id, entry)) return false;
        }

        var seen = new HashSet<Guid>();
        foreach (var entry in second)
        {
            if (!seen.Add(entry.Id) ||
                !byId.TryGetValue(entry.Id, out var other) ||
                entry.ModifiedAt != other.ModifiedAt ||
                entry.IsDeleted != other.IsDeleted ||
                entry.Label != other.Label ||
                entry.Username != other.Username ||
                entry.Password != other.Password ||
                entry.Category != other.Category ||
                entry.Url != other.Url ||
                entry.Notes != other.Notes ||
                entry.FreeText != other.FreeText)
            {
                return false;
            }
        }

        return true;
    }
}
