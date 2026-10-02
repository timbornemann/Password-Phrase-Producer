using Password_Phrase_Producer.Models;

namespace Password_Phrase_Producer.Services.Security;

internal static class TotpEntrySetComparer
{
    internal static bool AreEquivalent(IList<TotpEntry> first, IList<TotpEntry> second)
    {
        if (first.Count != second.Count) return false;

        var byId = new Dictionary<Guid, TotpEntry>(first.Count);
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
                entry.Issuer != other.Issuer ||
                entry.AccountName != other.AccountName ||
                entry.Algorithm != other.Algorithm ||
                entry.Digits != other.Digits ||
                entry.Period != other.Period ||
                !(entry.Secret ?? Array.Empty<byte>()).AsSpan()
                    .SequenceEqual(other.Secret ?? Array.Empty<byte>()))
            {
                return false;
            }
        }

        return true;
    }
}
