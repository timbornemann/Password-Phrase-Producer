using System;
using System.Collections.Generic;
using System.Linq;

namespace Password_Phrase_Producer.Services.Vault;

/// <summary>
/// Interface for entities that can be identified by a unique ID.
/// </summary>
public interface IIdentifiable
{
    Guid Id { get; }
}

/// <summary>
/// Interface for entities that have a modification timestamp.
/// </summary>
public interface ITimestamped
{
    DateTimeOffset ModifiedAt { get; }
}

/// <summary>
/// Result of a merge operation.
/// </summary>
public class MergeResult<T>
{
    public List<T> MergedEntries { get; set; } = new();
    public int AddedCount { get; set; }
    public int UpdatedCount { get; set; }
    public int UnchangedCount { get; set; }
}

/// <summary>
/// Service for merging vault entries with intelligent conflict resolution.
/// </summary>
public class VaultMergeService
{
    /// <summary>
    /// Merges incoming entries with existing entries based on ID and modification timestamp.
    /// </summary>
    /// <typeparam name="T">Type that implements both IIdentifiable and ITimestamped</typeparam>
    /// <param name="existing">Current entries in the vault</param>
    /// <param name="incoming">Entries to merge from import</param>
    /// <returns>Merge result containing the merged list and statistics</returns>
    public MergeResult<T> MergeEntries<T>(IList<T> existing, IList<T> incoming)
        where T : IIdentifiable, ITimestamped
    {
        var result = new MergeResult<T>();
        
        // Handle null or empty inputs defensively
        if (existing is null || existing.Count == 0)
        {
            // No existing entries - just add all incoming entries
            result.MergedEntries.AddRange(incoming ?? new List<T>());
            result.AddedCount = incoming?.Count ?? 0;
            return result;
        }
        
        if (incoming is null || incoming.Count == 0)
        {
            // No incoming entries - keep all existing entries
            result.MergedEntries.AddRange(existing);
            result.UnchangedCount = existing.Count;
            return result;
        }
        
        // Build dictionary of existing entries, handling potential duplicates by keeping the first occurrence
        var existingDict = new Dictionary<Guid, T>();
        foreach (var entry in existing)
        {
            if (!existingDict.ContainsKey(entry.Id))
            {
                existingDict[entry.Id] = entry;
            }
        }
        
        var processedIds = new HashSet<Guid>();

        // Process incoming entries
        foreach (var incomingEntry in incoming)
        {
            processedIds.Add(incomingEntry.Id);

            if (existingDict.TryGetValue(incomingEntry.Id, out var existingEntry))
            {
                // Entry exists in both - compare timestamps
                if (incomingEntry.ModifiedAt > existingEntry.ModifiedAt)
                {
                    // Incoming is newer - use incoming
                    result.MergedEntries.Add(incomingEntry);
                    result.UpdatedCount++;
                }
                else
                {
                    // Existing is same or newer - keep existing
                    result.MergedEntries.Add(existingEntry);
                    result.UnchangedCount++;
                }
            }
            else
            {
                // New entry - add it
                result.MergedEntries.Add(incomingEntry);
                result.AddedCount++;
            }
        }

        // Add entries that only exist in existing (not in incoming)
        foreach (var existingEntry in existing)
        {
            if (!processedIds.Contains(existingEntry.Id))
            {
                result.MergedEntries.Add(existingEntry);
                result.UnchangedCount++;
            }
        }

        return result;
    }

    /// <summary>
    /// Simple merge for entities without the full interface - uses Func delegates for property access.
    /// </summary>
    public MergeResult<T> MergeEntries<T>(
        IList<T> existing,
        IList<T> incoming,
        Func<T, Guid> idSelector,
        Func<T, DateTimeOffset> timestampSelector)
    {
        var result = new MergeResult<T>();
        
        // Handle null or empty inputs defensively
        if (existing is null || existing.Count == 0)
        {
            // No existing entries - just add all incoming entries
            result.MergedEntries.AddRange(incoming ?? new List<T>());
            result.AddedCount = incoming?.Count ?? 0;
            return result;
        }
        
        if (incoming is null || incoming.Count == 0)
        {
            // No incoming entries - keep all existing entries
            result.MergedEntries.AddRange(existing);
            result.UnchangedCount = existing.Count;
            return result;
        }
        
        // Build dictionary of existing entries, handling potential duplicates by keeping the first occurrence
        var existingDict = new Dictionary<Guid, T>();
        foreach (var entry in existing)
        {
            var id = idSelector(entry);
            if (!existingDict.ContainsKey(id))
            {
                existingDict[id] = entry;
            }
        }
        
        var processedIds = new HashSet<Guid>();

        foreach (var incomingEntry in incoming)
        {
            var id = idSelector(incomingEntry);
            processedIds.Add(id);

            if (existingDict.TryGetValue(id, out var existingEntry))
            {
                if (timestampSelector(incomingEntry) > timestampSelector(existingEntry))
                {
                    result.MergedEntries.Add(incomingEntry);
                    result.UpdatedCount++;
                }
                else
                {
                    result.MergedEntries.Add(existingEntry);
                    result.UnchangedCount++;
                }
            }
            else
            {
                result.MergedEntries.Add(incomingEntry);
                result.AddedCount++;
            }
        }

        foreach (var existingEntry in existing)
        {
            if (!processedIds.Contains(idSelector(existingEntry)))
            {
                result.MergedEntries.Add(existingEntry);
                result.UnchangedCount++;
            }
        }

        return result;
    }
}

