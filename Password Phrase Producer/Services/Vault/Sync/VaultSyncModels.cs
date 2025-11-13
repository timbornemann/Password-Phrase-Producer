using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Password_Phrase_Producer.Services.Vault.Sync;

public enum VaultSyncOperation
{
    None,
    Disabled,
    NoProvider,
    UpToDate,
    Uploaded,
    Downloaded,
    Conflict,
    Error
}

public sealed class VaultSyncRemoteState
{
    public DateTimeOffset LastModifiedUtc { get; set; }

    public string MerkleHash { get; set; } = string.Empty;

    public long ContentLength { get; set; }

    public string? EntityTag { get; set; }
}

public sealed class VaultSyncUploadRequest
{
    public required byte[] Payload { get; init; }

    public required VaultSyncRemoteState LocalState { get; init; }

    public VaultSyncRemoteState? RemoteStateBeforeUpload { get; init; }
}

public sealed class VaultSyncDownloadResult
{
    public required byte[] Payload { get; init; }

    public required VaultSyncRemoteState RemoteState { get; init; }
}

public sealed class VaultSyncResult
{
    public VaultSyncOperation Operation { get; init; }

    public VaultSyncRemoteState? LocalState { get; init; }

    public VaultSyncRemoteState? RemoteState { get; init; }

    public int? DownloadedEntries { get; init; }

    public int? UploadedEntries { get; init; }

    public string? ErrorMessage { get; init; }

    [JsonIgnore]
    public bool Success => Operation is not VaultSyncOperation.Error;
}

public sealed class RemoteVaultValidationResult
{
    public bool RemoteExists { get; init; }

    public bool Success { get; init; }

    public int? EntryCount { get; init; }

    public VaultSyncRemoteState? RemoteState { get; init; }

    public string? ErrorMessage { get; init; }
}

public sealed class VaultSyncConfiguration
{
    public bool IsEnabled { get; set; }

    public bool AutoSyncEnabled { get; set; }

    public string? ProviderKey { get; set; }

    public Dictionary<string, string> Parameters { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    public VaultSyncConfiguration Clone()
        => new()
        {
            IsEnabled = IsEnabled,
            AutoSyncEnabled = AutoSyncEnabled,
            ProviderKey = ProviderKey,
            Parameters = new Dictionary<string, string>(Parameters, StringComparer.OrdinalIgnoreCase)
        };
}

public sealed class VaultSyncStatus
{
    public bool IsEnabled { get; set; }

    public bool AutoSyncEnabled { get; set; }

    public string? ProviderKey { get; set; }

    public VaultSyncOperation LastOperation { get; set; }

    public DateTimeOffset? LastSyncUtc { get; set; }

    public string? LastError { get; set; }

    public VaultSyncRemoteState? RemoteState { get; set; }

    public DateTimeOffset? NextAutoSyncUtc { get; set; }

    public int? LastDownloadedEntries { get; set; }

    public int? LastUploadedEntries { get; set; }
}
