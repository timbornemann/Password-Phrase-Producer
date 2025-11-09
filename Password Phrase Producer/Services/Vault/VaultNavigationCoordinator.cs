using System;

namespace Password_Phrase_Producer.Services.Vault;

public sealed class PendingVaultEntryRequest
{
    public PendingVaultEntryRequest(string password)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(password);

        Id = Guid.NewGuid();
        Password = password;
    }

    public Guid Id { get; }

    public string Password { get; }
}

public static class VaultNavigationCoordinator
{
    private static readonly object SyncRoot = new();
    private static PendingVaultEntryRequest? _pendingRequest;

    public static PendingVaultEntryRequest? GetPendingRequest()
    {
        lock (SyncRoot)
        {
            return _pendingRequest;
        }
    }

    public static PendingVaultEntryRequest SetPendingPassword(string password)
    {
        lock (SyncRoot)
        {
            var request = new PendingVaultEntryRequest(password);
            _pendingRequest = request;
            return request;
        }
    }

    public static void ClearPendingRequest(Guid requestId)
    {
        lock (SyncRoot)
        {
            if (_pendingRequest?.Id == requestId)
            {
                _pendingRequest = null;
            }
        }
    }
}
