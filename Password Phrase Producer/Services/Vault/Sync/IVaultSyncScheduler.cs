using System;
using System.Threading;
using System.Threading.Tasks;

namespace Password_Phrase_Producer.Services.Vault.Sync;

public interface IVaultSyncScheduler
{
    void Schedule(TimeSpan interval, Func<CancellationToken, Task> callback);

    void Cancel();
}

public sealed class NoOpVaultSyncScheduler : IVaultSyncScheduler
{
    public void Schedule(TimeSpan interval, Func<CancellationToken, Task> callback)
    {
    }

    public void Cancel()
    {
    }
}
