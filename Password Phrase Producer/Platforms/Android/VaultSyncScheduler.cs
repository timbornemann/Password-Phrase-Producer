using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Password_Phrase_Producer.Services.Vault.Sync;

namespace Password_Phrase_Producer.Platforms.Android;

public sealed class VaultSyncScheduler : IVaultSyncScheduler, IDisposable
{
    private readonly ILogger<VaultSyncScheduler> _logger;
    private Timer? _timer;
    private Func<CancellationToken, Task>? _callback;
    private int _isRunning;

    public VaultSyncScheduler(ILogger<VaultSyncScheduler> logger)
    {
        _logger = logger;
    }

    public void Schedule(TimeSpan interval, Func<CancellationToken, Task> callback)
    {
        Cancel();
        _callback = callback ?? throw new ArgumentNullException(nameof(callback));
        _timer = new Timer(OnTimerTick, null, TimeSpan.Zero, interval);
    }

    public void Cancel()
    {
        Interlocked.Exchange(ref _isRunning, 0);
        _timer?.Dispose();
        _timer = null;
        _callback = null;
    }

    public void Dispose()
        => Cancel();

    private void OnTimerTick(object? state)
    {
        if (_callback is null)
        {
            return;
        }

        if (Interlocked.Exchange(ref _isRunning, 1) == 1)
        {
            return;
        }

        _ = ExecuteAsync();
    }

    private async Task ExecuteAsync()
    {
        try
        {
            var callback = _callback;
            if (callback is null)
            {
                return;
            }

            using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(5));
            await callback(cts.Token).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Fehler beim Ausführen der Hintergrundsynchronisation.");
        }
        finally
        {
            Interlocked.Exchange(ref _isRunning, 0);
        }
    }
}
