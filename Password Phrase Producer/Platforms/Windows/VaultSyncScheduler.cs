using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.UI.Dispatching;
using Password_Phrase_Producer.Services.Vault.Sync;

namespace Password_Phrase_Producer.Platforms.Windows;

public sealed class VaultSyncScheduler : IVaultSyncScheduler
{
    private readonly DispatcherQueue _dispatcherQueue;
    private readonly ILogger<VaultSyncScheduler> _logger;
    private DispatcherQueueTimer? _timer;
    private Func<CancellationToken, Task>? _callback;
    private bool _isRunning;

    public VaultSyncScheduler(ILogger<VaultSyncScheduler> logger)
    {
        _dispatcherQueue = DispatcherQueue.GetForCurrentThread() ?? throw new InvalidOperationException("Es konnte keine DispatcherQueue initialisiert werden.");
        _logger = logger;
    }

    public void Schedule(TimeSpan interval, Func<CancellationToken, Task> callback)
    {
        Cancel();
        _callback = callback ?? throw new ArgumentNullException(nameof(callback));
        _timer = _dispatcherQueue.CreateTimer();
        _timer.Interval = interval;
        _timer.IsRepeating = true;
        _timer.Tick += OnTimerTick;
        _timer.Start();
    }

    public void Cancel()
    {
        if (_timer is null)
        {
            _callback = null;
            _isRunning = false;
            return;
        }

        _timer.Tick -= OnTimerTick;
        _timer.Stop();
        _timer = null;
        _callback = null;
        _isRunning = false;
    }

    private void OnTimerTick(DispatcherQueueTimer sender, object args)
    {
        if (_callback is null || _isRunning)
        {
            return;
        }

        _isRunning = true;
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
            _isRunning = false;
        }
    }
}
