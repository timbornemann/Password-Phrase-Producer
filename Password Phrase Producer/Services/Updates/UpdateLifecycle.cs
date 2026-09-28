using PasswordPhraseProducer.Updates;

namespace Password_Phrase_Producer.Services.Updates;

public sealed class UpdateLifecycle(IAppUpdateService updates)
{
    private CancellationTokenSource? _foreground;

    public void Start()
    {
        Stop();
        _foreground = new();
        _ = RunAsync(_foreground.Token);
    }

    public void Stop()
    {
        _foreground?.Cancel();
        _foreground?.Dispose();
        _foreground = null;
    }

    private async Task RunAsync(CancellationToken ct)
    {
        try
        {
            await updates.InitializeAsync(ct);
            using var timer = new PeriodicTimer(TimeSpan.FromMinutes(1));
            do { await updates.CheckAsync(cancellationToken: ct); }
            while (await timer.WaitForNextTickAsync(ct));
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
        catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"Update check: {ex.GetType().Name}"); }
    }
}
