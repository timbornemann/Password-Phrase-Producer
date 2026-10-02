namespace Password_Phrase_Producer.Services.LocalTransfer;

// One place to terminate listeners, downloads and imports when the app locks.
public sealed class LocalTransferActivity
{
    private readonly object _gate = new();
    private readonly HashSet<CancellationTokenSource> _active = new();

    internal CancellationTokenSource Begin(CancellationToken cancellationToken = default)
    {
        var source = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        lock (_gate) _active.Add(source);
        return source;
    }

    internal void End(CancellationTokenSource source)
    {
        lock (_gate) _active.Remove(source);
        source.Dispose();
    }

    internal void CancelAll()
    {
        CancellationTokenSource[] sources;
        lock (_gate) sources = _active.ToArray();
        foreach (var source in sources)
        {
            try { source.Cancel(); }
            catch (Exception) { /* Locking the app must continue even if a listener is closing. */ }
        }
    }
}
