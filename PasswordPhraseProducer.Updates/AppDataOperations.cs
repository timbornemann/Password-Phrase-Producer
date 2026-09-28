namespace PasswordPhraseProducer.Updates;

/// <summary>Tracks complete data operations, including nested calls and their asynchronous continuations.</summary>
public sealed class AppDataOperations
{
    public static AppDataOperations Shared { get; } = new();
    private readonly object _sync = new();
    private readonly AsyncLocal<OperationChain?> _current = new();
    private int _active;
    private long _failures;
    private int _failedChains;
    private bool _maintenance;
    private TaskCompletionSource _drained = NewCompletion();
    private static TaskCompletionSource NewCompletion() => new(TaskCreationOptions.RunContinuationsAsynchronously);

    public Operation BeginOperation()
    {
        lock (_sync)
        {
            var previous = _current.Value;
            // Captured execution contexts can outlive their original operation. Only a
            // still-active chain may continue nested work while installation is draining it.
            var nested = previous is { Active: > 0 };
            if (_maintenance && !nested)
                throw new InvalidOperationException("Ein Update wird vorbereitet. Bitte versuche es anschließend erneut.");
            if (_active++ == 0) _drained = NewCompletion();
            var chain = nested ? previous! : new OperationChain();
            chain.Active++;
            _current.Value = chain;
            return new Operation(this, chain, previous);
        }
    }

    public async Task<IDisposable> QuiesceAsync(TimeSpan timeout, CancellationToken cancellationToken)
    {
        Task drained;
        long failures;
        bool alreadyFailed;
        lock (_sync)
        {
            if (_maintenance) throw new InvalidOperationException("Ein Update wird bereits installiert.");
            _maintenance = true;
            failures = _failures;
            alreadyFailed = _failedChains > 0;
            drained = _active == 0 ? Task.CompletedTask : _drained.Task;
        }
        try
        {
            await drained.WaitAsync(timeout, cancellationToken);
            lock (_sync)
                if (alreadyFailed || _failures != failures) throw new IOException("Ein Speichervorgang ist fehlgeschlagen. Das Update wurde abgebrochen.");
            return new MaintenanceLease(this);
        }
        catch
        {
            EndMaintenance();
            throw;
        }
    }

    private void EndMaintenance() { lock (_sync) _maintenance = false; }

    public sealed class Operation : IDisposable
    {
        private AppDataOperations? _owner;
        private readonly OperationChain _chain;
        private readonly OperationChain? _previous;
        internal Operation(AppDataOperations owner, OperationChain chain, OperationChain? previous)
        { _owner = owner; _chain = chain; _previous = previous; }
        public void Failed()
        {
            if (_owner is not { } owner) return;
            lock (owner._sync)
            {
                if (_owner is null || _chain.Failed) return;
                _chain.Failed = true;
                owner._failures++;
                owner._failedChains++;
            }
        }
        public void Dispose()
        {
            if (Interlocked.Exchange(ref _owner, null) is not { } owner) return;
            lock (owner._sync)
            {
                owner._current.Value = _previous;
                if (--_chain.Active == 0 && _chain.Failed) owner._failedChains--;
                if (--owner._active == 0) owner._drained.TrySetResult();
            }
        }
    }

    internal sealed class OperationChain
    {
        public int Active;
        public bool Failed;
    }

    private sealed class MaintenanceLease(AppDataOperations owner) : IDisposable
    {
        public void Dispose() => owner.EndMaintenance();
    }
}
