using System.Text.Json;

namespace Password_Phrase_Producer.Services.Security;

public enum ProtectedAccess
{
    App,
    PasswordVault,
    DataVault,
    Authenticator
}

public sealed record UnlockAttemptStatus(
    int PasswordAttemptsRemaining,
    int BiometricFailures,
    DateTimeOffset? LockedUntil,
    bool PasswordOnly,
    bool RecoveryUsed)
{
    public bool IsLocked => LockedUntil is not null;
    public bool CanUseBiometrics => !IsLocked && !PasswordOnly && BiometricFailures < 2 && PasswordAttemptsRemaining > 0;
    public bool CanUseRecovery => IsLocked && !RecoveryUsed;
}

public interface IUnlockAttemptStore
{
    Task<string?> ReadAsync(string key);
    Task WriteAsync(string key, string value);
}

public sealed class SecureUnlockAttemptStore : IUnlockAttemptStore
{
    public Task<string?> ReadAsync(string key) => SecureStorage.Default.GetAsync(key);
    public Task WriteAsync(string key, string value) => SecureStorage.Default.SetAsync(key, value);
}

public interface IUnlockAttemptGate
{
    event Action<ProtectedAccess>? LockedOut;
    Task<UnlockAttemptStatus> GetStatusAsync(ProtectedAccess access);
    Task<bool> RunPasswordAsync(ProtectedAccess access, Func<Task<bool>> verify);
    Task<bool> RunBiometricAsync(ProtectedAccess access, Func<Task<bool>> verify);
    Task<bool> RedeemRecoveryAsync(ProtectedAccess access, Func<Task<bool>> verifyAnswers);
    Task RearmRecoveryAsync(ProtectedAccess access);
    Task ResetAsync(ProtectedAccess access);
}

/// <summary>
/// Serializes all credential checks for one protection domain. The attempt is
/// persisted before verification, so terminating the process cannot replay it.
/// </summary>
public sealed class UnlockAttemptGate : IUnlockAttemptGate
{
    private const string StoragePrefix = "UnlockAttemptState_V1_";
    private const string MarkerPrefix = "UnlockAttemptInitialized_V1_";
    private static readonly TimeSpan[] LockoutDurations =
    [
        TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(15),
        TimeSpan.FromMinutes(60), TimeSpan.FromMinutes(240), TimeSpan.FromMinutes(960),
        TimeSpan.FromHours(24)
    ];

    private readonly IUnlockAttemptStore _store;
    private readonly TimeProvider _clock;
    private readonly SemaphoreSlim[] _mutexes = Enumerable.Range(0, 4).Select(_ => new SemaphoreSlim(1, 1)).ToArray();

    public event Action<ProtectedAccess>? LockedOut;

    public UnlockAttemptGate(IUnlockAttemptStore store, TimeProvider? clock = null)
    {
        _store = store;
        _clock = clock ?? TimeProvider.System;
    }

    public async Task<UnlockAttemptStatus> GetStatusAsync(ProtectedAccess access)
    {
        var mutex = Mutex(access);
        await mutex.WaitAsync().ConfigureAwait(false);
        try
        {
            var state = await LoadAndAdvanceAsync(access).ConfigureAwait(false);
            return Snapshot(state);
        }
        finally { mutex.Release(); }
    }

    public Task<bool> RunPasswordAsync(ProtectedAccess access, Func<Task<bool>> verify)
        => RunAsync(access, biometric: false, verify);

    public Task<bool> RunBiometricAsync(ProtectedAccess access, Func<Task<bool>> verify)
        => RunAsync(access, biometric: true, verify);

    private async Task<bool> RunAsync(ProtectedAccess access, bool biometric, Func<Task<bool>> verify)
    {
        ArgumentNullException.ThrowIfNull(verify);
        var mutex = Mutex(access);
        await mutex.WaitAsync().ConfigureAwait(false);
        try
        {
            var state = await LoadAndAdvanceAsync(access).ConfigureAwait(false);
            if (state.LockedUntilUtcTicks != 0 ||
                biometric && (state.PasswordOnly || state.BiometricFailures >= 2))
                return false;

            // A crash after this write costs one attempt, never grants an extra one.
            state.Remaining--;
            await SaveAsync(access, state).ConfigureAwait(false);

            bool accepted;
            try
            {
                accepted = await verify().ConfigureAwait(false);
            }
            catch (BiometricAuthenticationException ex) when (biometric)
            {
                if (ex.Outcome == BiometricAuthOutcome.Rejected)
                {
                    state.BiometricFailures++;
                    await FinishFailureAsync(access, state).ConfigureAwait(false);
                }
                else
                {
                    state.Remaining++;
                    await SaveAsync(access, state).ConfigureAwait(false);
                }
                return false;
            }
            catch
            {
                state.Remaining++;
                await SaveAsync(access, state).ConfigureAwait(false);
                if (biometric) return false;
                throw;
            }

            if (accepted)
            {
                state.Remaining = 4;
                state.BiometricFailures = 0;
                state.LockoutCount = 0;
                state.LockedUntilUtcTicks = 0;
                state.PasswordOnly = false;
                await SaveAsync(access, state).ConfigureAwait(false);
                return true;
            }

            if (biometric)
            {
                // A missing or invalid biometric key is a device/data error. Actual
                // sensor rejection is reported by BiometricAuthenticationException.
                state.Remaining++;
                await SaveAsync(access, state).ConfigureAwait(false);
                return false;
            }

            await FinishFailureAsync(access, state).ConfigureAwait(false);
            return false;
        }
        finally { mutex.Release(); }
    }

    public async Task<bool> RedeemRecoveryAsync(ProtectedAccess access, Func<Task<bool>> verifyAnswers)
    {
        ArgumentNullException.ThrowIfNull(verifyAnswers);
        var mutex = Mutex(access);
        await mutex.WaitAsync().ConfigureAwait(false);
        try
        {
            var state = await LoadAndAdvanceAsync(access).ConfigureAwait(false);
            if (state.LockedUntilUtcTicks == 0 || state.RecoveryUsed)
                return false;

            // One submitted challenge per domain, even across restarts and crashes.
            state.RecoveryUsed = true;
            await SaveAsync(access, state).ConfigureAwait(false);
            if (!await verifyAnswers().ConfigureAwait(false)) return false;

            state.LockedUntilUtcTicks = 0;
            state.Remaining = 2;
            state.PasswordOnly = true;
            await SaveAsync(access, state).ConfigureAwait(false);
            return true;
        }
        finally { mutex.Release(); }
    }

    public async Task RearmRecoveryAsync(ProtectedAccess access)
    {
        var mutex = Mutex(access);
        await mutex.WaitAsync().ConfigureAwait(false);
        try
        {
            var state = await LoadAndAdvanceAsync(access).ConfigureAwait(false);
            state.RecoveryUsed = false;
            await SaveAsync(access, state).ConfigureAwait(false);
        }
        finally { mutex.Release(); }
    }

    public async Task ResetAsync(ProtectedAccess access)
    {
        var mutex = Mutex(access);
        await mutex.WaitAsync().ConfigureAwait(false);
        try { await SaveAsync(access, new AttemptState()).ConfigureAwait(false); }
        finally { mutex.Release(); }
    }

    private async Task FinishFailureAsync(ProtectedAccess access, AttemptState state)
    {
        if (state.Remaining <= 0)
        {
            StartLockout(state);
            await SaveAsync(access, state).ConfigureAwait(false);
            LockedOut?.Invoke(access);
        }
        else
        {
            await SaveAsync(access, state).ConfigureAwait(false);
        }
    }

    private void StartLockout(AttemptState state)
    {
        var duration = LockoutDurations[Math.Min(state.LockoutCount, LockoutDurations.Length - 1)];
        state.LockoutCount++;
        state.LockedUntilUtcTicks = _clock.GetUtcNow().Add(duration).UtcTicks;
        state.Remaining = 0;
        state.PasswordOnly = false;
    }

    private async Task<AttemptState> LoadAndAdvanceAsync(ProtectedAccess access)
    {
        string? json;
        try { json = await _store.ReadAsync(StoragePrefix + access).ConfigureAwait(false); }
        catch { LockedOut?.Invoke(access); throw; }
        AttemptState state;
        if (json is null)
        {
            string? marker;
            try { marker = await _store.ReadAsync(MarkerPrefix + access).ConfigureAwait(false); }
            catch { LockedOut?.Invoke(access); throw; }
            if (marker is not null)
            {
                LockedOut?.Invoke(access);
                throw new InvalidDataException("Der Entsperrzähler fehlt.");
            }
            state = new AttemptState();
            await SaveAsync(access, state).ConfigureAwait(false);
            try { await _store.WriteAsync(MarkerPrefix + access, "1").ConfigureAwait(false); }
            catch { LockedOut?.Invoke(access); throw; }
        }
        else
        {
            try { state = JsonSerializer.Deserialize<AttemptState>(json) ?? throw new JsonException(); }
            catch (JsonException ex)
            {
                LockedOut?.Invoke(access);
                throw new InvalidDataException("Der Entsperrzähler ist beschädigt.", ex);
            }
            if (state.Version != 1 || state.Remaining is < 0 or > 4 || state.BiometricFailures is < 0 or > 2 ||
                state.LockoutCount < 0 || state.LockedUntilUtcTicks < 0)
            {
                LockedOut?.Invoke(access);
                throw new InvalidDataException("Der Entsperrzähler ist beschädigt.");
            }
        }

        if (state.LockedUntilUtcTicks == 0 && state.Remaining == 0)
        {
            // A process may have stopped after reserving the last attempt.
            StartLockout(state);
            await SaveAsync(access, state).ConfigureAwait(false);
            LockedOut?.Invoke(access);
        }

        if (state.LockedUntilUtcTicks != 0 && _clock.GetUtcNow().UtcTicks >= state.LockedUntilUtcTicks)
        {
            state.LockedUntilUtcTicks = 0;
            state.Remaining = 4;
            state.BiometricFailures = 0;
            state.PasswordOnly = false;
            await SaveAsync(access, state).ConfigureAwait(false);
        }
        return state;
    }

    private async Task SaveAsync(ProtectedAccess access, AttemptState state)
    {
        try { await _store.WriteAsync(StoragePrefix + access, JsonSerializer.Serialize(state)).ConfigureAwait(false); }
        catch { LockedOut?.Invoke(access); throw; }
    }

    private static UnlockAttemptStatus Snapshot(AttemptState state) => new(
        state.Remaining, state.BiometricFailures,
        state.LockedUntilUtcTicks == 0 ? null : new DateTimeOffset(state.LockedUntilUtcTicks, TimeSpan.Zero),
        state.PasswordOnly, state.RecoveryUsed);

    private SemaphoreSlim Mutex(ProtectedAccess access)
    {
        var index = (int)access;
        if (index < 0 || index >= _mutexes.Length) throw new ArgumentOutOfRangeException(nameof(access));
        return _mutexes[index];
    }

    private sealed class AttemptState
    {
        public int Version { get; set; } = 1;
        public int Remaining { get; set; } = 4;
        public int BiometricFailures { get; set; }
        public int LockoutCount { get; set; }
        public long LockedUntilUtcTicks { get; set; }
        public bool PasswordOnly { get; set; }
        public bool RecoveryUsed { get; set; }
    }
}
