using Password_Phrase_Producer.Services.Security;
using Xunit;

namespace PasswordPhraseProducer.Updates.Tests;

public sealed class UnlockAttemptGateTests
{
    [Theory]
    [InlineData(ProtectedAccess.App)]
    [InlineData(ProtectedAccess.PasswordVault)]
    [InlineData(ProtectedAccess.DataVault)]
    [InlineData(ProtectedAccess.Authenticator)]
    public async Task FourFailuresLockOnlyTheirOwnDomain(ProtectedAccess target)
    {
        var clock = new FakeClock();
        var gate = NewGate(clock);
        var checks = 0;
        for (var i = 0; i < 4; i++)
            Assert.False(await gate.RunPasswordAsync(target, () => { checks++; return Task.FromResult(false); }));
        var status = await gate.GetStatusAsync(target);
        Assert.True(status.IsLocked);
        Assert.Equal(0, status.PasswordAttemptsRemaining);
        Assert.Equal(clock.GetUtcNow().AddMinutes(1), status.LockedUntil);
        Assert.False(await gate.RunPasswordAsync(target, () => { checks++; return Task.FromResult(true); }));
        Assert.Equal(4, checks);
        var other = target == ProtectedAccess.App ? ProtectedAccess.DataVault : ProtectedAccess.App;
        Assert.Equal(4, (await gate.GetStatusAsync(other)).PasswordAttemptsRemaining);
    }

    [Fact]
    public async Task ConsecutiveLockoutsEscalateAndSuccessResetsThem()
    {
        var clock = new FakeClock();
        var gate = NewGate(clock);
        var expectedMinutes = new[] { 1, 5, 15, 60, 240, 960, 1440, 1440 };
        foreach (var minutes in expectedMinutes)
        {
            for (var i = 0; i < 4; i++)
                Assert.False(await gate.RunPasswordAsync(ProtectedAccess.App, () => Task.FromResult(false)));
            var status = await gate.GetStatusAsync(ProtectedAccess.App);
            Assert.Equal(clock.GetUtcNow().AddMinutes(minutes), status.LockedUntil);
            clock.Advance(TimeSpan.FromMinutes(minutes));
        }
        Assert.True(await gate.RunPasswordAsync(ProtectedAccess.App, () => Task.FromResult(true)));
        for (var i = 0; i < 4; i++)
            Assert.False(await gate.RunPasswordAsync(ProtectedAccess.App, () => Task.FromResult(false)));
        Assert.Equal(clock.GetUtcNow().AddMinutes(1), (await gate.GetStatusAsync(ProtectedAccess.App)).LockedUntil);
    }

    [Fact]
    public async Task TwoBiometricRejectionsLeaveTwoPasswordTries()
    {
        var gate = NewGate(new FakeClock());
        for (var i = 0; i < 2; i++)
            Assert.False(await gate.RunBiometricAsync(ProtectedAccess.Authenticator,
                () => throw new BiometricAuthenticationException(BiometricAuthOutcome.Rejected, "rejected")));
        var status = await gate.GetStatusAsync(ProtectedAccess.Authenticator);
        Assert.Equal(2, status.PasswordAttemptsRemaining);
        Assert.False(status.CanUseBiometrics);
        Assert.False(await gate.RunBiometricAsync(ProtectedAccess.Authenticator, () => Task.FromResult(true)));
        Assert.False(await gate.RunPasswordAsync(ProtectedAccess.Authenticator, () => Task.FromResult(false)));
        Assert.False(await gate.RunPasswordAsync(ProtectedAccess.Authenticator, () => Task.FromResult(false)));
        Assert.True((await gate.GetStatusAsync(ProtectedAccess.Authenticator)).IsLocked);
    }

    [Fact]
    public async Task CancelledOrUnavailableBiometricDoesNotConsumeAttempt()
    {
        var gate = NewGate(new FakeClock());
        foreach (var outcome in new[] { BiometricAuthOutcome.Cancelled, BiometricAuthOutcome.Unavailable })
            Assert.False(await gate.RunBiometricAsync(ProtectedAccess.App,
                () => throw new BiometricAuthenticationException(outcome, "not a rejected scan")));
        Assert.Equal(4, (await gate.GetStatusAsync(ProtectedAccess.App)).PasswordAttemptsRemaining);
    }

    [Fact]
    public async Task RestartAndParallelCallsCannotGainExtraAttempts()
    {
        var store = new MemoryStore();
        var clock = new FakeClock();
        var gate = new UnlockAttemptGate(store, clock);
        await Task.WhenAll(Enumerable.Range(0, 8).Select(_ =>
            gate.RunPasswordAsync(ProtectedAccess.PasswordVault, () => Task.FromResult(false))));
        var restarted = new UnlockAttemptGate(store, clock);
        Assert.True((await restarted.GetStatusAsync(ProtectedAccess.PasswordVault)).IsLocked);
        Assert.Equal(0, (await restarted.GetStatusAsync(ProtectedAccess.PasswordVault)).PasswordAttemptsRemaining);
    }

    [Fact]
    public async Task RecoveryIsOneSubmissionAndGrantsOnlyTwoPasswordAttempts()
    {
        var gate = NewGate(new FakeClock());
        for (var i = 0; i < 4; i++)
            await gate.RunPasswordAsync(ProtectedAccess.DataVault, () => Task.FromResult(false));
        Assert.True(await gate.RedeemRecoveryAsync(ProtectedAccess.DataVault, () => Task.FromResult(true)));
        var status = await gate.GetStatusAsync(ProtectedAccess.DataVault);
        Assert.False(status.IsLocked);
        Assert.Equal(2, status.PasswordAttemptsRemaining);
        Assert.False(status.CanUseBiometrics);
        for (var i = 0; i < 2; i++)
            await gate.RunPasswordAsync(ProtectedAccess.DataVault, () => Task.FromResult(false));
        Assert.True((await gate.GetStatusAsync(ProtectedAccess.DataVault)).IsLocked);
        Assert.False(await gate.RedeemRecoveryAsync(ProtectedAccess.DataVault, () => Task.FromResult(true)));
        await gate.RearmRecoveryAsync(ProtectedAccess.DataVault);
        Assert.True(await gate.RedeemRecoveryAsync(ProtectedAccess.DataVault, () => Task.FromResult(true)));
    }

    [Fact]
    public async Task WrongRecoveryAnswerConsumesOpportunityWithoutEndingLockout()
    {
        var gate = NewGate(new FakeClock());
        for (var i = 0; i < 4; i++)
            await gate.RunPasswordAsync(ProtectedAccess.App, () => Task.FromResult(false));
        Assert.False(await gate.RedeemRecoveryAsync(ProtectedAccess.App, () => Task.FromResult(false)));
        Assert.False(await gate.RedeemRecoveryAsync(ProtectedAccess.App, () => Task.FromResult(true)));
        var status = await gate.GetStatusAsync(ProtectedAccess.App);
        Assert.True(status.IsLocked);
        Assert.True(status.RecoveryUsed);
    }

    [Fact]
    public async Task DamagedStoredStateFailsClosed()
    {
        var store = new MemoryStore();
        await store.WriteAsync("UnlockAttemptState_V1_App", "{invalid-json");
        var gate = new UnlockAttemptGate(store);
        await Assert.ThrowsAsync<InvalidDataException>(() => gate.GetStatusAsync(ProtectedAccess.App));
        await Assert.ThrowsAsync<InvalidDataException>(() =>
            gate.RunPasswordAsync(ProtectedAccess.App, () => Task.FromResult(true)));
    }

    private static UnlockAttemptGate NewGate(FakeClock clock) => new(new MemoryStore(), clock);

    private sealed class MemoryStore : IUnlockAttemptStore
    {
        private readonly Dictionary<string, string> _data = new();
        public Task<string?> ReadAsync(string key) => Task.FromResult(_data.GetValueOrDefault(key));
        public Task WriteAsync(string key, string value) { _data[key] = value; return Task.CompletedTask; }
    }

    private sealed class FakeClock : TimeProvider
    {
        private DateTimeOffset _now = new(2026, 9, 29, 12, 0, 0, TimeSpan.Zero);
        public override DateTimeOffset GetUtcNow() => _now;
        public void Advance(TimeSpan duration) => _now += duration;
    }
}
