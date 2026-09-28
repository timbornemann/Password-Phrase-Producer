using System.Collections.Concurrent;
using System.Security.Cryptography;
using Password_Phrase_Producer.Services.Security;
using Password_Phrase_Producer.Services.Storage;
using Xunit;

namespace PasswordPhraseProducer.Updates.Tests;

// Stand-in for the OS secure store. The production encryption services themselves are linked unmodified.
internal static class SecureStorage
{
    public static TestSecureStore Default { get; } = new();
    internal sealed class TestSecureStore
    {
        private readonly ConcurrentDictionary<string, string> _values = new();
        public Task<string?> GetAsync(string key) => Task.FromResult(_values.GetValueOrDefault(key));
        public Task SetAsync(string key, string value) { _values[key] = value; return Task.CompletedTask; }
    }
}

public sealed class StorageCompatibilityTests
{
    [Fact]
    public async Task ExistingAppPasswordAndEncryptedFilesSurviveReplacementOfServiceInstances()
    {
        var directory = Path.Combine(Path.GetTempPath(), "ppp-storage-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            var biometrics = new DisabledBiometrics();
            var appLock = new AppLockService(biometrics);
            await appLock.SetupAsync("persisted-master-password", false);
            var files = new SecureFileService(appLock);
            var fixtures = StartupDataGuard.DataFiles.ToDictionary(n => n, _ => RandomNumberGenerator.GetBytes(150));
            foreach (var fixture in fixtures) await files.WriteAllBytesAsync(Path.Combine(directory, fixture.Key), fixture.Value);
            var ciphertext = fixtures.Keys.ToDictionary(n => n, n => File.ReadAllBytes(Path.Combine(directory, n)));
            await SecureStorage.Default.SetAsync("TotpPasswordSalt", "existing-totp-salt");
            await SecureStorage.Default.SetAsync("TotpPasswordVerifier", "existing-totp-verifier");
            for (var version = 0; version < 3; version++)
            {
                appLock.Lock();
                appLock = new AppLockService(biometrics);
                await StartupDataGuard.VerifyAsync(directory, SecureStorage.Default.GetAsync);
                Assert.False(await appLock.UnlockAsync("wrong-password"));
                Assert.True(await appLock.UnlockAsync("persisted-master-password"));
                files = new SecureFileService(appLock);
                foreach (var fixture in fixtures)
                {
                    Assert.Equal(fixture.Value, await files.ReadAllBytesAsync(Path.Combine(directory, fixture.Key)));
                    Assert.Equal(ciphertext[fixture.Key], File.ReadAllBytes(Path.Combine(directory, fixture.Key)));
                }
            }
            File.Delete(Path.Combine(directory, "totp.key"));
            await Assert.ThrowsAsync<InvalidDataException>(() => StartupDataGuard.VerifyAsync(directory, SecureStorage.Default.GetAsync));
            Assert.Equal(ciphertext["totp_data.json.enc"], File.ReadAllBytes(Path.Combine(directory, "totp_data.json.enc")));
        }
        finally { Directory.Delete(directory, true); }
    }

    private sealed class DisabledBiometrics : IBiometricAuthenticationService
    {
        public Task<bool> IsAvailableAsync(CancellationToken ct = default) => Task.FromResult(false);
        public Task<bool> AuthenticateAsync(string reason, CancellationToken ct = default) => Task.FromResult(false);
        public Task<byte[]> EncryptAsync(byte[] data, CancellationToken ct = default) => throw new NotSupportedException();
        public Task<byte[]> DecryptAsync(byte[] data, CancellationToken ct = default) => throw new NotSupportedException();
    }
}
