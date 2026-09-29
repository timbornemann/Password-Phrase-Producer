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
        public void Clear() => _values.Clear();
    }
}

public sealed class StorageCompatibilityTests
{
    [Fact]
    public async Task SecureFilesNeverFallBackToPlaintextWithoutAppLock()
    {
        SecureStorage.Default.Clear();
        var path = Path.Combine(Path.GetTempPath(), "ppp-no-plaintext-" + Guid.NewGuid().ToString("N"));
        try
        {
            var files = new SecureFileService(new AppLockService(new DisabledBiometrics()));
            await Assert.ThrowsAsync<InvalidOperationException>(() => files.WriteAllBytesAsync(path, new byte[] { 1, 2, 3 }));
            Assert.False(File.Exists(path));
            await File.WriteAllBytesAsync(path, new byte[] { 1, 2, 3 });
            await Assert.ThrowsAsync<InvalidOperationException>(() => files.ReadAllBytesAsync(path));
        }
        finally { File.Delete(path); SecureStorage.Default.Clear(); }
    }

    [Fact]
    public async Task PasswordVerificationDoesNotUnlockTheApp()
    {
        SecureStorage.Default.Clear();
        try
        {
            var appLock = new AppLockService(new DisabledBiometrics());
            await appLock.SetupAsync("sufficiently long app password", false);
            appLock.Lock();

            Assert.False(await appLock.VerifyPasswordAsync("wrong password"));
            Assert.False(appLock.IsUnlocked);
            Assert.True(await appLock.VerifyPasswordAsync("sufficiently long app password"));
            Assert.False(appLock.IsUnlocked);
        }
        finally { SecureStorage.Default.Clear(); }
    }

    [Fact]
    public async Task OptionalBiometricFailureDoesNotInvalidateAppPasswordSetup()
    {
        SecureStorage.Default.Clear();
        try
        {
            var appLock = new AppLockService(new DisabledBiometrics());
            await appLock.SetupAsync("sufficiently long app password", true);
            Assert.True(await appLock.IsConfiguredAsync());
            Assert.False(await appLock.IsBiometricConfiguredAsync());
            appLock.Lock();
            Assert.True(await appLock.UnlockAsync("sufficiently long app password"));
        }
        finally { SecureStorage.Default.Clear(); }
    }

    [Fact]
    public async Task ExistingAppPasswordAndEncryptedFilesSurviveReplacementOfServiceInstances()
    {
        SecureStorage.Default.Clear();
        var directory = Path.Combine(Path.GetTempPath(), "ppp-storage-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            var biometrics = new DisabledBiometrics();
            var appLock = new AppLockService(biometrics);
            await appLock.SetupAsync("persisted-master-password", false);
            var metadataJson = await SecureStorage.Default.GetAsync("AppLockMetadata_V1");
            using (var metadataDocument = System.Text.Json.JsonDocument.Parse(metadataJson!))
                Assert.Equal(600_000, metadataDocument.RootElement.GetProperty("Iterations").GetInt32());
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
            await Assert.ThrowsAsync<InvalidOperationException>(() => appLock.SetupAsync("replacement", false));
            await Assert.ThrowsAsync<UnauthorizedAccessException>(() => appLock.ChangePasswordAsync("wrong-password", "new-master-password"));
            await appLock.ChangePasswordAsync("persisted-master-password", "new-master-password");
            appLock.Lock();
            Assert.False(await appLock.UnlockAsync("persisted-master-password"));
            Assert.True(await appLock.UnlockAsync("new-master-password"));
            foreach (var fixture in fixtures)
                Assert.Equal(fixture.Value, await files.ReadAllBytesAsync(Path.Combine(directory, fixture.Key)));
            File.Delete(Path.Combine(directory, "totp.key"));
            await Assert.ThrowsAsync<InvalidDataException>(() => StartupDataGuard.VerifyAsync(directory, SecureStorage.Default.GetAsync));
            Assert.Equal(ciphertext["totp_data.json.enc"], File.ReadAllBytes(Path.Combine(directory, "totp_data.json.enc")));
        }
        finally { Directory.Delete(directory, true); SecureStorage.Default.Clear(); }
    }

    [Fact]
    public async Task BiometricUnlockRejectsCorruptKeyAndMigratesLegacyMetadata()
    {
        SecureStorage.Default.Clear();
        try
        {
            var biometrics = new CorruptibleBiometrics();
            var appLock = new AppLockService(biometrics);
            await appLock.SetupAsync("a sufficiently long app password", true);
            appLock.Lock();

            biometrics.Corrupt = true;
            Assert.False(await appLock.UnlockWithBiometricsAsync());
            Assert.False(appLock.IsUnlocked);

            biometrics.Corrupt = false;
            Assert.True(await appLock.UnlockWithBiometricsAsync());
            appLock.Lock();

            var stored = await SecureStorage.Default.GetAsync("AppLockMetadata_V1");
            var metadata = System.Text.Json.Nodes.JsonNode.Parse(stored!)!;
            metadata.AsObject().Remove("MasterKeyVerifier");
            await SecureStorage.Default.SetAsync("AppLockMetadata_V1", metadata.ToJsonString());
            appLock = new AppLockService(biometrics);
            Assert.False(await appLock.UnlockWithBiometricsAsync());
            Assert.True(await appLock.UnlockAsync("a sufficiently long app password"));
            appLock.Lock();
            Assert.True(await appLock.UnlockWithBiometricsAsync());

            stored = await SecureStorage.Default.GetAsync("AppLockMetadata_V1");
            metadata = System.Text.Json.Nodes.JsonNode.Parse(stored!)!;
            metadata["MasterKeyVerifier"] = Convert.ToBase64String(new byte[32]);
            await SecureStorage.Default.SetAsync("AppLockMetadata_V1", metadata.ToJsonString());
            appLock = new AppLockService(biometrics);
            Assert.False(await appLock.UnlockWithBiometricsAsync());
            Assert.True(await appLock.UnlockAsync("a sufficiently long app password"));
            appLock.Lock();
            Assert.True(await appLock.UnlockWithBiometricsAsync());
        }
        finally { SecureStorage.Default.Clear(); }
    }

    [Fact]
    public async Task LockInvalidatesBiometricUnlockAlreadyInProgress()
    {
        SecureStorage.Default.Clear();
        try
        {
            var biometrics = new DelayedBiometrics();
            var appLock = new AppLockService(biometrics);
            await appLock.SetupAsync("a sufficiently long app password", true);
            appLock.Lock();

            var pendingUnlock = appLock.UnlockWithBiometricsAsync();
            await biometrics.DecryptStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));
            appLock.Lock();
            biometrics.ReleaseDecrypt.SetResult();

            Assert.False(await pendingUnlock);
            Assert.False(appLock.IsUnlocked);
        }
        finally { SecureStorage.Default.Clear(); }
    }

    private sealed class DisabledBiometrics : IBiometricAuthenticationService
    {
        public Task<bool> IsAvailableAsync(CancellationToken ct = default) => Task.FromResult(false);
        public Task<bool> AuthenticateAsync(string reason, CancellationToken ct = default) => Task.FromResult(false);
        public Task<byte[]> EncryptAsync(byte[] data, CancellationToken ct = default) => throw new NotSupportedException();
        public Task<byte[]> DecryptAsync(byte[] data, CancellationToken ct = default) => throw new NotSupportedException();
    }

    private sealed class CorruptibleBiometrics : IBiometricAuthenticationService
    {
        public bool Corrupt { get; set; }
        public Task<bool> IsAvailableAsync(CancellationToken ct = default) => Task.FromResult(true);
        public Task<bool> AuthenticateAsync(string reason, CancellationToken ct = default) => Task.FromResult(true);
        public Task<byte[]> EncryptAsync(byte[] data, CancellationToken ct = default) => Task.FromResult(data.ToArray());
        public Task<byte[]> DecryptAsync(byte[] data, CancellationToken ct = default)
        {
            var output = data.ToArray();
            if (Corrupt) output[0] ^= 1;
            return Task.FromResult(output);
        }
    }

    private sealed class DelayedBiometrics : IBiometricAuthenticationService
    {
        public TaskCompletionSource DecryptStarted { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource ReleaseDecrypt { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public Task<bool> IsAvailableAsync(CancellationToken ct = default) => Task.FromResult(true);
        public Task<bool> AuthenticateAsync(string reason, CancellationToken ct = default) => Task.FromResult(true);
        public Task<byte[]> EncryptAsync(byte[] data, CancellationToken ct = default) => Task.FromResult(data.ToArray());
        public async Task<byte[]> DecryptAsync(byte[] data, CancellationToken ct = default)
        {
            DecryptStarted.SetResult();
            await ReleaseDecrypt.Task;
            return data.ToArray();
        }
    }
}
