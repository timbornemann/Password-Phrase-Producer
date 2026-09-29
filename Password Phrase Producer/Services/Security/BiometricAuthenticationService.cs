using System;
using System.Threading;
using System.Threading.Tasks;

namespace Password_Phrase_Producer.Services.Security;

public class BiometricAuthenticationService : IBiometricAuthenticationService
{
#if ANDROID
    private const string AndroidKeyStore = "AndroidKeyStore";
    private const string KeyAlias = "PasswordPhraseProducerBiometricKey";


    public Task<bool> IsAvailableAsync(CancellationToken cancellationToken = default)
    {
        var context = Microsoft.Maui.ApplicationModel.Platform.CurrentActivity ?? Microsoft.Maui.ApplicationModel.Platform.AppContext;
        if (context is null)
        {
            return Task.FromResult(false);
        }

        var manager = AndroidX.Biometric.BiometricManager.From(context);
        if (manager is null)
        {
            return Task.FromResult(false);
        }

        // CryptoObject-backed keys require a strong biometric. A weak sensor
        // must not make the settings UI offer a flow that cannot unlock keys.
        var status = manager.CanAuthenticate((int)AndroidX.Biometric.BiometricManager.Authenticators.BiometricStrong);

        return Task.FromResult(status == AndroidX.Biometric.BiometricManager.BiometricSuccess);
    }

    public async Task<bool> AuthenticateAsync(string reason, CancellationToken cancellationToken = default)
    {
        return await AuthenticateInternalAsync(reason, null, cancellationToken).ConfigureAwait(false) is null;
    }

    public async Task<byte[]> EncryptAsync(byte[] data, CancellationToken cancellationToken = default)
    {
        var cipher = GetCipher(Javax.Crypto.CipherMode.EncryptMode);
        var outcome = await AuthenticateInternalAsync("Biometrie einrichten", cipher, cancellationToken).ConfigureAwait(false);
        
        if (outcome is not null || cipher is null)
        {
            throw new BiometricAuthenticationException(outcome ?? BiometricAuthOutcome.Unavailable,
                "Biometric authentication failed or cancelled.");
        }

        var iv = cipher.GetIV();
        byte[] encrypted;
        try 
        {
             encrypted = cipher.DoFinal(data);
        }
        catch (Java.Lang.Exception ex)
        {
             throw new UnauthorizedAccessException("Encryption failed at DoFinal.", ex);
        }

        // Combine IV and encrypted data
        try 
        {
            var result = new byte[iv.Length + encrypted.Length];
            Buffer.BlockCopy(iv, 0, result, 0, iv.Length);
            Buffer.BlockCopy(encrypted, 0, result, iv.Length, encrypted.Length);
            return result;
        }
        catch (Exception ex)
        {
             throw new InvalidOperationException("Encryption processing failed.", ex);
        }
    }

    public async Task<byte[]> DecryptAsync(byte[] data, CancellationToken cancellationToken = default)
    {
        // Extract IV (12 bytes for GCM, but we used AES default which is likely CBC/PKCS7 with 16 bytes IV Block Size for AES)
        // Actually we need to check the BlockSize from the Cipher.
        // For simplicity and robustness, we assume AES/CBC/PKCS7Padding which has 16 bytes IV.
        // However, let's just use the IV size from the Cipher instance if possible, or fixed size.
        // We will use AES/CBC/PKCS7Padding.
        
        // Wait, we need to create the cipher first to know what it expects? 
        // No, we need to init the cipher with the IV from the data.
        
        const int ivLength = 16; // AES block size
        if (data.Length < ivLength)
        {
            throw new ArgumentException("Invalid data length.");
        }

        var iv = new byte[ivLength];
        Buffer.BlockCopy(data, 0, iv, 0, ivLength);
        
        var cipherText = new byte[data.Length - ivLength];
        Buffer.BlockCopy(data, ivLength, cipherText, 0, cipherText.Length);

        var cipher = GetCipher(Javax.Crypto.CipherMode.DecryptMode, iv);
        var outcome = await AuthenticateInternalAsync("Tresor entsperren", cipher, cancellationToken).ConfigureAwait(false);

        if (outcome is not null || cipher is null)
        {
             throw new BiometricAuthenticationException(outcome ?? BiometricAuthOutcome.Unavailable,
                 "Biometric authentication failed or cancelled.");
        }

        try 
        {
            return cipher.DoFinal(cipherText);
        }
        catch (Java.Lang.Exception ex)
        {
            // Catch Java Cryptographic exceptions (BadPadding, etc.)
            // Treat as Unauthorized/Invalid Key
            throw new UnauthorizedAccessException("Decryption failed.", ex);
        }
    }

    private async Task<BiometricAuthOutcome?> AuthenticateInternalAsync(string reason, Javax.Crypto.Cipher? cipher, CancellationToken cancellationToken)
    {
         if (string.IsNullOrWhiteSpace(reason))
        {
            reason = "Authentifizierung erforderlich";
        }

        var activity = Microsoft.Maui.ApplicationModel.Platform.CurrentActivity;
        if (activity is null)
        {
            return BiometricAuthOutcome.Unavailable;
        }

        if (activity is not AndroidX.Fragment.App.FragmentActivity fragmentActivity)
        {
            return BiometricAuthOutcome.Unavailable;
        }

        var callback = new AndroidBiometricAuthCallback();
        await Microsoft.Maui.ApplicationModel.MainThread.InvokeOnMainThreadAsync(() =>
        {
            try 
            {
                var executor = AndroidX.Core.Content.ContextCompat.GetMainExecutor(fragmentActivity);
                var prompt = new AndroidX.Biometric.BiometricPrompt(fragmentActivity, executor, callback);
                callback.SetPrompt(prompt);

                var promptInfoBuilder = new AndroidX.Biometric.BiometricPrompt.PromptInfo.Builder()
                    .SetTitle("Passwort Tresor")
                    .SetSubtitle(reason)
                    .SetNegativeButtonText("Abbrechen")
                    .SetConfirmationRequired(false);

                promptInfoBuilder.SetAllowedAuthenticators((int)AndroidX.Biometric.BiometricManager.Authenticators.BiometricStrong);

                var promptInfo = promptInfoBuilder.Build();

                if (cipher != null)
                {
                     var cryptoObject = new AndroidX.Biometric.BiometricPrompt.CryptoObject(cipher);
                     prompt.Authenticate(promptInfo, cryptoObject);
                }
                else
                {
                    prompt.Authenticate(promptInfo);
                }
            }
            catch (Exception)
            {
                // Catch any binding/cast errors on the UI thread to prevent crash
                callback.FailUnavailable();
            }
        });

        using var registration = cancellationToken.Register(callback.Cancel);

        try
        {
            return await callback.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return BiometricAuthOutcome.Cancelled;
        }
        catch (Exception)
        {
            return BiometricAuthOutcome.Unavailable;
        }
    }

    private Javax.Crypto.Cipher GetCipher(Javax.Crypto.CipherMode mode, byte[]? iv = null)
    {
        var keyStore = Java.Security.KeyStore.GetInstance(AndroidKeyStore);
        keyStore.Load(null);

        if (!keyStore.ContainsAlias(KeyAlias))
        {
            if (mode == Javax.Crypto.CipherMode.DecryptMode)
            {
                 throw new InvalidOperationException("Key not found.");
            }
            GenerateKey();
        }

        var key = keyStore.GetKey(KeyAlias, null);
        var cipher = Javax.Crypto.Cipher.GetInstance("AES/CBC/PKCS7Padding");

        if (mode == Javax.Crypto.CipherMode.EncryptMode)
        {
            cipher.Init(mode, key);
        }
        else
        {
            var ivSpec = new Javax.Crypto.Spec.IvParameterSpec(iv);
            cipher.Init(mode, key, ivSpec);
        }

        return cipher;
    }

    private void GenerateKey()
    {
        var keyGenerator = Javax.Crypto.KeyGenerator.GetInstance(Android.Security.Keystore.KeyProperties.KeyAlgorithmAes, AndroidKeyStore);
        var builder = new Android.Security.Keystore.KeyGenParameterSpec.Builder(KeyAlias, 
             Android.Security.Keystore.KeyStorePurpose.Encrypt | Android.Security.Keystore.KeyStorePurpose.Decrypt)
             .SetBlockModes(Android.Security.Keystore.KeyProperties.BlockModeCbc)
             .SetEncryptionPaddings(Android.Security.Keystore.KeyProperties.EncryptionPaddingPkcs7)
             .SetUserAuthenticationRequired(true) // Crucial for security
             .SetInvalidatedByBiometricEnrollment(true);
        
        if (OperatingSystem.IsAndroidVersionAtLeast(30))
        {
             builder.SetUserAuthenticationParameters(0, (int)Android.Security.Keystore.KeyPropertiesAuthType.BiometricStrong);
        }
        else
        {
             // For older versions, -1 means effectively "any biometric"
             builder.SetUserAuthenticationValidityDurationSeconds(-1);
        }

        keyGenerator.Init(builder.Build());
        keyGenerator.GenerateKey();
    }


    private sealed class AndroidBiometricAuthCallback : AndroidX.Biometric.BiometricPrompt.AuthenticationCallback
    {
        private readonly TaskCompletionSource<BiometricAuthOutcome?> _taskCompletionSource = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private AndroidX.Biometric.BiometricPrompt? _prompt;
        private int _failedScans;

        public Task<BiometricAuthOutcome?> Task => _taskCompletionSource.Task;

        public void SetPrompt(AndroidX.Biometric.BiometricPrompt prompt)
        {
            _prompt = prompt;
        }

        public void Cancel()
        {
            var prompt = _prompt;
            if (prompt is null)
            {
                return;
            }

            Microsoft.Maui.ApplicationModel.MainThread.BeginInvokeOnMainThread(prompt.CancelAuthentication);
        }

        public void FailUnavailable()
        {
            _taskCompletionSource.TrySetResult(BiometricAuthOutcome.Unavailable);
            Cancel();
        }

        public override void OnAuthenticationSucceeded(AndroidX.Biometric.BiometricPrompt.AuthenticationResult result)
        {
            // IMPORTANT: If we used CryptoObject, result.CryptoObject.Cipher should be the authenticated cipher.
            // Using the existing cipher instance *should* work as it's modified in place by the authentication (unlocked).
            _taskCompletionSource.TrySetResult(null);
        }

        public override void OnAuthenticationFailed()
        {
            if (++_failedScans >= 2)
            {
                _taskCompletionSource.TrySetResult(BiometricAuthOutcome.Rejected);
                Cancel();
            }
        }

        public override void OnAuthenticationError(int errorCode, Java.Lang.ICharSequence? errString)
        {
            if (errorCode == AndroidX.Biometric.BiometricPrompt.ErrorCanceled || 
                errorCode == AndroidX.Biometric.BiometricPrompt.ErrorUserCanceled ||
                errorCode == AndroidX.Biometric.BiometricPrompt.ErrorNegativeButton)
            {
                _taskCompletionSource.TrySetResult(_failedScans > 0
                    ? BiometricAuthOutcome.Rejected : BiometricAuthOutcome.Cancelled);
                return;
            }

            _taskCompletionSource.TrySetResult(_failedScans > 0 ||
                errorCode == AndroidX.Biometric.BiometricPrompt.ErrorLockout ||
                errorCode == AndroidX.Biometric.BiometricPrompt.ErrorLockoutPermanent
                ? BiometricAuthOutcome.Rejected : BiometricAuthOutcome.Unavailable);
        }
    }
#elif WINDOWS
    private const string WindowsKeyName = "PasswordPhraseProducerBiometricKey_V2";
    public async Task<bool> IsAvailableAsync(CancellationToken cancellationToken = default)
    {
        try 
        {
            var output = await global::Windows.Security.Credentials.UI.UserConsentVerifier.CheckAvailabilityAsync();
            return output == global::Windows.Security.Credentials.UI.UserConsentVerifierAvailability.Available;
        }
        catch (Exception)
        {
            // If the API is not available or throws, assume biometrics are not available.
            return false;
        }
    }

    public async Task<bool> AuthenticateAsync(string reason, CancellationToken cancellationToken = default)
    {
        return await RequestWindowsVerificationAsync(reason, cancellationToken).ConfigureAwait(false) is null;
    }

    private static async Task<BiometricAuthOutcome?> RequestWindowsVerificationAsync(
        string reason, CancellationToken cancellationToken)
    {
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            var result = await global::Windows.Security.Credentials.UI.UserConsentVerifier.RequestVerificationAsync(reason);
            return result switch
            {
                global::Windows.Security.Credentials.UI.UserConsentVerificationResult.Verified => null,
                global::Windows.Security.Credentials.UI.UserConsentVerificationResult.RetriesExhausted => BiometricAuthOutcome.Rejected,
                global::Windows.Security.Credentials.UI.UserConsentVerificationResult.Canceled => BiometricAuthOutcome.Cancelled,
                _ => BiometricAuthOutcome.Unavailable
            };
        }
        catch (OperationCanceledException) { return BiometricAuthOutcome.Cancelled; }
        catch
        {
            return BiometricAuthOutcome.Unavailable;
        }
    }

    public async Task<byte[]> EncryptAsync(byte[] data, CancellationToken cancellationToken = default)
    {
        var outcome = await RequestWindowsVerificationAsync("Biometrie einrichten", cancellationToken).ConfigureAwait(false);
        if (outcome is not null)
            throw new BiometricAuthenticationException(outcome.Value, "Windows Hello wurde abgebrochen oder ist fehlgeschlagen.");
        EnsureKeyExists(createIfMissing: true);
        
        // 2. Use AesCng with Named Key
        using var aes = new System.Security.Cryptography.AesCng(WindowsKeyName, System.Security.Cryptography.CngProvider.MicrosoftSoftwareKeyStorageProvider);
        aes.KeySize = 256;
        aes.Mode = System.Security.Cryptography.CipherMode.CBC; 
        aes.Padding = System.Security.Cryptography.PaddingMode.PKCS7;
        
        // Generate IV
        aes.GenerateIV();
        var iv = aes.IV;
        
        // Encrypt
        using var encryptor = aes.CreateEncryptor();
        var cipherText = encryptor.TransformFinalBlock(data, 0, data.Length);
        
        // Combine IV + Cipher
        var result = new byte[iv.Length + cipherText.Length];
        Buffer.BlockCopy(iv, 0, result, 0, iv.Length);
        Buffer.BlockCopy(cipherText, 0, result, iv.Length, cipherText.Length);
        
        return result;
    }

    public async Task<byte[]> DecryptAsync(byte[] data, CancellationToken cancellationToken = default)
    {
        const int ivLength = 16; // AES IV default
        if (data.Length < ivLength) throw new ArgumentException("Invalid data length");
        
        // Extract IV
        var iv = new byte[ivLength];
        Buffer.BlockCopy(data, 0, iv, 0, ivLength);
        
        var cipherText = new byte[data.Length - ivLength];
        Buffer.BlockCopy(data, ivLength, cipherText, 0, cipherText.Length);
        
        var outcome = await RequestWindowsVerificationAsync("Tresor entsperren", cancellationToken).ConfigureAwait(false);
        if (outcome is not null)
            throw new BiometricAuthenticationException(outcome.Value, "Windows Hello wurde abgebrochen oder ist fehlgeschlagen.");
        EnsureKeyExists(createIfMissing: false);
        
        using var aes = new System.Security.Cryptography.AesCng(WindowsKeyName, System.Security.Cryptography.CngProvider.MicrosoftSoftwareKeyStorageProvider);
        aes.KeySize = 256;
        aes.Mode = System.Security.Cryptography.CipherMode.CBC;
        aes.Padding = System.Security.Cryptography.PaddingMode.PKCS7;
        aes.IV = iv;
        
        try 
        {
            // Decrypt
            using var decryptor = aes.CreateDecryptor();
            // This line specifically should trigger the Windows Hello Prompt because the handle usage requires consent.
            return decryptor.TransformFinalBlock(cipherText, 0, cipherText.Length);
        }
        catch (System.Security.Cryptography.CryptographicException ex)
        {
            // If user cancels or authentication fails, CNG throws a CryptographicException.
            throw new BiometricAuthenticationException(BiometricAuthOutcome.Unavailable,
                $"Biometric decryption failed: {ex.GetType().Name}.");
        }
    }

    private void EnsureKeyExists(bool createIfMissing)
    {
        if (System.Security.Cryptography.CngKey.Exists(WindowsKeyName, System.Security.Cryptography.CngProvider.MicrosoftSoftwareKeyStorageProvider))
        {
            using var existing = System.Security.Cryptography.CngKey.Open(WindowsKeyName, System.Security.Cryptography.CngProvider.MicrosoftSoftwareKeyStorageProvider);
            if (existing.UIPolicy?.ProtectionLevel != System.Security.Cryptography.CngUIProtectionLevels.ForceHighProtection)
                throw new BiometricAuthenticationException(BiometricAuthOutcome.Unavailable,
                    "Der biometrische Schlüssel hat keine erzwungene Geräteauthentifizierung.");
            return;
        }

        if (!createIfMissing)
            throw new BiometricAuthenticationException(BiometricAuthOutcome.Unavailable,
                "Der biometrische Geräteschlüssel fehlt.");
        
        // Create new
        var keyCreationParams = new System.Security.Cryptography.CngKeyCreationParameters
        {
            Provider = System.Security.Cryptography.CngProvider.MicrosoftSoftwareKeyStorageProvider,
            KeyUsage = System.Security.Cryptography.CngKeyUsages.AllUsages,
            // ForceHighProtection means: "The user is prompted for a password or consent UI when the key is used."
            UIPolicy = new System.Security.Cryptography.CngUIPolicy(
                System.Security.Cryptography.CngUIProtectionLevels.ForceHighProtection, 
                "Zugriff auf Passwort-Tresor", 
                "Verwenden Sie Windows Hello (PIN/Biometrie) oder Ihr Passwort, um den Tresor zu entschlüsseln.", 
                null)
        };
        
        using var key = System.Security.Cryptography.CngKey.Create(new System.Security.Cryptography.CngAlgorithm("AES"), WindowsKeyName, keyCreationParams);
    }

#else
    // A prompt alone does not protect key material. Until this platform has a
    // hardware/Keychain bound encryption implementation, biometric unlock is disabled.
    public Task<bool> IsAvailableAsync(CancellationToken cancellationToken = default) => Task.FromResult(false);
    public Task<bool> AuthenticateAsync(string reason, CancellationToken cancellationToken = default) => Task.FromResult(false);
    public Task<byte[]> EncryptAsync(byte[] data, CancellationToken cancellationToken = default) =>
        throw new NotSupportedException("Biometric key protection is unavailable on this platform.");
    public Task<byte[]> DecryptAsync(byte[] data, CancellationToken cancellationToken = default) =>
        throw new NotSupportedException("Biometric key protection is unavailable on this platform.");
#endif
}
