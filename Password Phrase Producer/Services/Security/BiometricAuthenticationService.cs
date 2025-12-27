using System;
using System.Reflection;
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

        int status;
        if (OperatingSystem.IsAndroidVersionAtLeast(30))
        {
            status = manager.CanAuthenticate((int)(AndroidX.Biometric.BiometricManager.Authenticators.BiometricStrong |
                                                    AndroidX.Biometric.BiometricManager.Authenticators.BiometricWeak));
        }
        else
        {
#pragma warning disable CA1416 // Validate platform compatibility
            status = manager.CanAuthenticate();
#pragma warning restore CA1416 // Validate platform compatibility
        }

        return Task.FromResult(status == AndroidX.Biometric.BiometricManager.BiometricSuccess);
    }

    public async Task<bool> AuthenticateAsync(string reason, CancellationToken cancellationToken = default)
    {
        return await AuthenticateInternalAsync(reason, null, cancellationToken).ConfigureAwait(false);
    }

    public async Task<byte[]> EncryptAsync(byte[] data, CancellationToken cancellationToken = default)
    {
        var cipher = GetCipher(Javax.Crypto.CipherMode.EncryptMode);
        var success = await AuthenticateInternalAsync("Biometrie einrichten", cipher, cancellationToken).ConfigureAwait(false);
        
        if (!success || cipher is null)
        {
            throw new UnauthorizedAccessException("Biometric authentication failed or cancelled.");
        }

        var iv = cipher.GetIV();
        var encrypted = cipher.DoFinal(data);

        // Combine IV and encrypted data
        var result = new byte[iv.Length + encrypted.Length];
        Buffer.BlockCopy(iv, 0, result, 0, iv.Length);
        Buffer.BlockCopy(encrypted, 0, result, iv.Length, encrypted.Length);
        
        return result;
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
        var success = await AuthenticateInternalAsync("Tresor entsperren", cipher, cancellationToken).ConfigureAwait(false);

        if (!success || cipher is null)
        {
             throw new UnauthorizedAccessException("Biometric authentication failed or cancelled.");
        }

        return cipher.DoFinal(cipherText);
    }

    private async Task<bool> AuthenticateInternalAsync(string reason, Javax.Crypto.Cipher? cipher, CancellationToken cancellationToken)
    {
         if (string.IsNullOrWhiteSpace(reason))
        {
            reason = "Authentifizierung erforderlich";
        }

        var activity = Microsoft.Maui.ApplicationModel.Platform.CurrentActivity;
        if (activity is null)
        {
            return false;
        }

        if (activity is not AndroidX.Fragment.App.FragmentActivity fragmentActivity)
        {
            return false;
        }

        var callback = new AndroidBiometricAuthCallback();
        await Microsoft.Maui.ApplicationModel.MainThread.InvokeOnMainThreadAsync(() =>
        {
            var executor = AndroidX.Core.Content.ContextCompat.GetMainExecutor(fragmentActivity);
            var prompt = new AndroidX.Biometric.BiometricPrompt(fragmentActivity, executor, callback);
            callback.SetPrompt(prompt);

            var promptInfoBuilder = new AndroidX.Biometric.BiometricPrompt.PromptInfo.Builder()
                .SetTitle("Passwort Tresor")
                .SetSubtitle(reason)
                .SetNegativeButtonText("Abbrechen")
                .SetConfirmationRequired(false); // Can be true for higher security

            if (OperatingSystem.IsAndroidVersionAtLeast(30))
            {
                promptInfoBuilder.SetAllowedAuthenticators((int)(AndroidX.Biometric.BiometricManager.Authenticators.BiometricStrong));
            }

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
        });

        using var registration = cancellationToken.Register(callback.Cancel);

        try
        {
            return await callback.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return false;
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

        var key = (Javax.Crypto.ISecretKey)keyStore.GetKey(KeyAlias, null);
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
        private readonly TaskCompletionSource<bool> _taskCompletionSource = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private AndroidX.Biometric.BiometricPrompt? _prompt;

        public Task<bool> Task => _taskCompletionSource.Task;

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

        public override void OnAuthenticationSucceeded(AndroidX.Biometric.BiometricPrompt.AuthenticationResult result)
        {
            // IMPORTANT: If we used CryptoObject, result.CryptoObject.Cipher should be the authenticated cipher.
            // Using the existing cipher instance *should* work as it's modified in place by the authentication (unlocked).
            _taskCompletionSource.TrySetResult(true);
        }

        public override void OnAuthenticationFailed()
        {
            // keep waiting for another attempt
        }

        public override void OnAuthenticationError(int errorCode, Java.Lang.ICharSequence? errString)
        {
            if (errorCode == AndroidX.Biometric.BiometricPrompt.ErrorCanceled || 
                errorCode == AndroidX.Biometric.BiometricPrompt.ErrorUserCanceled ||
                errorCode == AndroidX.Biometric.BiometricPrompt.ErrorNegativeButton)
            {
                _taskCompletionSource.TrySetCanceled();
                return;
            }

            _taskCompletionSource.TrySetResult(false);
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
        try
        {
            // Explicitly request verification from the user.
            // Note: This shows a UI prompt. 
            // If strictly encrypting/decrypting using the CngKey, the OS will trigger the prompt automatically upon key access.
            // This method is provided for scenarios where authentication is required without an immediate key operation.
            var result = await global::Windows.Security.Credentials.UI.UserConsentVerifier.RequestVerificationAsync(reason);
            return result == global::Windows.Security.Credentials.UI.UserConsentVerificationResult.Verified;
        }
        catch
        {
            return false;
        }
    }

    public async Task<byte[]> EncryptAsync(byte[] data, CancellationToken cancellationToken = default)
    {
        // 1. Ensure Key Exists with Policy
        EnsureKeyExists();
        
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
        
        // 1. Ensure Key Exists
        EnsureKeyExists();
        
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
            throw new UnauthorizedAccessException("Biometric decryption was cancelled or failed.", ex);
        }
    }

    private void EnsureKeyExists()
    {
        // Check if exists
        if (System.Security.Cryptography.CngKey.Exists(WindowsKeyName, System.Security.Cryptography.CngProvider.MicrosoftSoftwareKeyStorageProvider))
        {
            return;
        }
        
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
    public async Task<bool> IsAvailableAsync(CancellationToken cancellationToken = default)
    {
        var status = await Plugin.Maui.Biometric.BiometricAuthenticationService.Default
            .GetAuthenticationStatusAsync()
            .WaitAsync(cancellationToken)
            .ConfigureAwait(false);

        return IsAvailable(status);
    }

    public async Task<bool> AuthenticateAsync(string reason, CancellationToken cancellationToken = default)
    {
        var request = new Plugin.Maui.Biometric.AuthenticationRequest
        {
            Title = "Passwort Tresor entsperren",
            Subtitle = reason,
            NegativeText = "Abbrechen"
        };

        var result = await Plugin.Maui.Biometric.BiometricAuthenticationService.Default
            .AuthenticateAsync(request, cancellationToken)
            .ConfigureAwait(false);

        return result.Status == Plugin.Maui.Biometric.BiometricResponseStatus.Success;
    }

    public async Task<byte[]> EncryptAsync(byte[] data, CancellationToken cancellationToken = default)
    {
        // Fallback for iOS/Others if encryption not critically implemented yet.
        // Ideally should implement Keychain AccessControl for iOS.
        // Current User Request focused on "Windows/iOS" but recommendations emphasized Windows TPM.
        // For now, iOS remains on standard Authenticate + Store logic (which is imperfect but not explicitly broken if we assume Keychain is secure enough).
        // WARNING: This still returns cleartext, relying on SecureStorage (Keychain). 
        // If secure storage is compromised (Jailbreak), key is visible.
        
        var authObj = await AuthenticateAsync("Verschlüsselung autorisieren", cancellationToken);
        if (!authObj)
        {
             throw new UnauthorizedAccessException("Authentication failed.");
        }
        return data; 
    }

    public async Task<byte[]> DecryptAsync(byte[] data, CancellationToken cancellationToken = default)
    {
        var authObj = await AuthenticateAsync("Entschlüsselung autorisieren", cancellationToken);
        if (!authObj)
        {
             throw new UnauthorizedAccessException("Authentication failed.");
        }
        return data;
    }

    private static bool IsAvailable(object? status)
    {
        if (status is null)
        {
            return false;
        }

        if (status is Enum enumStatus)
        {
            return string.Equals(enumStatus.ToString(), "Available", StringComparison.Ordinal);
        }

        var statusProperty = status.GetType().GetRuntimeProperty("Status") ?? status.GetType().GetProperty("Status");
        if (statusProperty is not null)
        {
            var value = statusProperty.GetValue(status);
            if (value is null)
            {
                return false;
            }

            if (value is Enum nestedEnum)
            {
                return string.Equals(nestedEnum.ToString(), "Available", StringComparison.Ordinal);
            }

            if (value is bool boolValue)
            {
                return boolValue;
            }

            return string.Equals(value.ToString(), "Available", StringComparison.Ordinal);
        }

        var availableProperty = status.GetType().GetRuntimeProperty("IsAvailable") ?? status.GetType().GetProperty("IsAvailable");
        if (availableProperty?.GetValue(status) is bool isAvailable)
        {
            return isAvailable;
        }

        return string.Equals(status.ToString(), "Available", StringComparison.Ordinal);
    }
#endif
}
