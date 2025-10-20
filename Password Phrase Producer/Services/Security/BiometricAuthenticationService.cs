using System;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;

namespace Password_Phrase_Producer.Services.Security;

public class BiometricAuthenticationService : IBiometricAuthenticationService
{
#if ANDROID
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
        if (string.IsNullOrWhiteSpace(reason))
        {
            reason = "Authentifizierung erforderlich";
        }

        var activity = Microsoft.Maui.ApplicationModel.Platform.CurrentActivity;
        if (activity is null)
        {
            return false;
        }

        var callback = new AndroidBiometricAuthCallback();
        await Microsoft.Maui.ApplicationModel.MainThread.InvokeOnMainThreadAsync(() =>
        {
            var executor = AndroidX.Core.Content.ContextCompat.GetMainExecutor(activity);
            var prompt = new AndroidX.Biometric.BiometricPrompt(activity, executor, callback);
            callback.SetPrompt(prompt);

            var promptInfoBuilder = new AndroidX.Biometric.BiometricPrompt.PromptInfo.Builder()
                .SetTitle("Tresor entsperren")
                .SetSubtitle(reason)
                .SetNegativeButtonText("Abbrechen")
                .SetConfirmationRequired(false);

            if (OperatingSystem.IsAndroidVersionAtLeast(30))
            {
                promptInfoBuilder.SetAllowedAuthenticators((int)(AndroidX.Biometric.BiometricManager.Authenticators.BiometricStrong |
                                                                 AndroidX.Biometric.BiometricManager.Authenticators.BiometricWeak));
            }

            var promptInfo = promptInfoBuilder.Build();
            prompt.Authenticate(promptInfo);
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
            _taskCompletionSource.TrySetResult(true);
        }

        public override void OnAuthenticationFailed()
        {
            // keep waiting for another attempt
        }

        public override void OnAuthenticationError(int errorCode, Java.Lang.ICharSequence? errString)
        {
            if (errorCode == AndroidX.Biometric.BiometricPrompt.ErrorCanceled)
            {
                _taskCompletionSource.TrySetCanceled();
                return;
            }

            _taskCompletionSource.TrySetResult(false);
        }
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
            Title = "Tresor entsperren",
            Subtitle = reason,
            NegativeText = "Abbrechen"
        };

        var result = await Plugin.Maui.Biometric.BiometricAuthenticationService.Default
            .AuthenticateAsync(request, cancellationToken)
            .ConfigureAwait(false);

        return result.Status == Plugin.Maui.Biometric.BiometricResponseStatus.Success;
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
