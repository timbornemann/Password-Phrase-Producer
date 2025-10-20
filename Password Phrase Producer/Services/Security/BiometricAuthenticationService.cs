using System;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using Plugin.Maui.Biometric;
using PluginBiometricService = Plugin.Maui.Biometric.BiometricAuthenticationService;

namespace Password_Phrase_Producer.Services.Security;

public class BiometricAuthenticationService : IBiometricAuthenticationService
{
    public async Task<bool> IsAvailableAsync(CancellationToken cancellationToken = default)
    {
        var status = await PluginBiometricService.Default
            .GetAuthenticationStatusAsync()
            .WaitAsync(cancellationToken)
            .ConfigureAwait(false);

        return IsAvailable(status);
    }

    public async Task<bool> AuthenticateAsync(string reason, CancellationToken cancellationToken = default)
    {
        var request = new AuthenticationRequest
        {
            Title = "Tresor entsperren",
            Subtitle = reason,
            NegativeText = "Abbrechen"
        };

        var result = await PluginBiometricService.Default
            .AuthenticateAsync(request, cancellationToken)
            .ConfigureAwait(false);

        return result.Status == BiometricResponseStatus.Success;
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
}
