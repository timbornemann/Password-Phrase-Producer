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
            .GetAuthenticationStatusAsync(cancellationToken)
            .ConfigureAwait(false);

        return status == BiometricStatus.Available;
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
}
