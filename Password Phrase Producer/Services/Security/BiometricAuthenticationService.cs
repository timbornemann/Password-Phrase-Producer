using System.Threading;
using System.Threading.Tasks;
using Plugin.Fingerprint;
using Plugin.Fingerprint.Abstractions;

namespace Password_Phrase_Producer.Services.Security;

public class BiometricAuthenticationService : IBiometricAuthenticationService
{
    public async Task<bool> IsAvailableAsync(CancellationToken cancellationToken = default)
    {
        return await CrossFingerprint.Current.IsAvailableAsync(true).ConfigureAwait(false);
    }

    public async Task<bool> AuthenticateAsync(string reason, CancellationToken cancellationToken = default)
    {
        var request = new AuthenticationRequestConfiguration("Tresor entsperren", reason)
        {
            AllowAlternativeAuthentication = true,
            CancelTitle = "Abbrechen"
        };

        var result = await CrossFingerprint.Current.AuthenticateAsync(request).ConfigureAwait(false);
        return result.Authenticated;
    }
}
