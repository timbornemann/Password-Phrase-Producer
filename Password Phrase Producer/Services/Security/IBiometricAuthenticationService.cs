using System.Threading;
using System.Threading.Tasks;

namespace Password_Phrase_Producer.Services.Security;

public interface IBiometricAuthenticationService
{
    Task<bool> IsAvailableAsync(CancellationToken cancellationToken = default);

    Task<bool> AuthenticateAsync(string reason, CancellationToken cancellationToken = default);
}
