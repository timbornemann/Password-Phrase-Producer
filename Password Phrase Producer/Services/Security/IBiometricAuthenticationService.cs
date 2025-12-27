using System.Threading;
using System.Threading.Tasks;

namespace Password_Phrase_Producer.Services.Security;

public interface IBiometricAuthenticationService
{
    Task<bool> IsAvailableAsync(CancellationToken cancellationToken = default);

    Task<bool> AuthenticateAsync(string reason, CancellationToken cancellationToken = default);

    Task<byte[]> EncryptAsync(byte[] data, CancellationToken cancellationToken = default);

    Task<byte[]> DecryptAsync(byte[] data, CancellationToken cancellationToken = default);
}
