using System.Threading;
using System.Threading.Tasks;

namespace Password_Phrase_Producer.Services.Security;

public enum BiometricAuthOutcome { Rejected, Cancelled, Unavailable }

public sealed class BiometricAuthenticationException : UnauthorizedAccessException
{
    public BiometricAuthOutcome Outcome { get; }
    public BiometricAuthenticationException(BiometricAuthOutcome outcome, string message) : base(message)
        => Outcome = outcome;
}

public interface IBiometricAuthenticationService
{
    Task<bool> IsAvailableAsync(CancellationToken cancellationToken = default);

    Task<bool> AuthenticateAsync(string reason, CancellationToken cancellationToken = default);

    Task<byte[]> EncryptAsync(byte[] data, CancellationToken cancellationToken = default);

    Task<byte[]> DecryptAsync(byte[] data, CancellationToken cancellationToken = default);
}
