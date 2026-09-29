using System.Text;

namespace Password_Phrase_Producer.Services.Security;

internal static class NewPasswordPolicy
{
    private const int MinimumCharacters = 15;

    internal static void Validate(string? password, string parameterName)
    {
        if (string.IsNullOrWhiteSpace(password) || password.EnumerateRunes().Count() < MinimumCharacters)
            throw new ArgumentException("Verwende mindestens 15 Zeichen für ein neues Master- oder Backup-Passwort.", parameterName);

        // Length alone is not strength. Reject obvious patterns without imposing
        // character-class rules that would discourage long passphrases.
        var trimmed = password.Trim();
        if (trimmed.All(c => c == trimmed[0]) ||
            trimmed.Equals("password123456789", StringComparison.OrdinalIgnoreCase) ||
            trimmed.Equals("passwort123456789", StringComparison.OrdinalIgnoreCase) ||
            trimmed.Equals("123456789012345", StringComparison.Ordinal))
            throw new ArgumentException("Dieses Passwort ist zu leicht zu erraten. Verwende eine längere, zufällige Passphrase.", parameterName);
    }
}
