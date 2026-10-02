namespace Password_Phrase_Producer.Services.Security;

internal static class NewPasswordPolicy
{
    internal static void Validate(string? password, string parameterName)
    {
        if (string.IsNullOrWhiteSpace(password))
            throw new ArgumentException("Bitte gib ein Passwort ein.", parameterName);
    }
}
