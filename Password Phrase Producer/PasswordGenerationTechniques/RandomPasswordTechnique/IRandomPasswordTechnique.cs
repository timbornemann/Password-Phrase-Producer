namespace Password_Phrase_Producer.PasswordGenerationTechniques.RandomPasswordTechnique;

public interface IRandomPasswordTechnique
{
    string GeneratePassword(int length, bool includeUppercase, bool includeLowercase, bool includeDigits, bool includeSpecial, string? seed = null);
}

