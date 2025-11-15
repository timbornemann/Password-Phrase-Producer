namespace Password_Phrase_Producer.PasswordGenerationTechniques.Base64EncoderTechnique;

public interface IBase64EncoderTechnique
{
    string GeneratePassword(string input);
}

