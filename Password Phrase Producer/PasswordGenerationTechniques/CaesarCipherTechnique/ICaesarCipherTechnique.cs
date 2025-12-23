namespace Password_Phrase_Producer.PasswordGenerationTechniques.CaesarCipherTechnique;

public interface ICaesarCipherTechnique
{
    string GeneratePassword(string input, int shift);
}


