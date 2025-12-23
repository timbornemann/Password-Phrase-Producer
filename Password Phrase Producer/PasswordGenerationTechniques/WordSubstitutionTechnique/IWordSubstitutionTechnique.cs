namespace Password_Phrase_Producer.PasswordGenerationTechniques.WordSubstitutionTechnique;

public interface IWordSubstitutionTechnique
{
    string GeneratePassword(string input, bool useLeetSpeak, bool useSymbols);
}


