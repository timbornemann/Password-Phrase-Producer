namespace Password_Phrase_Producer.PasswordGenerationTechniques.PatternCascadeTechnique
{
    public interface IPatternCascadeTechnique
    {
        string CreatePassword(string primaryWord, string secondaryWord, string numericToken);
    }
}
