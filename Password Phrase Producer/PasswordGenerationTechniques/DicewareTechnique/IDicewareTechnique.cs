namespace Password_Phrase_Producer.PasswordGenerationTechniques.DicewareTechnique
{
    public interface IDicewareTechnique
    {
        string Generate(int wordCount, string? seed);
    }
}
