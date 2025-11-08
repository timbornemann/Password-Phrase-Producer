namespace Password_Phrase_Producer.PasswordGenerationTechniques.SymbolInjectionTechnique
{
    public interface ISymbolInjectionTechnique
    {
        string InjectSymbols(string input, int symbolCount, bool randomizeCase, string? seed);
    }
}
