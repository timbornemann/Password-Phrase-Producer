namespace Password_Phrase_Producer.Services.EntropyAnalyzer;

public interface IPasswordEntropyAnalyzer
{
    EntropyAnalysisResult Analyze(string password);
}
