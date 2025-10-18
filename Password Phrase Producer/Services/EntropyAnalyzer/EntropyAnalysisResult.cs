using System;
using System.Collections.Generic;

namespace Password_Phrase_Producer.Services.EntropyAnalyzer;

public sealed record CharacterBreakdown(int Uppercase, int Lowercase, int Digits, int Symbols, int Spaces);

public sealed record EntropyAnalysisResult(
    string Password,
    int Length,
    double Entropy,
    double StrengthScore,
    string StrengthLabel,
    int CharacterSetSize,
    int CharacterGroupCount,
    CharacterBreakdown Breakdown,
    IReadOnlyList<string> Suggestions)
{
    public static EntropyAnalysisResult Empty { get; } = new(
        string.Empty,
        0,
        0,
        0,
        "Unbewertet",
        0,
        0,
        new CharacterBreakdown(0, 0, 0, 0, 0),
        Array.Empty<string>());
}
