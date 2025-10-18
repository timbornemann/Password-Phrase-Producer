using System;
using System.Collections.Generic;

namespace Password_Phrase_Producer.Services.EntropyAnalyzer;

public sealed class PasswordEntropyAnalyzer : IPasswordEntropyAnalyzer
{
    private const double TargetEntropy = 120d;
    private const double MaxLengthReference = 24d;

    public EntropyAnalysisResult Analyze(string password)
    {
        if (string.IsNullOrWhiteSpace(password))
        {
            return EntropyAnalysisResult.Empty;
        }

        var normalizedPassword = password;
        int length = normalizedPassword.Length;

        int uppercase = 0;
        int lowercase = 0;
        int digits = 0;
        int symbols = 0;
        int spaces = 0;

        var uniqueCharacters = new HashSet<char>();

        foreach (var c in normalizedPassword)
        {
            uniqueCharacters.Add(c);

            if (char.IsUpper(c))
            {
                uppercase++;
            }
            else if (char.IsLower(c))
            {
                lowercase++;
            }
            else if (char.IsDigit(c))
            {
                digits++;
            }
            else if (char.IsWhiteSpace(c))
            {
                spaces++;
            }
            else
            {
                symbols++;
            }
        }

        int characterSetSize = CalculateCharacterSpace(uppercase, lowercase, digits, symbols, uniqueCharacters.Count);
        int characterGroups = CountCharacterGroups(uppercase, lowercase, digits, symbols);

        double entropy = CalculateEntropy(length, characterSetSize);
        double score = CalculateScore(entropy, length, characterGroups);
        string strengthLabel = GetStrengthLabel(score);

        var suggestions = BuildSuggestions(length, uppercase, lowercase, digits, symbols, uniqueCharacters.Count);

        var breakdown = new CharacterBreakdown(uppercase, lowercase, digits, symbols, spaces);

        return new EntropyAnalysisResult(
            normalizedPassword,
            length,
            Math.Round(entropy, 2, MidpointRounding.AwayFromZero),
            Math.Round(score, 1, MidpointRounding.AwayFromZero),
            strengthLabel,
            characterSetSize,
            characterGroups,
            breakdown,
            suggestions);
    }

    private static int CalculateCharacterSpace(int uppercase, int lowercase, int digits, int symbols, int uniqueCharacterCount)
    {
        int space = 0;

        if (uppercase > 0)
        {
            space += 26;
        }

        if (lowercase > 0)
        {
            space += 26;
        }

        if (digits > 0)
        {
            space += 10;
        }

        if (symbols > 0)
        {
            space += 33;
        }

        // Reward diversity of actual characters without double counting whitespace.
        if (space == 0 && uniqueCharacterCount > 0)
        {
            space = uniqueCharacterCount;
        }

        return Math.Max(space, 1);
    }

    private static int CountCharacterGroups(int uppercase, int lowercase, int digits, int symbols)
    {
        int groups = 0;

        if (uppercase > 0)
        {
            groups++;
        }

        if (lowercase > 0)
        {
            groups++;
        }

        if (digits > 0)
        {
            groups++;
        }

        if (symbols > 0)
        {
            groups++;
        }

        return groups;
    }

    private static double CalculateEntropy(int length, int characterSetSize)
    {
        if (length == 0 || characterSetSize <= 1)
        {
            return 0d;
        }

        return length * Math.Log(characterSetSize, 2);
    }

    private static double CalculateScore(double entropy, int length, int characterGroups)
    {
        double entropyComponent = Math.Min(entropy / TargetEntropy, 1d);
        double lengthComponent = Math.Min(length / MaxLengthReference, 1d);
        double varietyComponent = Math.Min(characterGroups / 4d, 1d);

        double weighted = (entropyComponent * 0.5) + (lengthComponent * 0.2) + (varietyComponent * 0.3);

        return weighted * 100d;
    }

    private static string GetStrengthLabel(double score)
    {
        if (score >= 80d)
        {
            return "Stark";
        }

        if (score >= 55d)
        {
            return "Solide";
        }

        return "Schwach";
    }

    private static IReadOnlyList<string> BuildSuggestions(
        int length,
        int uppercase,
        int lowercase,
        int digits,
        int symbols,
        int uniqueCharacters)
    {
        var suggestions = new List<string>();

        if (length < 12)
        {
            suggestions.Add("Verlängere die Passphrase auf mindestens 12 Zeichen.");
        }

        if (uppercase == 0)
        {
            suggestions.Add("Füge Großbuchstaben hinzu, um den Zeichensatz zu erweitern.");
        }

        if (lowercase == 0)
        {
            suggestions.Add("Integriere Kleinbuchstaben für eine bessere Mischung.");
        }

        if (digits == 0)
        {
            suggestions.Add("Nutze Ziffern, um mehr Kombinationen zu ermöglichen.");
        }

        if (symbols == 0)
        {
            suggestions.Add("Sonderzeichen erhöhen die Komplexität deutlich.");
        }

        if (uniqueCharacters < length / 2)
        {
            suggestions.Add("Vermeide zu viele Wiederholungen von Zeichen.");
        }

        if (suggestions.Count == 0)
        {
            suggestions.Add("Großartig! Deine Passphrase wirkt bereits sehr robust.");
        }

        return suggestions;
    }
}
