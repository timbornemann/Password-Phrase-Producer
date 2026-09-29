using System;
using System.Collections.Generic;

namespace Password_Phrase_Producer.Services.EntropyAnalyzer;

public sealed class PasswordEntropyAnalyzer : IPasswordEntropyAnalyzer
{
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

        // Appearance alone does not reveal how a password was generated. Deterministic
        // transformations can look random while having almost no unpredictable entropy.
        var suggestions = new[]
        {
            "Aus Länge und Zeichenarten allein lässt sich keine Stärke berechnen. Nutze für neue Passwörter den Zufallsgenerator."
        };

        var breakdown = new CharacterBreakdown(uppercase, lowercase, digits, symbols, spaces);

        return new EntropyAnalysisResult(
            normalizedPassword,
            length,
            double.NaN,
            0,
            "Nicht messbar",
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

}
