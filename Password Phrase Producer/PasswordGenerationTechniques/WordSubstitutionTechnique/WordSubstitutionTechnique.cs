using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Password_Phrase_Producer.PasswordGenerationTechniques.WordSubstitutionTechnique;

internal class WordSubstitutionTechnique : IWordSubstitutionTechnique
{
    private static readonly Dictionary<char, string> LeetSpeakMap = new()
    {
        {'a', "4"}, {'A', "4"},
        {'e', "3"}, {'E', "3"},
        {'i', "1"}, {'I', "1"},
        {'o', "0"}, {'O', "0"},
        {'s', "5"}, {'S', "5"},
        {'t', "7"}, {'T', "7"},
        {'l', "1"}, {'L', "1"},
        {'g', "9"}, {'G', "9"},
        {'b', "8"}, {'B', "8"},
        {'z', "2"}, {'Z', "2"}
    };

    private static readonly Dictionary<string, string> SymbolSubstitutions = new()
    {
        {"and", "&"}, {"at", "@"}, {"for", "4"}, {"to", "2"},
        {"you", "u"}, {"be", "b"}, {"are", "r"}, {"the", "th"},
        {"one", "1"}, {"two", "2"}, {"three", "3"}, {"four", "4"},
        {"five", "5"}, {"six", "6"}, {"seven", "7"}, {"eight", "8"},
        {"nine", "9"}, {"ten", "10"}
    };

    public string GeneratePassword(string input, bool useLeetSpeak, bool useSymbols)
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            return string.Empty;
        }

        string result = input;

        // Apply symbol substitutions first (word-level)
        if (useSymbols)
        {
            foreach (var substitution in SymbolSubstitutions.OrderByDescending(x => x.Key.Length))
            {
                result = result.Replace(substitution.Key, substitution.Value, StringComparison.OrdinalIgnoreCase);
            }
        }

        // Apply leet speak (character-level)
        if (useLeetSpeak)
        {
            StringBuilder sb = new StringBuilder(result.Length);
            foreach (char c in result)
            {
                if (LeetSpeakMap.TryGetValue(c, out string? replacement))
                {
                    sb.Append(replacement);
                }
                else
                {
                    sb.Append(c);
                }
            }
            result = sb.ToString();
        }

        return result;
    }
}

