using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace Password_Phrase_Producer.PasswordGenerationTechniques.DicewareTechnique
{
    internal class AdaptiveDicewareTechnique : IDicewareTechnique
    {
        private static readonly string[] WordList = LoadWordList();
        private static readonly HashSet<string> SessionWordSet = new(WordList, StringComparer.Ordinal);

        internal static string GenerateSessionPhrase()
        {
            var words = new string[6];
            for (var index = 0; index < words.Length; index++)
                words[index] = WordList[RandomNumberGenerator.GetInt32(WordList.Length)];
            return string.Join(' ', words);
        }

        internal static bool TryNormalizeSessionPhrase(string? value, out string phrase)
        {
            phrase = string.Empty;
            if (string.IsNullOrWhiteSpace(value) || value.Length > 256) return false;
            var words = value.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Select(word => word.ToLowerInvariant())
                .ToArray();
            if (words.Length != 6 || words.Any(word => !SessionWordSet.Contains(word))) return false;
            phrase = string.Join(' ', words);
            return true;
        }

        private static string[] LoadWordList()
        {
            using var stream = typeof(AdaptiveDicewareTechnique).Assembly
                .GetManifestResourceStream("EffLargeWordlist")
                ?? throw new InvalidOperationException("Diceware wordlist is missing.");
            using var reader = new StreamReader(stream);
            var words = new List<string>(7776);
            string? line;
            while ((line = reader.ReadLine()) is not null)
            {
                var fields = line.Split('\t');
                if (fields.Length != 2 || string.IsNullOrWhiteSpace(fields[1]))
                    throw new InvalidDataException("Invalid Diceware wordlist.");
                words.Add(fields[1]);
            }

            if (words.Count != 7776 || words.Distinct(StringComparer.Ordinal).Count() != words.Count)
                throw new InvalidDataException("Invalid Diceware wordlist size or duplicate words.");
            return words.ToArray();
        }

        public string Generate(int wordCount, string? seed)
        {
            if (wordCount <= 0)
            {
                return string.Empty;
            }

            using var random = new SecureRandomIndex(seed, "diceware");
            var words = new List<string>(capacity: wordCount);
            for (int i = 0; i < wordCount; i++)
            {
                words.Add(WordList[random.Next(WordList.Length)]);
            }

            string marker = CalculateEntropyMarker(words);
            return string.Join('-', words) + marker;
        }

        private static string CalculateEntropyMarker(IEnumerable<string> words)
        {
            int letters = 0;
            int vowels = 0;

            foreach (string word in words)
            {
                foreach (char character in word)
                {
                    if (char.IsLetter(character))
                    {
                        letters++;
                        if (IsVowel(character))
                        {
                            vowels++;
                        }
                    }
                }
            }

            int consonants = letters - vowels;
            int score = (consonants * 37 + vowels * 17 + letters) % 1000;
            return $"!{score:D3}";
        }

        private static bool IsVowel(char character)
        {
            char normalized = char.ToLowerInvariant(character);
            return normalized is 'a' or 'e' or 'i' or 'o' or 'u';
        }
    }
}
