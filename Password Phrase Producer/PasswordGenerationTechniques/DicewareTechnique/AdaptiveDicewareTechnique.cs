using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Password_Phrase_Producer.PasswordGenerationTechniques.DicewareTechnique
{
    internal class AdaptiveDicewareTechnique : IDicewareTechnique
    {
        private static readonly string[] WordList =
        {
            "anker", "atlas", "biene", "blitz", "cloud", "delta", "ember", "falke", "gamma", "harfe",
            "ionen", "jaguar", "komet", "laser", "magma", "nebel", "omega", "pixel", "quarz", "robot",
            "silbe", "token", "ultra", "vital", "wolke", "xenon", "yukon", "zirbe", "fjord", "zenit"
        };

        public string Generate(int wordCount, string? seed)
        {
            if (wordCount <= 0)
            {
                return string.Empty;
            }

            Random random = CreateRandom(seed);
            var words = new List<string>(capacity: wordCount);
            for (int i = 0; i < wordCount; i++)
            {
                words.Add(WordList[random.Next(WordList.Length)]);
            }

            string marker = CalculateEntropyMarker(words);
            return string.Join('-', words) + marker;
        }

        private static Random CreateRandom(string? seed)
        {
            if (string.IsNullOrWhiteSpace(seed))
            {
                return Random.Shared;
            }

            byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(seed));
            int seedValue = BitConverter.ToInt32(hash, 0);
            return new Random(seedValue);
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
