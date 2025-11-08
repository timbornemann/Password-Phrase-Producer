using System;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Password_Phrase_Producer.PasswordGenerationTechniques.SymbolInjectionTechnique
{
    internal class SymbolInterleavingTechnique : ISymbolInjectionTechnique
    {
        private static readonly char[] Symbols = { '!', '?', '#', '$', '%', '&', '*', '+', '=', '-', '_' };

        public string InjectSymbols(string input, int symbolCount, bool randomizeCase, string? seed)
        {
            if (string.IsNullOrWhiteSpace(input))
            {
                return string.Empty;
            }

            var random = CreateRandom(seed);
            var builder = new StringBuilder(input.Length + Math.Max(symbolCount, 0));

            foreach (char character in input.Trim())
            {
                if (randomizeCase && char.IsLetter(character))
                {
                    bool upper = random.Next(2) == 0;
                    builder.Append(upper ? char.ToUpperInvariant(character) : char.ToLowerInvariant(character));
                }
                else
                {
                    builder.Append(character);
                }
            }

            int inserts = Math.Max(symbolCount, 0);
            for (int i = 0; i < inserts; i++)
            {
                char symbol = Symbols[random.Next(Symbols.Length)];
                int insertIndex = random.Next(builder.Length + 1);
                builder.Insert(insertIndex, symbol);
            }

            builder.Append(inserts.ToString("X", CultureInfo.InvariantCulture));

            return builder.ToString();
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
    }
}
