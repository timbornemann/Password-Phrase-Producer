using System;
using System.Globalization;
using System.Linq;
using System.Text;

namespace Password_Phrase_Producer.PasswordGenerationTechniques.MirrorLockTechnique
{
    internal class MirrorLockTechnique : IMirrorLockTechnique
    {
        public string CreatePassword(string input)
        {
            if (string.IsNullOrWhiteSpace(input))
            {
                return string.Empty;
            }

            string normalized = NormalizeSegment(input.Trim());
            if (string.IsNullOrEmpty(normalized))
            {
                return string.Empty;
            }

            string reversed = new string(normalized.Reverse().ToArray());
            string pivot = CalculatePivot(normalized);

            return string.Concat(normalized, pivot, reversed);
        }

        private static string NormalizeSegment(string value)
        {
            var cleaned = new string(value.Where(char.IsLetterOrDigit).ToArray());
            if (cleaned.Length == 0)
            {
                return string.Empty;
            }

            var builder = new StringBuilder(cleaned.Length);
            for (int i = 0; i < cleaned.Length; i++)
            {
                char current = cleaned[i];
                builder.Append(i % 2 == 0
                    ? char.ToUpperInvariant(current)
                    : char.ToLowerInvariant(current));
            }

            return builder.ToString();
        }

        private static string CalculatePivot(string segment)
        {
            int asciiSum = 0;
            foreach (char character in segment)
            {
                asciiSum += character;
            }

            return (asciiSum % 1000).ToString("D3", CultureInfo.InvariantCulture);
        }
    }
}
