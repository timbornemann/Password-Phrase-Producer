using System;
using System.Globalization;
using System.Linq;
using System.Text;

namespace Password_Phrase_Producer.PasswordGenerationTechniques.PatternCascadeTechnique
{
    internal class PatternCascadeTechnique : IPatternCascadeTechnique
    {
        public string CreatePassword(string primaryWord, string secondaryWord, string numericToken)
        {
            if (string.IsNullOrWhiteSpace(primaryWord) || string.IsNullOrWhiteSpace(secondaryWord))
            {
                return string.Empty;
            }

            string normalizedPrimary = Normalize(primaryWord);
            string normalizedSecondary = Normalize(secondaryWord);
            string digits = ExtractDigits(numericToken);

            if (string.IsNullOrEmpty(normalizedPrimary) || string.IsNullOrEmpty(normalizedSecondary))
            {
                return string.Empty;
            }

            if (digits.Length == 0)
            {
                digits = (normalizedPrimary.Length + normalizedSecondary.Length).ToString("D2", CultureInfo.InvariantCulture);
            }

            string checksum = CalculateChecksum(normalizedPrimary, normalizedSecondary, digits);

            return string.Concat(normalizedPrimary, digits, normalizedSecondary, checksum);
        }

        private static string Normalize(string value)
        {
            var filtered = new string(value.Where(char.IsLetter).ToArray());
            if (filtered.Length == 0)
            {
                return string.Empty;
            }

            var builder = new StringBuilder(filtered.Length);
            for (int i = 0; i < filtered.Length; i++)
            {
                char character = filtered[i];
                builder.Append(i % 2 == 0
                    ? char.ToUpperInvariant(character)
                    : char.ToLowerInvariant(character));
            }

            return builder.ToString();
        }

        private static string ExtractDigits(string numericToken)
        {
            var digits = new string(numericToken.Where(char.IsDigit).ToArray());
            if (digits.Length >= 2)
            {
                return digits;
            }

            if (digits.Length == 1)
            {
                return digits + digits;
            }

            return string.Empty;
        }

        private static string CalculateChecksum(string primary, string secondary, string digits)
        {
            int value = 0;
            int factor = 1;

            foreach (char character in primary.Concat(secondary))
            {
                value += character * factor;
                factor = (factor % 5) + 1;
            }

            foreach (char digit in digits)
            {
                value += (digit - '0') * 17;
            }

            int checksum = value % 4096;
            return checksum.ToString("X3", CultureInfo.InvariantCulture);
        }
    }
}
