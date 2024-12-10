using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace Password_Phrase_Producer.PasswordGenerationTechniques.HashBasedTechniques
{
    internal class DeterministicHashPasswordGenerator : IHashBasedTechniques
    {
        private const int MinimumLength = 12;

        private static readonly string Lowercase = "abcdefghijklmnopqrstuvwxyz";
        private static readonly string Uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        private static readonly string Digits = "0123456789";
        private static readonly string Special = "!@#$%^&*()_+-=[]{};:,.<>?/";

        private static readonly string AllChars = Lowercase + Uppercase + Digits + Special;

        public string GeneratePassword(string input)
        {
            byte[] hashBytes = ComputeSha256(input);

            StringBuilder sb = new StringBuilder();
            foreach (var b in hashBytes)
            {
                int index = b % AllChars.Length;
                sb.Append(AllChars[index]);
            }

            string result = sb.ToString();

            if (result.Length < MinimumLength)
            {
                while (result.Length < MinimumLength)
                {
                    result += AllChars[result.Length % AllChars.Length];
                }
            }

            result = EnsureCharacterTypes(result);

            return result;
        }

        private static byte[] ComputeSha256(string input)
        {
            using (var sha = SHA256.Create())
            {
                return sha.ComputeHash(Encoding.UTF8.GetBytes(input));
            }
        }

        private static string EnsureCharacterTypes(string password)
        {
            bool hasLower = password.Any(c => Lowercase.Contains(c));
            bool hasUpper = password.Any(c => Uppercase.Contains(c));
            bool hasDigit = password.Any(c => Digits.Contains(c));
            bool hasSpecial = password.Any(c => Special.Contains(c));

            char[] result = password.ToCharArray();

            if (!hasLower)
            {
                result[0] = Lowercase[0];
            }

            if (!hasUpper)
            {
                result[1] = Uppercase[0];
            }

            if (!hasDigit)
            {
                result[2] = Digits[0];
            }

            if (!hasSpecial)
            {
                result[3] = Special[0];
            }

            return new string(result);
        }

    }
}
