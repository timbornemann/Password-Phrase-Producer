using System;
using System.Text;

namespace Password_Phrase_Producer.PasswordGenerationTechniques.RandomPasswordTechnique;

internal class RandomPasswordTechnique : IRandomPasswordTechnique
{
    private const string Lowercase = "abcdefghijklmnopqrstuvwxyz";
    private const string Uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private const string Digits = "0123456789";
    private const string Special = "!@#$%^&*()_+-=[]{};:,.<>?/";

    internal static double MinimumEntropyBits(int length, bool includeUppercase, bool includeLowercase,
        bool includeDigits, bool includeSpecial)
    {
        if (length <= 0) return 0;
        var selected = new[]
        {
            includeLowercase ? Lowercase.Length : 0,
            includeUppercase ? Uppercase.Length : 0,
            includeDigits ? Digits.Length : 0,
            includeSpecial ? Special.Length : 0
        };
        var total = selected.Sum();
        if (total == 0) total = Lowercase.Length;
        var required = selected.Where(size => size > 0).Take(length).ToArray();
        return required.Sum(size => Math.Log2(size)) + (length - required.Length) * Math.Log2(total);
    }

    public string GeneratePassword(int length, bool includeUppercase, bool includeLowercase, bool includeDigits, bool includeSpecial, string? seed = null)
    {
        if (length <= 0)
        {
            return string.Empty;
        }

        StringBuilder charSet = new StringBuilder();
        if (includeLowercase) charSet.Append(Lowercase);
        if (includeUppercase) charSet.Append(Uppercase);
        if (includeDigits) charSet.Append(Digits);
        if (includeSpecial) charSet.Append(Special);

        if (charSet.Length == 0)
        {
            // Default to lowercase if nothing is selected
            charSet.Append(Lowercase);
        }

        using var random = new SecureRandomIndex(seed, "random-password");
        StringBuilder password = new StringBuilder(length);

        // Ensure at least one character from each selected set (if length allows)
        if (includeLowercase && password.Length < length)
            password.Append(Lowercase[random.Next(Lowercase.Length)]);
        if (includeUppercase && password.Length < length)
            password.Append(Uppercase[random.Next(Uppercase.Length)]);
        if (includeDigits && password.Length < length)
            password.Append(Digits[random.Next(Digits.Length)]);
        if (includeSpecial && password.Length < length)
            password.Append(Special[random.Next(Special.Length)]);

        // Fill the rest randomly
        while (password.Length < length)
        {
            password.Append(charSet[random.Next(charSet.Length)]);
        }

        // Shuffle the password to avoid predictable patterns
        return Shuffle(password.ToString(), random);
    }

    private static string Shuffle(string input, SecureRandomIndex random)
    {
        char[] chars = input.ToCharArray();
        for (int i = chars.Length - 1; i > 0; i--)
        {
            int j = random.Next(i + 1);
            (chars[i], chars[j]) = (chars[j], chars[i]);
        }
        return new string(chars);
    }
}

