using System;
using System.Text;

namespace Password_Phrase_Producer.PasswordGenerationTechniques.CaesarCipherTechnique;

internal class CaesarCipherTechnique : ICaesarCipherTechnique
{
    public string GeneratePassword(string input, int shift)
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            return string.Empty;
        }

        // Normalize shift to be within 0-25 range
        shift = ((shift % 26) + 26) % 26;

        StringBuilder result = new StringBuilder(input.Length);

        foreach (char c in input)
        {
            if (char.IsLetter(c))
            {
                char baseChar = char.IsUpper(c) ? 'A' : 'a';
                int shifted = (c - baseChar + shift) % 26;
                result.Append((char)(baseChar + shifted));
            }
            else if (char.IsDigit(c))
            {
                int digit = c - '0';
                int shifted = (digit + shift) % 10;
                result.Append((char)('0' + shifted));
            }
            else
            {
                result.Append(c);
            }
        }

        return result.ToString();
    }
}

