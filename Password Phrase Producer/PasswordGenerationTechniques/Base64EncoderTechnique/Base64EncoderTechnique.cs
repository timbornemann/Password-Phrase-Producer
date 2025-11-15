using System;
using System.Text;

namespace Password_Phrase_Producer.PasswordGenerationTechniques.Base64EncoderTechnique;

internal class Base64EncoderTechnique : IBase64EncoderTechnique
{
    public string GeneratePassword(string input)
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            return string.Empty;
        }

        byte[] bytes = Encoding.UTF8.GetBytes(input);
        string base64 = Convert.ToBase64String(bytes);
        
        // Replace some characters to make it more password-friendly
        return base64.Replace("+", "-").Replace("/", "_").Replace("=", "");
    }
}

