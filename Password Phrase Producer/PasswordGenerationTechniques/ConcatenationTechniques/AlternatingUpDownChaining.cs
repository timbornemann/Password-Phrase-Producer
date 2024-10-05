using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace Password_Phrase_Producer.PasswordGenerationTechniques.ConcatenationTechniques
{
    internal class AlternatingUpDownChaining
    {
        public string EncryptPassword(IEnumerable<string> plainTextWords)
        {
            int charIndex = 0;
            StringBuilder concatenatedPassword = new StringBuilder();
            bool toUpper = true;
            for (int i = 0; i<GetLongestStringLength(plainTextWords); i++)
            {
                foreach (string word in plainTextWords)
                {
                   if(charIndex < word.Length && !char.IsWhiteSpace(word[charIndex]) && word[charIndex] != '\0')
                    {
                        if (toUpper)
                        {
                            concatenatedPassword.Append(word.ToUpper()[charIndex]);
                        }
                        else
                        {
                            concatenatedPassword.Append(word.ToLower()[charIndex]);
                        }
                    }
                    else
                    {
                        continue;
                    }
                }
                charIndex++;
                toUpper = !toUpper;
            }
            return concatenatedPassword.ToString();
        }

        private int GetLongestStringLength(IEnumerable<string> strings)
        {
            if (strings == null || !strings.Any())
                return 0;        
            return strings.Max(s => s.Length);
        }

    }
}
