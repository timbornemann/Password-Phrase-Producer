using Password_Phrase_Producer.PasswordGenerationTechniques.TbvTechniques;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PasswordPhraseProducer.PasswordGenerationTechniques.TbvTechniques
{
    internal class TBV3 : Itbv
    {
        private readonly string allCharacters = "uK9@bR]fVQ2!M4A>€c)X0a^Häe=,1§DköU#YxgÄl²3B_q&Zs$8nO*C.6d~P%tL5{hS<p7³vÜz}?EÖw(yN°r/J[Fo´i`Iü|W'j+;m-G:T";
        private TBVHelper helper = new TBVHelper();
        public static bool Cancellation { get; set; } = false;


        public string GeneratePassword(string userPassword, int code1, int code2, int code3)
        {
            if (Cancellation) return "";

            string shuffledCharacters = helper.ShuffleString(allCharacters, code1, code2, code3);
            string[] shuffledCharactersArray = helper.ConvertStringToArray(shuffledCharacters);
            string tempPassword = userPassword;
            int lengthMultiplier = ((code1 + code2 + code3) / 3) + 1;

            // First encryption loop
            for (int i = 1; i <= lengthMultiplier; i++)
            {
                if (Cancellation) return "";

                tempPassword += shuffledCharactersArray[helper.ValidateIndex(
                    ((code1 + code3)) + ((i * code2)) + userPassword.Length,
                    shuffledCharactersArray.Length - 1)];

                tempPassword = helper.ShuffleString(tempPassword, code1, code2, code3);
            }

            // Second encryption loop
            for (int i = 0; i < code3; i++)
            {
                if (Cancellation) return "";

                tempPassword = helper.ShuffleString(tempPassword, code2, code1, code3);
            }

            // Third encryption loop
            for (int i = ((code3 + code2) / 2) + userPassword.Length; i > 0; i--)
            {
                if (Cancellation) return "";

                tempPassword += shuffledCharactersArray[helper.ValidateIndex(
                    i + (((code1 + code3) + i) + ((code3 + code2) * i)), shuffledCharactersArray.Length - 1)];
            }

            // Fourth encryption loop
            for (int i = 1; i < (code1 * lengthMultiplier + 1); i++)
            {
                if (Cancellation) return "";

                tempPassword += shuffledCharactersArray[helper.ValidateIndex(
                    ((i + code3) + (i * code2) + (i * code1) * code1), shuffledCharactersArray.Length - 1)];
            }

            // Fifth encryption loop
            for (int i = 0; i < code3; i++)
            {
                if (Cancellation) return "";

                tempPassword = helper.ShuffleString(tempPassword, code1, code2, code3);
            }

            // Reverse encryption
            string reversedPassword = new string(tempPassword.Reverse().ToArray());
            reversedPassword = helper.ShuffleString(reversedPassword, code1, code3, code2);

            // Reverse encryption loop
            reversedPassword = helper.ShuffleString(reversedPassword, code1, code3, code2);
            char[] reversedPasswordChars = reversedPassword.ToCharArray();
            string finalPassword = "";

            for (int i = 0; i < tempPassword.Length; i++)
            {
                if (Cancellation) return "";

                finalPassword += tempPassword[i];
                finalPassword += reversedPasswordChars[i];
            }

            return finalPassword;
        }

    }
}
