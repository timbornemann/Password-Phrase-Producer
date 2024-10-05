using Password_Phrase_Producer.PasswordGenerationTechniques.TbvTechniques;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PasswordPhraseProducer.PasswordGenerationTechniques.TbvTechniques
{
    internal class TBV2 : Itbv
    {
        private readonly string allCharacters = "uK9@bR]fVQ2!M4A>€c)X0a^Häe=,1§DköU#YxgÄl²3B_q&Zs$8nO*C.6d~P%tL5{hS<p7³vÜz}?EÖw(yN°r/J[Fo´i`Iü|W'j+;m-G:T";
        private TBVHelper helper = new TBVHelper();
        public static bool IsCancelled { get; set; } = false;


        public string GeneratePassword(string userPassword, int code1, int code2, int code3)
        {
            if (IsCancelled) return "";

            string shuffledCharacters = helper.ShuffleString(allCharacters, code1, code2, code3);
            string[] shuffledCharactersArray = helper.ConvertStringToArray(shuffledCharacters);
            string intermediatePassword = userPassword;
            int lengthMultiplier = (code1 + code2 + code3) / 3;

            // Main encryption loop
            for (int i = 1; i < lengthMultiplier + code1; i++)
            {
                if (IsCancelled) return "";

                intermediatePassword += shuffledCharactersArray[helper.ValidateIndex((code1 + code3) + (i * code2), shuffledCharactersArray.Length - 1)];
                intermediatePassword = helper.ShuffleString(intermediatePassword, code1, code2, code3);

                intermediatePassword += shuffledCharactersArray[helper.ValidateIndex(i + ((code1 + code3) + i) + ((code3 + code2) * i), shuffledCharactersArray.Length - 1)];
                intermediatePassword = helper.ShuffleString(intermediatePassword, code2, code1, code3);

                intermediatePassword += shuffledCharactersArray[helper.ValidateIndex((i + code3) + (i * code2) + (i * code1) * code1, shuffledCharactersArray.Length - 1)];
                intermediatePassword = helper.ShuffleString(intermediatePassword, code1, code2, code3);
            }

            // Reverse encryption
            string reversedPassword = new string(intermediatePassword.Reverse().ToArray());
            reversedPassword = helper.ShuffleString(reversedPassword, code1, code3, code2);

            // Combine forward and reverse strings
            string finalPassword = "";
            for (int i = 0; i < intermediatePassword.Length; i++)
            {
                if (IsCancelled) return "";

                finalPassword += intermediatePassword[i];
                finalPassword += reversedPassword[i];
            }

            return finalPassword;
        }
    }
}
