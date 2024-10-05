using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PasswordPhraseProducer.PasswordGenerationTechniques.TbvTechniques
{
    internal class TBVHelper
    {
        private const string UsableNumbers = "123456789";
        private const string SpecialCharacters = "-!#$%&'()*+,./:;<=>?@[]^_`{|}~§°²³´€";
        private const string AllCharacters = "uK9@bR]fVQ2!M4A>€c)X0a^Häe=,1§DköU#YxgÄl²3B_q&Zs$8nO*C.6d~P%tL5{hS<p7³vÜz}?EÖw(yN°r/J[Fo´i`Iü|W'j+;m-G:T";

        public bool ContainsOnlyNumbers(string word)
        {
            return word.All(c => UsableNumbers.Contains(c));
        }

        public int ValidateIndex(int calculation, int size)
        {
            return (calculation % size + size) % size;
        }

        public string ShuffleString(string inputString, int code1, int code2, int code3)
        {
            var result = new List<char>();
            var charactersList = inputString.ToList();
            bool firstCode = true, secondCode = false, thirdCode = false;

            while (charactersList.Count > 0)
            {
                int index;
                if (firstCode)
                {
                    index = ValidateIndex(code1, charactersList.Count);
                    firstCode = false; secondCode = true;
                }
                else if (secondCode)
                {
                    index = ValidateIndex(code2, charactersList.Count);
                    secondCode = false; thirdCode = true;
                }
                else
                {
                    index = ValidateIndex(code3, charactersList.Count);
                    thirdCode = false; firstCode = true;
                }

                result.Add(charactersList[index]);
                charactersList.RemoveAt(index);
            }

            return new string(result.ToArray());
        }

        public string RemoveCharacterFromString(char character, string original)
        {
            return new string(original.Where(c => c != character).ToArray());
        }

        public string[] ConvertStringToArray(string input)
        {
            return input.Select(c => c.ToString()).ToArray();
        }

        public int CountSpecialCharacters(string word)
        {
            return word.Count(c => SpecialCharacters.Contains(c));
        }

        public int CountNumbers(string word)
        {
            return word.Count(char.IsDigit);
        }

        public int CountLowercaseLetters(string word)
        {
            return word.Count(char.IsLower);
        }

        public int CountUppercaseLetters(string word)
        {
            return word.Count(char.IsUpper);
        }

        public int CountLetters(string word)
        {
            return word.Count(char.IsLetter);
        }

        public int CountAllValidCharacters(string word)
        {
            return word.Count(c => AllCharacters.Contains(c));
        }

        public int CountUniqueCharacters(string word)
        {
            return word.Distinct().Count();
        }

        public string EstimateBruteForceTime(string word)
        {
            double time = (Math.Pow(CountUniqueCharacters(word), word.Length) / 2000000000) / 2;
            string[] units = { "seconds", "minutes", "hours", "days", "years" };
            double[] divisors = { 1, 60, 60, 24, 365 };

            int index = 0;
            while (index < divisors.Length - 1 && time > divisors[index])
            {
                time /= divisors[index];
                index++;
            }

            return $"{time:F2} {units[index]}";
        }

        public string PackageStringData(string password, int code1, int code2, int code3, string encryptionMethod)
        {
            return $"{password.Length}|{password} [{code1}]{{{code2}}}({code3}){encryptionMethod}";
        }

        public string ExtractPassword(string packagedString)
        {
            int passwordLength = int.Parse(packagedString.Substring(0, packagedString.IndexOf('|')));
            return packagedString.Substring(packagedString.IndexOf('|') + 1, passwordLength);
        }

        public int ExtractCode1(string packagedString)
        {
            return int.Parse(packagedString.Split('[', ']')[1]);
        }

        public int ExtractCode2(string packagedString)
        {
            return int.Parse(packagedString.Split('{', '}')[1]);
        }

        public int ExtractCode3(string packagedString)
        {
            return int.Parse(packagedString.Split('(', ')')[1]);
        }

        public string ExtractEncryptionMethod(string packagedString)
        {
            return packagedString.Substring(packagedString.LastIndexOf(')') + 1);
        }

        public int[][] GenerateCodeCombinations(string size)
        {
            int limit = size switch
            {
                "xs" => 9,
                "s" => 10,
                "m" => 22,
                "l" => 30,
                "xl" => 40,
                "xxl" => 50,
                "xxxl" => 100,
                _ => 0
            };

            if (limit == 0) return null;

            var codeList = new int[(int)Math.Pow(limit, 3)][];
            int index = 0;

            for (int z1 = 1; z1 <= limit; z1++)
            {
                for (int z2 = 1; z2 <= limit; z2++)
                {
                    for (int z3 = 1; z3 <= limit; z3++)
                    {
                        codeList[index++] = new[] { z1, z2, z3 };
                    }
                }
            }

            return codeList;
        }

        public bool IsCodeCombinationValid(string password, int maxLength, string exclusions)
        {
            return password.Length <= maxLength && !exclusions.Any(password.Contains);
        }
    }
}
