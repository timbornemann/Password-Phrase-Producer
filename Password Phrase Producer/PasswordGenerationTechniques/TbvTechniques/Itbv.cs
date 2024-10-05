using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Password_Phrase_Producer.PasswordGenerationTechniques.TbvTechniques
{
    public interface Itbv
    {
       string GeneratePassword(string plainTextPassword, int code1, int code2, int code3);
    }
}
