using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Password_Phrase_Producer.PasswordGenerationTechniques.ConcatenationTechniques
{
    public interface IConcatenationTechnique
    {
        string EncryptPassword(IEnumerable<string> plainTextWords);
    }
}
