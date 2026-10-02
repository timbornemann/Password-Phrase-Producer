using System.Text;

namespace Password_Phrase_Producer.Services.Security;

/// <summary>
/// Conservative visual guidance for user-chosen passwords, not an entropy estimate
/// or a condition for accepting a password. The password stays on the device.
/// </summary>
internal static class PasswordStrengthEstimator
{
    private static readonly string[] CommonFragments =
    [
        "password", "passwort", "qwerty", "asdfgh", "letmein", "welcome",
        "123456", "654321", "abcdef"
    ];

    internal static double Estimate(string? password)
    {
        if (string.IsNullOrWhiteSpace(password)) return 0;

        var runes = password.EnumerateRunes().ToArray();
        var length = runes.Length;
        var uniqueCount = runes.Distinct().Count();
        var groups = (password.Any(char.IsLetter) ? 1 : 0)
            + (password.Any(char.IsDigit) ? 1 : 0)
            + (password.Any(c => !char.IsLetterOrDigit(c) && !char.IsWhiteSpace(c)) ? 1 : 0);

        var score = Math.Min(0.9, length / 28d);
        if (groups >= 2) score += 0.05;
        if (groups >= 3) score += 0.05;
        if (length >= 12 && uniqueCount >= 8) score += 0.05;
        score = Math.Min(1, score);

        // Familiar strings, simple sequences, and repeated patterns should not
        // look strong merely because they are long or contain several character types.
        var compact = new string(password.Where(char.IsLetterOrDigit).ToArray()).ToLowerInvariant();
        if (CommonFragments.Any(compact.Contains) || IsRepeatedPattern(runes) ||
            uniqueCount <= Math.Max(2, length / 5))
            return Math.Min(score, 0.2);

        if (length <= 7) score = Math.Min(score, 0.32);
        else if (length <= 11) score = Math.Min(score, 0.55);

        return Math.Max(0.06, score);
    }

    private static bool IsRepeatedPattern(Rune[] runes)
    {
        for (var patternLength = 1; patternLength <= runes.Length / 2; patternLength++)
        {
            if (runes.Length % patternLength != 0) continue;
            var repeats = true;
            for (var index = patternLength; index < runes.Length; index++)
            {
                if (runes[index] == runes[index % patternLength]) continue;
                repeats = false;
                break;
            }
            if (repeats) return true;
        }
        return false;
    }
}
