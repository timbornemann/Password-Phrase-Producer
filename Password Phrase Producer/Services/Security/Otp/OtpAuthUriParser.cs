namespace Password_Phrase_Producer.Services.Security.Otp;

/// <summary>
/// Parses standard key URIs (otpauth://totp/Issuer:Account?secret=...&amp;issuer=...).
/// </summary>
public static class OtpAuthUriParser
{
    private const string Prefix = "otpauth://";

    public static bool IsOtpAuthUri(string? text)
        => text is not null && text.TrimStart().StartsWith(Prefix, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Returns the parsed account or <c>null</c> if the URI is not a valid otpauth:// URI.
    /// </summary>
    public static OtpAccount? TryParse(string? text)
    {
        if (!IsOtpAuthUri(text))
        {
            return null;
        }

        var uri = text!.Trim();
        var rest = uri[Prefix.Length..];

        var fragmentIndex = rest.IndexOf('#');
        if (fragmentIndex >= 0)
        {
            rest = rest[..fragmentIndex];
        }

        var queryIndex = rest.IndexOf('?');
        var pathPart = queryIndex >= 0 ? rest[..queryIndex] : rest;
        var queryPart = queryIndex >= 0 ? rest[(queryIndex + 1)..] : string.Empty;

        var slashIndex = pathPart.IndexOf('/');
        var typePart = slashIndex >= 0 ? pathPart[..slashIndex] : pathPart;
        var labelPart = slashIndex >= 0 ? pathPart[(slashIndex + 1)..] : string.Empty;

        OtpKind kind;
        if (typePart.Equals("totp", StringComparison.OrdinalIgnoreCase))
        {
            kind = OtpKind.Totp;
        }
        else if (typePart.Equals("hotp", StringComparison.OrdinalIgnoreCase))
        {
            kind = OtpKind.Hotp;
        }
        else
        {
            return null;
        }

        var query = QueryString.Parse(queryPart, plusIsSpace: true);

        if (!query.TryGetValue("secret", out var secretText)
            || !Base32.TryDecode(secretText, out var secret)
            || secret.Length == 0)
        {
            return null;
        }

        var label = QueryString.Unescape(labelPart, plusIsSpace: false).Trim();
        var issuer = string.Empty;
        var accountName = label;

        var colonIndex = label.IndexOf(':');
        if (colonIndex >= 0)
        {
            issuer = label[..colonIndex].Trim();
            accountName = label[(colonIndex + 1)..].Trim();
        }

        if (query.TryGetValue("issuer", out var issuerParam) && !string.IsNullOrWhiteSpace(issuerParam))
        {
            issuer = issuerParam.Trim();
        }

        var algorithm = OtpHashAlgorithm.Sha1;
        if (query.TryGetValue("algorithm", out var algorithmText))
        {
            switch (algorithmText.Trim().ToUpperInvariant())
            {
                case "SHA1":
                case "":
                    algorithm = OtpHashAlgorithm.Sha1;
                    break;
                case "SHA256":
                    algorithm = OtpHashAlgorithm.Sha256;
                    break;
                case "SHA512":
                    algorithm = OtpHashAlgorithm.Sha512;
                    break;
                case "MD5":
                    algorithm = OtpHashAlgorithm.Md5;
                    break;
                default:
                    return null;
            }
        }

        var digits = 6;
        if (query.TryGetValue("digits", out var digitsText) && !string.IsNullOrWhiteSpace(digitsText))
        {
            // A wrong digit count would silently produce wrong codes, so reject instead of guessing.
            if (!int.TryParse(digitsText, out digits) || digits < 6 || digits > 10)
            {
                return null;
            }
        }

        var period = 30;
        if (query.TryGetValue("period", out var periodText)
            && int.TryParse(periodText, out var parsedPeriod)
            && parsedPeriod > 0)
        {
            period = parsedPeriod;
        }

        long counter = 0;
        if (query.TryGetValue("counter", out var counterText))
        {
            long.TryParse(counterText, out counter);
        }

        return new OtpAccount
        {
            Issuer = issuer,
            AccountName = accountName,
            Secret = secret,
            Kind = kind,
            Algorithm = algorithm,
            Digits = digits,
            Period = period,
            Counter = counter
        };
    }
}

internal static class QueryString
{
    /// <summary>
    /// Parses a query string. Keys are compared case-insensitively; the first occurrence wins.
    /// </summary>
    public static Dictionary<string, string> Parse(string query, bool plusIsSpace)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var pair in query.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var equalsIndex = pair.IndexOf('=');
            var key = Unescape(equalsIndex >= 0 ? pair[..equalsIndex] : pair, plusIsSpace).Trim();
            var value = equalsIndex >= 0 ? Unescape(pair[(equalsIndex + 1)..], plusIsSpace) : string.Empty;
            result.TryAdd(key, value);
        }

        return result;
    }

    public static string Unescape(string value, bool plusIsSpace)
    {
        if (plusIsSpace)
        {
            value = value.Replace('+', ' ');
        }

        try
        {
            return Uri.UnescapeDataString(value);
        }
        catch (UriFormatException)
        {
            return value;
        }
    }
}

internal static class Base32
{
    private const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    /// <summary>
    /// Decodes RFC 4648 Base32. Whitespace, hyphens and padding are ignored, lowercase is accepted.
    /// </summary>
    public static bool TryDecode(string? input, out byte[] bytes)
    {
        bytes = Array.Empty<byte>();
        if (string.IsNullOrWhiteSpace(input))
        {
            return false;
        }

        var output = new List<byte>(input.Length * 5 / 8);
        var buffer = 0;
        var bitsLeft = 0;

        foreach (var raw in input)
        {
            if (char.IsWhiteSpace(raw) || raw == '-' || raw == '=')
            {
                continue;
            }

            var index = Alphabet.IndexOf(char.ToUpperInvariant(raw));
            if (index < 0)
            {
                return false;
            }

            buffer = (buffer << 5) | index;
            bitsLeft += 5;
            if (bitsLeft >= 8)
            {
                bitsLeft -= 8;
                output.Add((byte)(buffer >> bitsLeft));
                buffer &= (1 << bitsLeft) - 1;
            }
        }

        bytes = output.ToArray();
        return bytes.Length > 0;
    }
}
