using System.Text;

namespace Password_Phrase_Producer.Services.Security.Otp;

/// <summary>
/// One QR code of a Google Authenticator export. Large exports are split into several
/// QR codes that share the same <see cref="BatchId"/>.
/// </summary>
public sealed class MigrationBatch
{
    public IReadOnlyList<OtpAccount> Accounts { get; init; } = Array.Empty<OtpAccount>();
    public int Version { get; init; }
    public int BatchSize { get; init; } = 1;
    public int BatchIndex { get; init; }
    public int BatchId { get; init; }
}

/// <summary>
/// Decodes Google Authenticator export QR codes (otpauth-migration://offline?data=...).
/// The payload is a base64 encoded protobuf message which is read with a minimal parser,
/// so no generated protobuf classes are required.
/// </summary>
public static class GoogleAuthenticatorMigrationParser
{
    private const string Prefix = "otpauth-migration://";

    public static bool IsMigrationUri(string? text)
        => text is not null && text.TrimStart().StartsWith(Prefix, StringComparison.OrdinalIgnoreCase);

    public static bool TryParse(string? text, out MigrationBatch? batch)
    {
        try
        {
            batch = Parse(text);
            return true;
        }
        catch (FormatException)
        {
            batch = null;
            return false;
        }
    }

    /// <exception cref="FormatException">The text is not a valid Google Authenticator export.</exception>
    public static MigrationBatch Parse(string? text)
    {
        if (!IsMigrationUri(text))
        {
            throw new FormatException("Kein Google-Authenticator-Export (otpauth-migration://).");
        }

        var uri = text!.Trim();
        var queryIndex = uri.IndexOf('?');
        var query = queryIndex >= 0 ? uri[(queryIndex + 1)..] : string.Empty;

        // '+' is a valid base64 character here and must not be turned into a space.
        if (!QueryString.Parse(query, plusIsSpace: false).TryGetValue("data", out var data)
            || string.IsNullOrWhiteSpace(data))
        {
            throw new FormatException("Der Export enthält keine Daten.");
        }

        return ParsePayload(DecodeBase64(data));
    }

    private static byte[] DecodeBase64(string data)
    {
        var builder = new StringBuilder(data.Length + 3);
        foreach (var c in data)
        {
            switch (c)
            {
                case ' ':
                    // A '+' that went through form decoding somewhere along the way.
                    builder.Append('+');
                    break;
                case '-':
                    builder.Append('+');
                    break;
                case '_':
                    builder.Append('/');
                    break;
                case '=':
                case '\r':
                case '\n':
                case '\t':
                    break;
                default:
                    builder.Append(c);
                    break;
            }
        }

        var padding = (4 - builder.Length % 4) % 4;
        builder.Append('=', padding);

        try
        {
            return Convert.FromBase64String(builder.ToString());
        }
        catch (FormatException ex)
        {
            throw new FormatException("Die Exportdaten sind kein gültiges Base64.", ex);
        }
    }

    private static MigrationBatch ParsePayload(byte[] payload)
    {
        var accounts = new List<OtpAccount>();
        var version = 0;
        var batchSize = 1;
        var batchIndex = 0;
        var batchId = 0;

        foreach (var field in ProtobufReader.ReadFields(payload))
        {
            switch (field.Number)
            {
                case 1 when field.WireType == ProtobufReader.LengthDelimited:
                    var account = ParseOtpParameters(field.Bytes);
                    if (account is not null)
                    {
                        accounts.Add(account);
                    }
                    break;
                case 2 when field.WireType == ProtobufReader.Varint:
                    version = (int)field.Varint;
                    break;
                case 3 when field.WireType == ProtobufReader.Varint:
                    batchSize = Math.Max(1, (int)field.Varint);
                    break;
                case 4 when field.WireType == ProtobufReader.Varint:
                    batchIndex = Math.Max(0, (int)field.Varint);
                    break;
                case 5 when field.WireType == ProtobufReader.Varint:
                    batchId = unchecked((int)field.Varint);
                    break;
            }
        }

        if (batchIndex >= batchSize)
        {
            batchSize = batchIndex + 1;
        }

        return new MigrationBatch
        {
            Accounts = accounts,
            Version = version,
            BatchSize = batchSize,
            BatchIndex = batchIndex,
            BatchId = batchId
        };
    }

    private static OtpAccount? ParseOtpParameters(ReadOnlyMemory<byte> message)
    {
        var secret = Array.Empty<byte>();
        var name = string.Empty;
        var issuer = string.Empty;
        ulong algorithm = 1;
        ulong digits = 1;
        ulong type = 2;
        ulong counter = 0;

        foreach (var field in ProtobufReader.ReadFields(message))
        {
            switch (field.Number)
            {
                case 1 when field.WireType == ProtobufReader.LengthDelimited:
                    secret = field.Bytes.ToArray();
                    break;
                case 2 when field.WireType == ProtobufReader.LengthDelimited:
                    name = Encoding.UTF8.GetString(field.Bytes.Span);
                    break;
                case 3 when field.WireType == ProtobufReader.LengthDelimited:
                    issuer = Encoding.UTF8.GetString(field.Bytes.Span);
                    break;
                case 4 when field.WireType == ProtobufReader.Varint:
                    algorithm = field.Varint;
                    break;
                case 5 when field.WireType == ProtobufReader.Varint:
                    digits = field.Varint;
                    break;
                case 6 when field.WireType == ProtobufReader.Varint:
                    type = field.Varint;
                    break;
                case 7 when field.WireType == ProtobufReader.Varint:
                    counter = field.Varint;
                    break;
            }
        }

        if (secret.Length == 0)
        {
            return null;
        }

        // Google stores "Issuer:Account" in the name field when the original label contained it.
        if (!string.IsNullOrEmpty(issuer) && name.StartsWith(issuer + ":", StringComparison.Ordinal))
        {
            name = name[(issuer.Length + 1)..].TrimStart();
        }

        return new OtpAccount
        {
            Issuer = issuer,
            AccountName = name,
            Secret = secret,
            Kind = type == 1 ? OtpKind.Hotp : OtpKind.Totp,
            Algorithm = algorithm switch
            {
                2 => OtpHashAlgorithm.Sha256,
                3 => OtpHashAlgorithm.Sha512,
                4 => OtpHashAlgorithm.Md5,
                _ => OtpHashAlgorithm.Sha1
            },
            Digits = digits == 2 ? 8 : 6,
            Period = 30,
            Counter = unchecked((long)counter)
        };
    }
}

/// <summary>
/// Minimal protobuf wire format reader (varint, 64-bit, length-delimited and 32-bit fields).
/// </summary>
internal static class ProtobufReader
{
    public const int Varint = 0;
    public const int Fixed64 = 1;
    public const int LengthDelimited = 2;
    public const int Fixed32 = 5;

    public readonly record struct Field(int Number, int WireType, ulong Varint, ReadOnlyMemory<byte> Bytes);

    public static List<Field> ReadFields(ReadOnlyMemory<byte> buffer)
    {
        var fields = new List<Field>();
        var span = buffer.Span;
        var pos = 0;

        while (pos < span.Length)
        {
            var key = ReadVarint(span, ref pos);
            var number = (int)(key >> 3);
            var wireType = (int)(key & 7);

            switch (wireType)
            {
                case Varint:
                    fields.Add(new Field(number, wireType, ReadVarint(span, ref pos), ReadOnlyMemory<byte>.Empty));
                    break;
                case LengthDelimited:
                    var length = ReadVarint(span, ref pos);
                    if (length > (ulong)(span.Length - pos))
                    {
                        throw new FormatException("Unerwartetes Ende der Exportdaten.");
                    }

                    fields.Add(new Field(number, wireType, 0, buffer.Slice(pos, (int)length)));
                    pos += (int)length;
                    break;
                case Fixed64:
                    fields.Add(new Field(number, wireType, 0, Take(buffer, ref pos, 8)));
                    break;
                case Fixed32:
                    fields.Add(new Field(number, wireType, 0, Take(buffer, ref pos, 4)));
                    break;
                default:
                    throw new FormatException($"Unbekannter Protobuf-Wire-Type {wireType}.");
            }
        }

        return fields;
    }

    private static ReadOnlyMemory<byte> Take(ReadOnlyMemory<byte> buffer, ref int pos, int length)
    {
        if (pos + length > buffer.Length)
        {
            throw new FormatException("Unerwartetes Ende der Exportdaten.");
        }

        var slice = buffer.Slice(pos, length);
        pos += length;
        return slice;
    }

    private static ulong ReadVarint(ReadOnlySpan<byte> span, ref int pos)
    {
        ulong result = 0;
        for (var shift = 0; shift < 64; shift += 7)
        {
            if (pos >= span.Length)
            {
                throw new FormatException("Unerwartetes Ende der Exportdaten.");
            }

            var b = span[pos++];
            result |= (ulong)(b & 0x7F) << shift;
            if ((b & 0x80) == 0)
            {
                return result;
            }
        }

        throw new FormatException("Ungültiger Protobuf-Varint.");
    }
}
