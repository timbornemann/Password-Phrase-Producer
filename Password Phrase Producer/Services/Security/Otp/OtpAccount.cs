namespace Password_Phrase_Producer.Services.Security.Otp;

public enum OtpKind
{
    Totp,
    Hotp
}

public enum OtpHashAlgorithm
{
    Sha1,
    Sha256,
    Sha512,
    Md5
}

/// <summary>
/// Platform independent description of an OTP account as found in an otpauth:// URI
/// or a Google Authenticator export (otpauth-migration://).
/// </summary>
public sealed class OtpAccount
{
    public string Issuer { get; init; } = string.Empty;
    public string AccountName { get; init; } = string.Empty;
    public byte[] Secret { get; init; } = Array.Empty<byte>();
    public OtpKind Kind { get; init; } = OtpKind.Totp;
    public OtpHashAlgorithm Algorithm { get; init; } = OtpHashAlgorithm.Sha1;
    public int Digits { get; init; } = 6;
    public int Period { get; init; } = 30;
    public long Counter { get; init; }

    /// <summary>
    /// The authenticator currently generates time based codes with SHA1/SHA256/SHA512 only.
    /// </summary>
    public bool IsSupported => Kind == OtpKind.Totp && Algorithm != OtpHashAlgorithm.Md5 && Secret.Length > 0;

    public string DisplayName => string.IsNullOrWhiteSpace(Issuer)
        ? (string.IsNullOrWhiteSpace(AccountName) ? "(ohne Name)" : AccountName)
        : string.IsNullOrWhiteSpace(AccountName) ? Issuer : $"{Issuer} ({AccountName})";
}
