using System.Text;
using Password_Phrase_Producer.Services.Qr;
using Password_Phrase_Producer.Services.Security.Otp;
using Xunit;
using ZXing;
using ZXing.QrCode;

namespace PasswordPhraseProducer.Updates.Tests;

public class OtpAuthUriParserTests
{
    [Fact]
    public void ParsesLabelIssuerAndParameters()
    {
        var account = OtpAuthUriParser.TryParse("otpauth://totp/ACME%20Co:john.doe%40example.com?secret=jbsw y3dp-ehpk3pxp&issuer=ACME+Co&algorithm=sha256&digits=8&period=60");

        Assert.NotNull(account);
        Assert.Equal("ACME Co", account.Issuer);
        Assert.Equal("john.doe@example.com", account.AccountName);
        Assert.Equal(new byte[] { 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x21, 0xDE, 0xAD, 0xBE, 0xEF }, account.Secret);
        Assert.Equal(OtpKind.Totp, account.Kind);
        Assert.Equal(OtpHashAlgorithm.Sha256, account.Algorithm);
        Assert.Equal(8, account.Digits);
        Assert.Equal(60, account.Period);
        Assert.True(account.IsSupported);
    }

    [Fact]
    public void IssuerParameterWinsOverLabel()
    {
        var account = OtpAuthUriParser.TryParse("OTPAUTH://TOTP/Old:alice?secret=JBSWY3DPEHPK3PXP&issuer=New");

        Assert.NotNull(account);
        Assert.Equal("New", account.Issuer);
        Assert.Equal("alice", account.AccountName);
        Assert.Equal(6, account.Digits);
        Assert.Equal(30, account.Period);
    }

    [Fact]
    public void HotpIsParsedButNotSupported()
    {
        var account = OtpAuthUriParser.TryParse("otpauth://hotp/Test?secret=JBSWY3DPEHPK3PXP&counter=42");

        Assert.NotNull(account);
        Assert.Equal(OtpKind.Hotp, account.Kind);
        Assert.Equal(42, account.Counter);
        Assert.False(account.IsSupported);
    }

    [Theory]
    [InlineData("otpauth://totp/Test")]
    [InlineData("otpauth://totp/Test?secret=")]
    [InlineData("otpauth://totp/Test?secret=NOT-BASE32-1890")]
    [InlineData("otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP&digits=5")]
    [InlineData("otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP&algorithm=SHA3")]
    [InlineData("otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP&period=0")]
    [InlineData("otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP&period=2147483647")]
    [InlineData("otpauth://hotp/Test?secret=JBSWY3DPEHPK3PXP&counter=-1")]
    [InlineData("otpauth://steam/Test?secret=JBSWY3DPEHPK3PXP")]
    [InlineData("https://example.com")]
    public void RejectsInvalidUris(string uri)
    {
        Assert.Null(OtpAuthUriParser.TryParse(uri));
    }

    [Fact]
    public void RejectsExcessivelyLongUri()
    {
        Assert.Null(OtpAuthUriParser.TryParse("otpauth://totp/Test?secret=" + new string('A', 20_000)));
    }
}

public class GoogleAuthenticatorMigrationParserTests
{
    [Fact]
    public void ParsesAllAccountsOfAnExport()
    {
        var uri = MigrationTestData.CreateUri(
            new[]
            {
                new MigrationTestData.Account(new byte[] { 1, 2, 3, 4, 5 }, "alice@example.com", "Example", Algorithm: 1, Digits: 1, Type: 2),
                new MigrationTestData.Account(new byte[] { 9, 8, 7 }, "GitHub:bob", "GitHub", Algorithm: 3, Digits: 2, Type: 2),
                new MigrationTestData.Account(new byte[] { 6, 6, 6 }, "counter", "", Algorithm: 0, Digits: 0, Type: 1, Counter: 7),
            });

        var batch = GoogleAuthenticatorMigrationParser.Parse(uri);

        Assert.Equal(3, batch.Accounts.Count);
        Assert.Equal(1, batch.BatchSize);

        var first = batch.Accounts[0];
        Assert.Equal("Example", first.Issuer);
        Assert.Equal("alice@example.com", first.AccountName);
        Assert.Equal(new byte[] { 1, 2, 3, 4, 5 }, first.Secret);
        Assert.Equal(OtpHashAlgorithm.Sha1, first.Algorithm);
        Assert.Equal(6, first.Digits);
        Assert.Equal(OtpKind.Totp, first.Kind);

        var second = batch.Accounts[1];
        Assert.Equal("bob", second.AccountName); // "Issuer:" prefix is removed
        Assert.Equal(OtpHashAlgorithm.Sha512, second.Algorithm);
        Assert.Equal(8, second.Digits);

        var third = batch.Accounts[2];
        Assert.Equal(OtpKind.Hotp, third.Kind);
        Assert.Equal(7, third.Counter);
        Assert.False(third.IsSupported);
    }

    [Fact]
    public void AcceptsUnencodedPlusSpacesAndMissingPadding()
    {
        // A secret with every byte value makes sure the base64 payload contains '+' characters.
        var account = new MigrationTestData.Account(Enumerable.Range(0, 256).Select(i => (byte)i).ToArray(), "x", "y");
        var base64 = Convert.ToBase64String(MigrationTestData.CreatePayload(new[] { account }));
        Assert.Contains('+', base64);

        var raw = "otpauth-migration://offline?data=" + base64.TrimEnd('=');
        var formDecoded = raw.Replace('+', ' ');

        Assert.Equal(account.Secret, GoogleAuthenticatorMigrationParser.Parse(raw).Accounts[0].Secret);
        Assert.Equal(account.Secret, GoogleAuthenticatorMigrationParser.Parse(formDecoded).Accounts[0].Secret);
    }

    [Theory]
    [InlineData("otpauth-migration://offline")]
    [InlineData("otpauth-migration://offline?data=")]
    [InlineData("otpauth-migration://offline?data=%%%")]
    [InlineData("otpauth-migration://offline?data=CgQ")] // truncated message
    [InlineData("otpauth://totp/x?secret=JBSWY3DP")]
    public void RejectsInvalidExports(string uri)
    {
        Assert.False(GoogleAuthenticatorMigrationParser.TryParse(uri, out _));
    }

    [Theory]
    [InlineData(int.MaxValue, 0)]
    [InlineData(2, int.MaxValue)]
    [InlineData(2, 2)]
    public void RejectsInvalidBatchMetadata(int batchSize, int batchIndex)
    {
        var uri = MigrationTestData.CreateUri(new[] { MigrationTestData.Simple("alice") }, batchSize, batchIndex);
        Assert.False(GoogleAuthenticatorMigrationParser.TryParse(uri, out _));
        Assert.Equal(OtpScanStatus.Invalid, new OtpScanCollector().Add(uri).Status);
    }

    [Fact]
    public void RejectsExcessivelyLongExport()
    {
        var uri = "otpauth-migration://offline?data=" + new string('A', 20_000);
        Assert.False(GoogleAuthenticatorMigrationParser.TryParse(uri, out _));
    }
}

public class OtpScanCollectorTests
{
    [Fact]
    public void SingleOtpAuthCodeIsCompleteImmediately()
    {
        var result = new OtpScanCollector().Add("otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP");

        Assert.Equal(OtpScanStatus.Complete, result.Status);
        Assert.Single(result.Accounts);
    }

    [Fact]
    public void CollectsAllPartsOfASplitExport()
    {
        var collector = new OtpScanCollector();
        var part1 = MigrationTestData.CreateUri(new[] { MigrationTestData.Simple("a") }, batchSize: 3, batchIndex: 0, batchId: 99);
        var part2 = MigrationTestData.CreateUri(new[] { MigrationTestData.Simple("b"), MigrationTestData.Simple("c") }, batchSize: 3, batchIndex: 1, batchId: 99);
        var part3 = MigrationTestData.CreateUri(new[] { MigrationTestData.Simple("d") }, batchSize: 3, batchIndex: 2, batchId: 99);

        Assert.Equal(OtpScanStatus.BatchPartial, collector.Add(part2).Status);
        Assert.Equal(OtpScanStatus.AlreadyScanned, collector.Add(part2).Status);
        Assert.Equal(OtpScanStatus.BatchPartial, collector.Add(part1).Status);
        Assert.Equal(new[] { 2 }, collector.MissingParts);

        var result = collector.Add(part3);

        Assert.Equal(OtpScanStatus.Complete, result.Status);
        Assert.Equal(new[] { "a", "b", "c", "d" }, result.Accounts.Select(a => a.AccountName));
        Assert.False(collector.HasPendingBatch);
    }

    [Fact]
    public void ScanningAnotherExportDiscardsThePreviousParts()
    {
        var collector = new OtpScanCollector();
        collector.Add(MigrationTestData.CreateUri(new[] { MigrationTestData.Simple("old") }, batchSize: 2, batchIndex: 0, batchId: 1));
        var oldSecret = collector.PendingAccounts.Single().Secret;

        var result = collector.Add(MigrationTestData.CreateUri(new[] { MigrationTestData.Simple("new") }, batchSize: 2, batchIndex: 0, batchId: 2));

        Assert.Equal(OtpScanStatus.BatchPartial, result.Status);
        Assert.Equal(new[] { "new" }, collector.PendingAccounts.Select(a => a.AccountName));
        Assert.All(oldSecret, value => Assert.Equal((byte)0, value));
    }

    [Fact]
    public void DiscardWipesPendingSecrets()
    {
        var collector = new OtpScanCollector();
        collector.Add(MigrationTestData.CreateUri(new[] { MigrationTestData.Simple("pending") }, batchSize: 2, batchIndex: 0, batchId: 1));
        var secret = collector.PendingAccounts.Single().Secret;

        collector.Discard();

        Assert.False(collector.HasPendingBatch);
        Assert.All(secret, value => Assert.Equal((byte)0, value));
    }

    [Theory]
    [InlineData("https://example.com", OtpScanStatus.NotOtp)]
    [InlineData("otpauth://totp/Test", OtpScanStatus.Invalid)]
    [InlineData("otpauth-migration://offline?data=%%%", OtpScanStatus.Invalid)]
    public void ReportsUnusableCodes(string text, OtpScanStatus expected)
    {
        Assert.Equal(expected, new OtpScanCollector().Add(text).Status);
    }
}

public class QrCodeDecoderTests
{
    [Fact]
    public void FindsDenseExportCodeInLiveFrameWithinAFewFrames()
    {
        var accounts = Enumerable.Range(0, 10)
            .Select(i => new MigrationTestData.Account(Enumerable.Range(0, 20).Select(b => (byte)(b * 7 + i)).ToArray(), $"user{i}@example.com", $"Service {i}"))
            .ToArray();
        var uri = MigrationTestData.CreateUri(accounts);

        // 1080p frame, code with 3 px per module slightly off center, with sensor noise.
        var frame = RenderFrame(new[] { (uri, 3, 700, 250) }, 1920, 1080, noise: 25, invert: false);
        var decoder = new QrCodeDecoder();

        var found = Enumerable.Range(0, 3).Select(_ => decoder.DecodeFrame(frame)).FirstOrDefault(r => r.Count > 0);

        Assert.NotNull(found);
        Assert.Equal(uri, found.Single());
    }

    [Fact]
    public void FindsSmallCodeViaCenterCrop()
    {
        const string uri = "otpauth://totp/ACME:alice?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=ACME&digits=6&period=30";

        // 2 px per module in a 1440p frame: too small after downscaling, readable in the full resolution crop.
        var frame = RenderFrame(new[] { (uri, 2, 1235, 675) }, 2560, 1440, noise: 10, invert: false);
        var decoder = new QrCodeDecoder();

        var found = Enumerable.Range(0, 3).Select(_ => decoder.DecodeFrame(frame)).FirstOrDefault(r => r.Count > 0);

        Assert.NotNull(found);
        Assert.Equal(uri, found.Single());
    }

    [Fact]
    public void DecodesInvertedCodes()
    {
        const string uri = "otpauth://totp/Dark:mode?secret=JBSWY3DPEHPK3PXP";
        var frame = RenderFrame(new[] { (uri, 6, 400, 200) }, 1280, 720, noise: 10, invert: true);
        var decoder = new QrCodeDecoder();

        var found = Enumerable.Range(0, 3).Select(_ => decoder.DecodeFrame(frame)).FirstOrDefault(r => r.Count > 0);

        Assert.NotNull(found);
        Assert.Equal(uri, found.Single());
    }

    [Fact]
    public void DecodesSeveralCodesInOneImage()
    {
        var first = MigrationTestData.CreateUri(new[] { MigrationTestData.Simple("a") }, batchSize: 2, batchIndex: 0, batchId: 5);
        var second = MigrationTestData.CreateUri(new[] { MigrationTestData.Simple("b") }, batchSize: 2, batchIndex: 1, batchId: 5);
        var image = RenderFrame(new[] { (first, 5, 100, 200), (second, 5, 900, 200) }, 1600, 900, noise: 10, invert: false);

        var found = new QrCodeDecoder().DecodeImage(image);

        Assert.Equal(new[] { first, second }.OrderBy(s => s), found.OrderBy(s => s));
    }

    [Fact]
    public void ReturnsNothingForEmptyFrames()
    {
        var frame = RenderFrame(Array.Empty<(string, int, int, int)>(), 640, 480, noise: 40, invert: false);

        Assert.Empty(new QrCodeDecoder().DecodeFrame(frame));
        Assert.Empty(new QrCodeDecoder().DecodeImage(frame));
    }

    private static GrayImage RenderFrame((string Text, int ModuleSize, int Left, int Top)[] codes, int width, int height, int noise, bool invert)
    {
        var random = new Random(1234);
        var pixels = new byte[width * height];
        for (var i = 0; i < pixels.Length; i++)
        {
            pixels[i] = (byte)Math.Clamp(200 + random.Next(-noise, noise + 1), 0, 255);
        }

        foreach (var (text, moduleSize, left, top) in codes)
        {
            var matrix = new QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, 0, 0, new Dictionary<EncodeHintType, object> { [EncodeHintType.MARGIN] = 4 });
            for (var y = 0; y < matrix.Height; y++)
            {
                for (var x = 0; x < matrix.Width; x++)
                {
                    var value = matrix[x, y] ? 30 : 220;
                    for (var dy = 0; dy < moduleSize; dy++)
                    {
                        for (var dx = 0; dx < moduleSize; dx++)
                        {
                            var px = left + x * moduleSize + dx;
                            var py = top + y * moduleSize + dy;
                            pixels[py * width + px] = (byte)Math.Clamp(value + random.Next(-noise, noise + 1), 0, 255);
                        }
                    }
                }
            }
        }

        if (invert)
        {
            for (var i = 0; i < pixels.Length; i++)
            {
                pixels[i] = (byte)(255 - pixels[i]);
            }
        }

        return new GrayImage(pixels, width, height);
    }
}

internal static class MigrationTestData
{
    public sealed record Account(byte[] Secret, string Name, string Issuer, int Algorithm = 1, int Digits = 1, int Type = 2, long Counter = 0);

    public static Account Simple(string name) => new(Encoding.ASCII.GetBytes("secret-" + name), name, "Issuer");

    public static string CreateUri(IEnumerable<Account> accounts, int batchSize = 1, int batchIndex = 0, int batchId = 12345)
        => "otpauth-migration://offline?data=" + Uri.EscapeDataString(Convert.ToBase64String(CreatePayload(accounts, batchSize, batchIndex, batchId)));

    public static byte[] CreatePayload(IEnumerable<Account> accounts, int batchSize = 1, int batchIndex = 0, int batchId = 12345)
    {
        var payload = new List<byte>();
        foreach (var account in accounts)
        {
            var parameters = new List<byte>();
            WriteBytes(parameters, 1, account.Secret);
            WriteBytes(parameters, 2, Encoding.UTF8.GetBytes(account.Name));
            WriteBytes(parameters, 3, Encoding.UTF8.GetBytes(account.Issuer));
            WriteVarintField(parameters, 4, (ulong)account.Algorithm);
            WriteVarintField(parameters, 5, (ulong)account.Digits);
            WriteVarintField(parameters, 6, (ulong)account.Type);
            WriteVarintField(parameters, 7, (ulong)account.Counter);
            WriteBytes(payload, 1, parameters.ToArray());
        }

        WriteVarintField(payload, 2, 1);
        WriteVarintField(payload, 3, (ulong)batchSize);
        WriteVarintField(payload, 4, (ulong)batchIndex);
        WriteVarintField(payload, 5, (ulong)batchId);
        return payload.ToArray();
    }

    private static void WriteBytes(List<byte> target, int field, byte[] value)
    {
        WriteVarint(target, (ulong)(field << 3 | 2));
        WriteVarint(target, (ulong)value.Length);
        target.AddRange(value);
    }

    private static void WriteVarintField(List<byte> target, int field, ulong value)
    {
        WriteVarint(target, (ulong)(field << 3));
        WriteVarint(target, value);
    }

    private static void WriteVarint(List<byte> target, ulong value)
    {
        while (value >= 0x80)
        {
            target.Add((byte)(value | 0x80));
            value >>= 7;
        }

        target.Add((byte)value);
    }
}
