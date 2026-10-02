using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Buffers.Binary;
using System.Text;
using System.Text.Json;
using Password_Phrase_Producer.Models;
using Password_Phrase_Producer.PasswordGenerationTechniques.DicewareTechnique;
using Password_Phrase_Producer.Services.LocalTransfer;
using Password_Phrase_Producer.Services.Qr;
using Password_Phrase_Producer.Services.Storage;
using Xunit;
using ZXing;
using ZXing.QrCode;

namespace PasswordPhraseProducer.Updates.Tests;

public sealed class LocalTransferTests
{
    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true
    };

    [Fact]
    public void SessionPhraseUsesExactlySixWordlistWords()
    {
        var seen = new HashSet<string>();
        for (var index = 0; index < 32; index++)
        {
            var phrase = AdaptiveDicewareTechnique.GenerateSessionPhrase();
            Assert.True(AdaptiveDicewareTechnique.TryNormalizeSessionPhrase(phrase, out var normalized));
            Assert.Equal(phrase, normalized);
            Assert.Equal(6, phrase.Split(' ').Length);
            Assert.DoesNotContain('!', phrase);
            foreach (var word in phrase.Split(' ')) seen.Add(word);
        }
        Assert.True(seen.Count > 100);
    }

    [Fact]
    public void QrCodeRoundTripsAndRejectsNonPrivateAddresses()
    {
        var phrase = AdaptiveDicewareTechnique.GenerateSessionPhrase();
        var ticket = new LocalTransferTicket(IPAddress.Parse("192.168.1.15"), 43129, phrase, Guid.NewGuid());
        Assert.Equal(ticket, LocalTransferTicket.ParseQrText(ticket.ToQrText()));
        Assert.Throws<InvalidDataException>(() => LocalTransferTicket.ParseQrText("otpauth://totp/test"));
        Assert.Throws<InvalidDataException>(() => LocalTransferTicket.ParseManual("8.8.8.8", "443", phrase));
        Assert.Throws<InvalidDataException>(() => LocalTransferTicket.ParseManual("192.168.1.2", "0", phrase));
        Assert.Throws<InvalidDataException>(() => LocalTransferTicket.ParseManual("192.168.1.2", "443", "one two"));

        var encoded = new QRCodeWriter().encode(ticket.ToQrText(), BarcodeFormat.QR_CODE, 0, 0);
        const int scale = 3;
        var side = (encoded.Width + 8) * scale;
        var gray = Enumerable.Repeat((byte)255, side * side).ToArray();
        for (var y = 0; y < encoded.Height; y++)
            for (var x = 0; x < encoded.Width; x++)
                if (encoded[x, y])
                    for (var dy = 0; dy < scale; dy++)
                        for (var dx = 0; dx < scale; dx++)
                            gray[((y + 4) * scale + dy) * side + (x + 4) * scale + dx] = 0;
        var scanned = new QrCodeDecoder().DecodeImage(new GrayImage(gray, side, side));
        Assert.Contains(ticket.ToQrText(), scanned);
    }

    [Fact]
    public void V3PreflightRejectsTamperingAndLegacyFormat()
    {
        var phrase = AdaptiveDicewareTechnique.GenerateSessionPhrase();
        var bytes = CreateEmptyBackup(phrase);
        var contents = LocalBackupVerifier.Verify(bytes, phrase);
        Assert.True(contents.PasswordVault);
        Assert.False(contents.DataVault);
        Assert.Throws<InvalidDataException>(() => LocalBackupVerifier.Verify(bytes, "wrong password"));

        var backup = JsonSerializer.Deserialize<FullBackupDto>(bytes, Options)!;
        backup.Version = 2;
        Assert.Throws<InvalidDataException>(() => LocalBackupVerifier.Verify(JsonSerializer.SerializeToUtf8Bytes(backup, Options), phrase));
        backup.Version = 3;
        backup.PasswordVault!.CipherText = "changed";
        Assert.Throws<InvalidDataException>(() => LocalBackupVerifier.Verify(JsonSerializer.SerializeToUtf8Bytes(backup, Options), phrase));
        FullBackupIntegrity.Seal(backup, phrase, Options);
        Assert.Throws<InvalidDataException>(() => LocalBackupVerifier.Verify(JsonSerializer.SerializeToUtf8Bytes(backup, Options), phrase));
        Assert.Throws<InvalidDataException>(() => LocalBackupVerifier.Verify(new byte[BackupInput.MaxBytes + 1], phrase));
    }

    [Fact]
    public async Task TlsRoundTripRejectsWrongWordsAndSessionSubstitution()
    {
        var address = LocalTransferAddresses.Find().FirstOrDefault();
        Assert.NotNull(address);
        var phrase = AdaptiveDicewareTechnique.GenerateSessionPhrase();
        var backup = CreateEmptyBackup(phrase);
        var expected = backup.ToArray();
        var approvals = 0;
        await using var sender = LocalTransferProtocol.StartSend(address, phrase, backup, () =>
        {
            approvals++;
            return Task.FromResult(true);
        });
        var wrongSession = sender.Ticket with { SessionId = Guid.NewGuid() };
        await Assert.ThrowsAsync<AuthenticationException>(() => LocalTransferProtocol.ReceiveAsync(wrongSession));
        var wrongWords = sender.Ticket with { Phrase = AdaptiveDicewareTechnique.GenerateSessionPhrase() };
        await Assert.ThrowsAsync<AuthenticationException>(() => LocalTransferProtocol.ReceiveAsync(wrongWords));
        Assert.Equal(0, approvals);
        var received = await LocalTransferProtocol.ReceiveAsync(sender.Ticket);
        await sender.Completion;
        Assert.Equal(expected, received);
        Assert.Equal(1, approvals);
        Assert.True(LocalBackupVerifier.Verify(received, phrase).PasswordVault);
    }

    [Fact]
    public async Task ThreeBadConnectionsEndSessionAndCancellationClosesListener()
    {
        var address = LocalTransferAddresses.Find().FirstOrDefault();
        Assert.NotNull(address);
        var phrase = AdaptiveDicewareTechnique.GenerateSessionPhrase();
        await using var sender = LocalTransferProtocol.StartSend(address, phrase, CreateEmptyBackup(phrase),
            () => Task.FromResult(true));
        for (var index = 0; index < 3; index++)
            await Assert.ThrowsAsync<AuthenticationException>(() => LocalTransferProtocol.ReceiveAsync(
                sender.Ticket with { SessionId = Guid.NewGuid() }));
        await Assert.ThrowsAsync<AuthenticationException>(() => sender.Completion);

        await using var canceled = LocalTransferProtocol.StartSend(address, phrase, CreateEmptyBackup(phrase),
            () => Task.FromResult(true));
        canceled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => canceled.Completion);

        await using var expired = LocalTransferProtocol.StartSend(address, phrase, CreateEmptyBackup(phrase),
            () => Task.FromResult(true), lifetime: TimeSpan.FromMilliseconds(80));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => expired.Completion);
    }

    [Fact]
    public async Task SenderApprovalIsRequiredBeforeBackupIsSent()
    {
        var address = LocalTransferAddresses.Find().FirstOrDefault();
        Assert.NotNull(address);
        var phrase = AdaptiveDicewareTechnique.GenerateSessionPhrase();
        var approvals = 0;
        await using var sender = LocalTransferProtocol.StartSend(address, phrase, CreateEmptyBackup(phrase), () =>
        {
            approvals++;
            return Task.FromResult(false);
        });
        await Assert.ThrowsAsync<AuthenticationException>(() => LocalTransferProtocol.ReceiveAsync(sender.Ticket));
        Assert.Equal(1, approvals);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => sender.Completion);
    }

    [Fact]
    public async Task ManualAddressAndWordsCanReceiveWithoutQrSessionId()
    {
        var address = LocalTransferAddresses.Find().FirstOrDefault();
        Assert.NotNull(address);
        var phrase = AdaptiveDicewareTechnique.GenerateSessionPhrase();
        var expected = CreateEmptyBackup(phrase);
        await using var sender = LocalTransferProtocol.StartSend(address, phrase, expected.ToArray(),
            () => Task.FromResult(true));
        var manual = LocalTransferTicket.ParseManual(address.ToString(), sender.Ticket.Port.ToString(), phrase);
        Assert.Null(manual.SessionId);
        var bytes = await LocalTransferProtocol.ReceiveAsync(manual);
        await sender.Completion;
        Assert.Equal(expected, bytes);
    }

    [Theory]
    [InlineData("certificate")]
    [InlineData("oversize")]
    [InlineData("truncated")]
    public async Task ReceiverRejectsForgedCertificateAndInvalidPayloads(string fault)
    {
        var address = LocalTransferAddresses.Find().FirstOrDefault();
        Assert.NotNull(address);
        var phrase = AdaptiveDicewareTechnique.GenerateSessionPhrase();
        var sessionId = Guid.NewGuid();
        using var listener = new TcpListener(address, 0);
        listener.Start();
        var ticket = new LocalTransferTicket(address, ((IPEndPoint)listener.LocalEndpoint).Port, phrase, sessionId);
        var fake = RunFakeServerAsync(listener, phrase, sessionId, fault);
        var receiverError = await Record.ExceptionAsync(() => LocalTransferProtocol.ReceiveAsync(ticket));
        var senderError = await Record.ExceptionAsync(() => fake);
        Assert.Null(senderError);
        if (fault == "truncated") Assert.IsAssignableFrom<IOException>(receiverError);
        else if (fault == "certificate") Assert.IsType<AuthenticationException>(receiverError);
        else Assert.IsType<InvalidDataException>(receiverError);
    }

    [Fact]
    public void MergePreservesExistingDataAndNewerDeletionMarkers()
    {
        var now = DateTimeOffset.UtcNow;
        var conflictId = Guid.NewGuid();
        var deletedId = Guid.NewGuid();
        var incoming = new[]
        {
            new PasswordVaultEntryDto { Id = conflictId, Label = "sender", ModifiedAt = now },
            new PasswordVaultEntryDto { Id = deletedId, Label = "deleted", IsDeleted = true, ModifiedAt = now },
            new PasswordVaultEntryDto { Id = Guid.NewGuid(), Label = "new", ModifiedAt = now }
        }.Select(entry => entry.ToModel()).ToList();
        var existing = new[]
        {
            new PasswordVaultEntryDto { Id = conflictId, Label = "old", ModifiedAt = now.AddDays(-1) },
            new PasswordVaultEntryDto { Id = deletedId, Label = "live", ModifiedAt = now.AddDays(-1) },
            new PasswordVaultEntryDto { Id = Guid.NewGuid(), Label = "local only", ModifiedAt = now }
        }.Select(entry => entry.ToModel()).ToList();

        var merged = new Password_Phrase_Producer.Services.Vault.VaultMergeService().MergeEntries(existing, incoming);
        Assert.Equal(4, merged.MergedEntries.Count);
        Assert.Equal("sender", merged.MergedEntries.Single(entry => entry.Id == conflictId).Label);
        Assert.True(merged.MergedEntries.Single(entry => entry.Id == deletedId).IsDeleted);
        Assert.Contains(merged.MergedEntries, entry => entry.Label == "local only");
        Assert.Equal(3, new Password_Phrase_Producer.Services.Vault.VaultMergeService()
            .MergeEntries(Array.Empty<PasswordVaultEntry>(), incoming).MergedEntries.Count);
    }

    private static async Task RunFakeServerAsync(TcpListener listener, string phrase, Guid sessionId, string fault)
    {
        using var client = await listener.AcceptTcpClientAsync();
        using var tls = new SslStream(client.GetStream(), false);
        using var keyPair = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=Local Vault Transfer", keyPair, HashAlgorithmName.SHA256);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1),
            DateTimeOffset.UtcNow.AddMinutes(5));
        using var usableCertificate = X509CertificateLoader.LoadPkcs12(certificate.Export(X509ContentType.Pfx), null);
        await tls.AuthenticateAsServerAsync(usableCertificate);

        var salt = RandomNumberGenerator.GetBytes(16);
        var serverNonce = RandomNumberGenerator.GetBytes(32);
        var secret = Rfc2898DeriveBytes.Pbkdf2(phrase, salt, 600_000, HashAlgorithmName.SHA256, 32);
        var certHash = fault == "certificate" ? RandomNumberGenerator.GetBytes(32) :
            SHA256.HashData(certificate.RawData);
        var proofData = Encoding.ASCII.GetBytes("PPP-LAN-1/server")
            .Concat(sessionId.ToByteArray()).Concat(serverNonce).Concat(certHash).ToArray();
        var proof = HMACSHA256.HashData(secret, proofData);
        var header = Encoding.ASCII.GetBytes("PPP-LAN-1").Concat(sessionId.ToByteArray())
            .Concat(salt).Concat(serverNonce).Concat(proof).ToArray();
        await tls.WriteAsync(header);
        await tls.FlushAsync();
        if (fault == "certificate") return;
        var reply = new byte[64];
        await tls.ReadExactlyAsync(reply);
        await tls.WriteAsync(new byte[] { 1 });
        var length = new byte[4];
        BinaryPrimitives.WriteInt32BigEndian(length, fault == "oversize" ? BackupInput.MaxBytes + 1 : 24);
        await tls.WriteAsync(length);
        if (fault == "truncated") await tls.WriteAsync(new byte[3]);
        await tls.FlushAsync();
    }

    private static byte[] CreateEmptyBackup(string phrase)
    {
        var plaintext = Encoding.UTF8.GetBytes("{\"entries\":[]}");
        var salt = RandomNumberGenerator.GetBytes(16);
        var key = Rfc2898DeriveBytes.Pbkdf2(phrase, salt, 200_000, HashAlgorithmName.SHA256, 32);
        var nonce = RandomNumberGenerator.GetBytes(12);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[16];
        using (var aes = new AesGcm(key, 16)) aes.Encrypt(nonce, plaintext, ciphertext, tag);
        var section = new PortableBackupDto
        {
            Salt = Convert.ToBase64String(salt),
            Verifier = Convert.ToBase64String(SHA256.HashData(key)),
            Iterations = 200_000,
            CipherText = Convert.ToBase64String(nonce.Concat(ciphertext).Concat(tag).ToArray())
        };
        CryptographicOperations.ZeroMemory(key);
        var backup = new FullBackupDto { PasswordVault = section };
        FullBackupIntegrity.Seal(backup, phrase, Options);
        return JsonSerializer.SerializeToUtf8Bytes(backup, Options);
    }
}
