using System.Buffers.Binary;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Password_Phrase_Producer.Services.Storage;

namespace Password_Phrase_Producer.Services.LocalTransfer;

internal static class LocalTransferProtocol
{
    private static readonly byte[] Magic = "PPP-LAN-1"u8.ToArray();
    private const int ProofLength = 32;
    private const int NonceLength = 32;
    private const int SaltLength = 16;
    private const int DerivationIterations = 600_000;
    private static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan ConnectionTimeout = TimeSpan.FromSeconds(20);

    internal static LocalSendSession StartSend(IPAddress address, string phrase, byte[] backup,
        Func<Task<bool>> approve, CancellationToken cancellationToken = default,
        TimeSpan? lifetime = null)
    {
        if (!LocalTransferAddresses.IsPrivate(address))
            throw new InvalidOperationException("Es ist keine private LAN-Adresse ausgewählt.");
        if (backup.Length is < 1 or > BackupInput.MaxBytes)
            throw new InvalidDataException("Die Sicherung ist leer oder größer als 128 MiB.");
        if (!Password_Phrase_Producer.PasswordGenerationTechniques.DicewareTechnique.AdaptiveDicewareTechnique
                .TryNormalizeSessionPhrase(phrase, out var normalized))
            throw new InvalidDataException("Ungültiger Sitzungscode.");
        if (lifetime is { } duration && duration <= TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(lifetime));

        var listener = new TcpListener(address, 0);
        listener.Start(1);
        try
        {
            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var request = new CertificateRequest("CN=Local Vault Transfer", key, HashAlgorithmName.SHA256);
            using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1),
                DateTimeOffset.UtcNow.AddMinutes(10));
            var session = new LocalSendSession(listener, normalized, backup, approve,
                certificate, cancellationToken, lifetime ?? Lifetime);
            session.Start();
            return session;
        }
        catch
        {
            listener.Stop();
            throw;
        }
    }

    internal static async Task<byte[]> ReceiveAsync(LocalTransferTicket ticket,
        CancellationToken cancellationToken = default)
    {
        if (!LocalTransferAddresses.IsPrivate(ticket.Address))
            throw new InvalidDataException("Nur private LAN-Adressen sind erlaubt.");
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(Lifetime);
        using var client = new TcpClient(AddressFamily.InterNetwork);
        using (var connect = CancellationTokenSource.CreateLinkedTokenSource(timeout.Token))
        {
            connect.CancelAfter(ConnectionTimeout);
            await client.ConnectAsync(ticket.Address, ticket.Port, connect.Token).ConfigureAwait(false);
        }

        byte[]? certificateHash = null;
        using var tls = new SslStream(client.GetStream(), false, (_, certificate, _, _) =>
        {
            if (certificate is null) return false;
            certificateHash = SHA256.HashData(certificate.GetRawCertData());
            // This is an ephemeral certificate. Trust it only after the certificate-bound
            // HMAC below has been verified with the secret phrase.
            return true;
        });
        using (var handshake = CancellationTokenSource.CreateLinkedTokenSource(timeout.Token))
        {
            handshake.CancelAfter(ConnectionTimeout);
            await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = "Local Vault Transfer",
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck
            }, handshake.Token).ConfigureAwait(false);
        }
        if (certificateHash is null) throw new AuthenticationException("TLS-Zertifikat fehlt.");

        var header = new byte[Magic.Length + 16 + SaltLength + NonceLength + ProofLength];
        await tls.ReadExactlyAsync(header, timeout.Token).ConfigureAwait(false);
        if (!header.AsSpan(0, Magic.Length).SequenceEqual(Magic))
            throw new InvalidDataException("Nicht unterstütztes Transferprotokoll.");
        var offset = Magic.Length;
        var sessionId = new Guid(header.AsSpan(offset, 16)); offset += 16;
        if (sessionId == Guid.Empty || ticket.SessionId is { } expectedId && expectedId != sessionId)
            throw new AuthenticationException("Die Transfer-Sitzung stimmt nicht mit dem QR-Code überein.");
        var salt = header.AsSpan(offset, SaltLength).ToArray(); offset += SaltLength;
        var serverNonce = header.AsSpan(offset, NonceLength).ToArray(); offset += NonceLength;
        var serverProof = header.AsSpan(offset, ProofLength);
        var secret = Derive(ticket.Phrase, salt);
        try
        {
            var expected = Proof(secret, "server", sessionId, serverNonce, null, certificateHash);
            if (!CryptographicOperations.FixedTimeEquals(expected, serverProof))
                throw new AuthenticationException("Wörter oder TLS-Identität stimmen nicht überein.");

            var clientNonce = RandomNumberGenerator.GetBytes(NonceLength);
            var clientProof = Proof(secret, "client", sessionId, serverNonce, clientNonce, certificateHash);
            await tls.WriteAsync(clientNonce, timeout.Token).ConfigureAwait(false);
            await tls.WriteAsync(clientProof, timeout.Token).ConfigureAwait(false);
            await tls.FlushAsync(timeout.Token).ConfigureAwait(false);

            var response = new byte[1];
            await tls.ReadExactlyAsync(response, timeout.Token).ConfigureAwait(false);
            if (response[0] != 1)
                throw new AuthenticationException(response[0] == 0
                    ? "Der Sender hat die Übertragung abgelehnt."
                    : "Die Anmeldung am Sender ist fehlgeschlagen.");

            var lengthBytes = new byte[4];
            await tls.ReadExactlyAsync(lengthBytes, timeout.Token).ConfigureAwait(false);
            var length = BinaryPrimitives.ReadInt32BigEndian(lengthBytes);
            if (length is < 1 or > BackupInput.MaxBytes)
                throw new InvalidDataException("Die Übertragung ist leer oder größer als 128 MiB.");
            var backup = new byte[length];
            try
            {
                await tls.ReadExactlyAsync(backup, timeout.Token).ConfigureAwait(false);
                return backup;
            }
            catch
            {
                CryptographicOperations.ZeroMemory(backup);
                throw;
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secret);
        }
    }

    private static byte[] Derive(string phrase, byte[] salt) =>
        Rfc2898DeriveBytes.Pbkdf2(phrase, salt, DerivationIterations, HashAlgorithmName.SHA256, ProofLength);

    private static byte[] Proof(byte[] secret, string role, Guid sessionId, byte[] serverNonce,
        byte[]? clientNonce, byte[] certificateHash)
    {
        using var data = new MemoryStream();
        data.Write(Encoding.ASCII.GetBytes("PPP-LAN-1/" + role));
        data.Write(sessionId.ToByteArray());
        data.Write(serverNonce);
        if (clientNonce is not null) data.Write(clientNonce);
        data.Write(certificateHash);
        return HMACSHA256.HashData(secret, data.ToArray());
    }

    internal sealed class LocalSendSession : IAsyncDisposable
    {
        private readonly TcpListener _listener;
        private readonly string _phrase;
        private readonly byte[] _backup;
        private readonly Func<Task<bool>> _approve;
        private readonly X509Certificate2 _certificate;
        private readonly CancellationTokenSource _lifetime;
        private readonly byte[] _salt = RandomNumberGenerator.GetBytes(SaltLength);
        private Task _completion = Task.CompletedTask;
        private bool _disposed;

        internal LocalSendSession(TcpListener listener, string phrase, byte[] backup,
            Func<Task<bool>> approve, X509Certificate2 certificate, CancellationToken cancellationToken,
            TimeSpan lifetime)
        {
            _listener = listener;
            _phrase = phrase;
            _backup = backup;
            _approve = approve;
            var pfx = certificate.Export(X509ContentType.Pfx);
            try { _certificate = X509CertificateLoader.LoadPkcs12(pfx, null); }
            finally { CryptographicOperations.ZeroMemory(pfx); }
            _lifetime = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            _lifetime.CancelAfter(lifetime);
            _lifetime.Token.Register(() => _listener.Stop());
            var endpoint = (IPEndPoint)_listener.LocalEndpoint;
            Ticket = new LocalTransferTicket(endpoint.Address, endpoint.Port, phrase, Guid.NewGuid());
            ExpiresAt = DateTimeOffset.UtcNow.Add(lifetime);
        }

        internal LocalTransferTicket Ticket { get; }
        internal DateTimeOffset ExpiresAt { get; }
        internal Task Completion => _completion;
        internal void Start() => _completion = RunAsync();
        internal void Cancel() => _lifetime.Cancel();

        private async Task RunAsync()
        {
            var failures = 0;
            try
            {
                while (failures < 3 && !_lifetime.IsCancellationRequested)
                {
                    TcpClient client;
                    try { client = await _listener.AcceptTcpClientAsync(_lifetime.Token).ConfigureAwait(false); }
                    catch (OperationCanceledException) { break; }
                    catch (SocketException) when (_lifetime.IsCancellationRequested) { break; }
                    using (client)
                    using (var attempt = CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token))
                    {
                        attempt.CancelAfter(ConnectionTimeout);
                        try
                        {
                            if (await SendToClientAsync(client, attempt.Token).ConfigureAwait(false))
                                return;
                            failures++;
                        }
                        catch (Exception ex) when (ex is IOException or AuthenticationException or
                            OperationCanceledException or SocketException)
                        {
                            if (_lifetime.IsCancellationRequested) break;
                            failures++;
                        }
                    }
                }
                if (failures >= 3) throw new AuthenticationException("Drei fehlgeschlagene Anmeldungen.");
                throw new OperationCanceledException("Die Transfer-Sitzung wurde beendet oder ist abgelaufen.");
            }
            finally
            {
                _listener.Stop();
                CryptographicOperations.ZeroMemory(_backup);
            }
        }

        private async Task<bool> SendToClientAsync(TcpClient client, CancellationToken token)
        {
            using var tls = new SslStream(client.GetStream(), false);
            await tls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
            {
                ServerCertificate = _certificate,
                ClientCertificateRequired = false,
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck
            }, token).ConfigureAwait(false);
            var certificateHash = SHA256.HashData(_certificate.RawData);
            var secret = Derive(_phrase, _salt);
            var serverNonce = RandomNumberGenerator.GetBytes(NonceLength);
            try
            {
                var header = new byte[Magic.Length + 16 + SaltLength + NonceLength + ProofLength];
                var offset = 0;
                Magic.CopyTo(header, offset); offset += Magic.Length;
                Ticket.SessionId!.Value.ToByteArray().CopyTo(header, offset); offset += 16;
                _salt.CopyTo(header, offset); offset += SaltLength;
                serverNonce.CopyTo(header, offset); offset += NonceLength;
                Proof(secret, "server", Ticket.SessionId.Value, serverNonce, null, certificateHash)
                    .CopyTo(header, offset);
                await tls.WriteAsync(header, token).ConfigureAwait(false);
                await tls.FlushAsync(token).ConfigureAwait(false);

                var clientMessage = new byte[NonceLength + ProofLength];
                await tls.ReadExactlyAsync(clientMessage, token).ConfigureAwait(false);
                var expected = Proof(secret, "client", Ticket.SessionId.Value, serverNonce,
                    clientMessage.AsSpan(0, NonceLength).ToArray(), certificateHash);
                if (!CryptographicOperations.FixedTimeEquals(expected,
                        clientMessage.AsSpan(NonceLength, ProofLength)))
                {
                    await tls.WriteAsync(new byte[] { 2 }, token).ConfigureAwait(false);
                    return false;
                }

                // A valid request is approved once at the sender before any backup bytes flow.
                var approved = await _approve().ConfigureAwait(false);
                if (!approved)
                {
                    await tls.WriteAsync(new byte[] { 0 }, _lifetime.Token).ConfigureAwait(false);
                    _lifetime.Cancel();
                    throw new AuthenticationException("Die Übertragung wurde am Sender abgelehnt.");
                }
                await tls.WriteAsync(new byte[] { 1 }, _lifetime.Token).ConfigureAwait(false);
                var lengthBytes = new byte[4];
                BinaryPrimitives.WriteInt32BigEndian(lengthBytes, _backup.Length);
                await tls.WriteAsync(lengthBytes, _lifetime.Token).ConfigureAwait(false);
                await tls.WriteAsync(_backup, _lifetime.Token).ConfigureAwait(false);
                await tls.FlushAsync(_lifetime.Token).ConfigureAwait(false);
                return true;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(secret);
            }
        }

        public async ValueTask DisposeAsync()
        {
            if (_disposed) return;
            _disposed = true;
            Cancel();
            try { await _completion.ConfigureAwait(false); }
            catch { /* Completion is observed by the page; disposal always releases secrets. */ }
            finally
            {
                _certificate.Dispose();
                _lifetime.Dispose();
            }
        }
    }
}
