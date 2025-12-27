using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Web;
using Google.Protobuf;
using OtpNet;
using Password_Phrase_Producer.Models;
using Password_Phrase_Producer.Services.Security.Protobuf;

namespace Password_Phrase_Producer.Services.Security;

public class TotpService
{
    private const string TotpFileName = "totp_data.json.enc";
    private readonly string _totpFilePath;
    private readonly TotpEncryptionService _encryptionService;
    private readonly JsonSerializerOptions _jsonOptions = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
    private readonly SemaphoreSlim _syncLock = new(1, 1);

    public event EventHandler? EntriesChanged;

    public bool IsUnlocked => _encryptionService.IsUnlocked;
    public bool HasPassword => _encryptionService.HasPassword;


    public TotpService(TotpEncryptionService encryptionService)
    {
        _encryptionService = encryptionService;
        _totpFilePath = Path.Combine(FileSystem.AppDataDirectory, TotpFileName);
    }

    private void EnsureUnlocked()
    {
        if (!_encryptionService.IsUnlocked)
        {
            throw new InvalidOperationException("Der Authenticator ist gesperrt.");
        }
    }

    public async Task<List<TotpEntry>> GetEntriesAsync(CancellationToken cancellationToken = default)
    {
        if (!_encryptionService.IsUnlocked)
        {
             return new List<TotpEntry>();
        }

        await _syncLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return await LoadEntriesInternalAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _syncLock.Release();
        }
    }

    public async Task AddOrUpdateEntryAsync(TotpEntry entry, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(entry);
        EnsureUnlocked();

        await _syncLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var entries = await LoadEntriesInternalAsync(cancellationToken).ConfigureAwait(false);
            var existingIndex = entries.FindIndex(e => e.Id == entry.Id);

            entry.ModifiedAt = DateTimeOffset.UtcNow;

            if (existingIndex >= 0)
            {
                entries[existingIndex] = entry;
            }
            else
            {
                entries.Add(entry);
            }

            await SaveEntriesInternalAsync(entries, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _syncLock.Release();
        }

        EntriesChanged?.Invoke(this, EventArgs.Empty);
    }

    public async Task DeleteEntryAsync(Guid entryId, CancellationToken cancellationToken = default)
    {
        EnsureUnlocked();

        await _syncLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var entries = await LoadEntriesInternalAsync(cancellationToken).ConfigureAwait(false);
            var removed = entries.RemoveAll(e => e.Id == entryId);

            if (removed > 0)
            {
                await SaveEntriesInternalAsync(entries, cancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            _syncLock.Release();
        }
        
        EntriesChanged?.Invoke(this, EventArgs.Empty);
    }

    public TotpCode? GenerateCode(TotpEntry entry)
    {
        if (entry.Secret == null || entry.Secret.Length == 0)
        {
            return null;
        }

        try
        {
            var mode = entry.Algorithm switch
            {
                TotpAlgorithm.Sha256 => OtpHashMode.Sha256,
                TotpAlgorithm.Sha512 => OtpHashMode.Sha512,
                _ => OtpHashMode.Sha1
            };

            var totp = new Totp(entry.Secret, step: entry.Period, mode: mode, totpSize: entry.Digits);
            var code = totp.ComputeTotp();
            var remaining = totp.RemainingSeconds();

            return new TotpCode(code, remaining, entry.Period);
        }
        catch
        {
            return null;
        }
    }

    public async Task<List<TotpEntry>> ImportFromUriAsync(string uriString)
    {
        if (string.IsNullOrWhiteSpace(uriString)) return new List<TotpEntry>();

        if (uriString.StartsWith("otpauth://totp/"))
        {
            var entry = ParseOtpAuthUri(uriString);
            if (entry != null)
            {
                await AddOrUpdateEntryAsync(entry);
                return new List<TotpEntry> { entry };
            }
        }
        else if (uriString.StartsWith("otpauth-migration://offline"))
        {
            var entries = ParseMigrationPayload(uriString);
            if (entries.Any())
            {
                foreach (var entry in entries)
                {
                    await AddOrUpdateEntryAsync(entry);
                }
                return entries;
            }
        }

        return new List<TotpEntry>();
    }

    private TotpEntry? ParseOtpAuthUri(string uriString)
    {
        try
        {
            var uri = new Uri(uriString);
            var path = Uri.UnescapeDataString(uri.AbsolutePath.TrimStart('/')); // "label"
            
            // Format: otpauth://totp/Issuer:Account?secret=...
            // or: otpauth://totp/Account?secret=...&issuer=...
            
            var label = path;
            string issuer = "";
            string accountName = label;

            if (label.Contains(':'))
            {
                var parts = label.Split(':', 2);
                issuer = parts[0];
                accountName = parts[1].Trim();
            }

            var query = HttpUtility.ParseQueryString(uri.Query);
            var secretStr = query["secret"];
            var issuerParam = query["issuer"];
            var algorithmStr = query["algorithm"];
            var digitsStr = query["digits"];
            var periodStr = query["period"];

            if (string.IsNullOrEmpty(secretStr)) return null;

            if (!string.IsNullOrEmpty(issuerParam))
            {
                issuer = issuerParam; // Param takes precedence usually
            }

            var algorithm = algorithmStr?.ToUpperInvariant() switch
            {
                "SHA256" => TotpAlgorithm.Sha256,
                "SHA512" => TotpAlgorithm.Sha512,
                _ => TotpAlgorithm.Sha1
            };

            int.TryParse(digitsStr, out var digits);
            if (digits == 0) digits = 6;

            int.TryParse(periodStr, out var period);
            if (period == 0) period = 30;

            return new TotpEntry
            {
                Issuer = issuer,
                AccountName = accountName,
                Secret = Base32Encoding.ToBytes(secretStr),
                Algorithm = algorithm,
                Digits = digits,
                Period = period
            };
        }
        catch
        {
            return null;
        }
    }

    private List<TotpEntry> ParseMigrationPayload(string uriString)
    {
        try
        {
            var uri = new Uri(uriString);
            var query = HttpUtility.ParseQueryString(uri.Query);
            var data = query["data"];

            if (string.IsNullOrEmpty(data)) return new List<TotpEntry>();

            var bytes = Convert.FromBase64String(data);
            var payload = MigrationPayload.Parser.ParseFrom(bytes);

            var list = new List<TotpEntry>();
            foreach (var p in payload.OtpParameters)
            {
                if (p.Type != OtType.Totp) continue; // Skip HOTP for now

                var algorithm = p.Algorithm switch
                {
                    Algorithm.Sha256 => TotpAlgorithm.Sha256,
                    Algorithm.Sha512 => TotpAlgorithm.Sha512,
                    _ => TotpAlgorithm.Sha1
                };

                list.Add(new TotpEntry
                {
                    Issuer = p.Issuer,
                    AccountName = p.Name,
                    Secret = p.Secret.ToByteArray(),
                    Algorithm = algorithm,
                    Digits = p.Digits > 0 ? p.Digits : 6,
                    Period = 30 // Migration format usually implies 30s for TOTP
                });
            }
            return list;
        }
        catch
        {
            return new List<TotpEntry>();
        }
    }

    private async Task<List<TotpEntry>> LoadEntriesInternalAsync(CancellationToken cancellationToken)
    {
        if (!File.Exists(_totpFilePath))
        {
            return new List<TotpEntry>();
        }

        var encryptedBytes = await File.ReadAllBytesAsync(_totpFilePath, cancellationToken).ConfigureAwait(false);
        if (encryptedBytes.Length == 0)
        {
            return new List<TotpEntry>();
        }

        byte[]? decryptedBytes = null;
        try 
        {
            decryptedBytes = _encryptionService.Decrypt(encryptedBytes);
            
            if (decryptedBytes.Length == 0)
            {
                return new List<TotpEntry>();
            }

            var json = Encoding.UTF8.GetString(decryptedBytes);
            try
            {
                var snapshot = JsonSerializer.Deserialize<TotpSnapshotDto>(json, _jsonOptions);
                return snapshot?.Entries.Select(e => e.ToModel()).ToList() ?? new List<TotpEntry>();
            }
            catch (Exception ex)
            {
                 throw new InvalidDataException("Die Authenticator-Datei ist beschädigt.", ex);
            }
        }
        catch (Exception ex) when (ex is not InvalidDataException)
        {
            // Decryption failed (or File read error handled above)
            throw new InvalidDataException("Fehler beim Entschlüsseln oder Lesen der Authenticator-Daten.", ex);
        }
        finally
        {
            if (decryptedBytes is not null)
            {
                // Sensible Daten aus dem Speicher löschen
                Array.Clear(decryptedBytes);
            }
        }
    }

    private async Task SaveEntriesInternalAsync(List<TotpEntry> entries, CancellationToken cancellationToken)
    {
        var dtos = entries.Select(TotpEntryDto.FromModel).ToList();
        var snapshot = new TotpSnapshotDto
        {
            Entries = dtos,
            ExportedAt = DateTimeOffset.UtcNow
        };

        var json = JsonSerializer.Serialize(snapshot, _jsonOptions);
        var bytes = Encoding.UTF8.GetBytes(json);
        
        try
        {
            var encryptedBytes = _encryptionService.Encrypt(bytes);
            
            Directory.CreateDirectory(Path.GetDirectoryName(_totpFilePath)!);
            await File.WriteAllBytesAsync(_totpFilePath, encryptedBytes, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            // Plain-Text JSON-Bytes aus dem Speicher löschen
            Array.Clear(bytes);
        }
    }

    /// <summary>
    /// Exports TOTP entries encrypted with a file password, similar to vault exports.
    /// </summary>
    public async Task<byte[]> ExportWithFilePasswordAsync(string filePassword, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePassword);
        EnsureUnlocked();

        const int KeySizeBytes = 32;
        const int SaltSizeBytes = 16;
        const int Pbkdf2Iterations = 200_000;

        await _syncLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            // 1. Klardaten auslesen
            var entries = await LoadEntriesInternalAsync(cancellationToken).ConfigureAwait(false);
            var dtos = entries.Select(TotpEntryDto.FromModel).ToList();

            var snapshot = new TotpSnapshotDto
            {
                Entries = dtos,
                ExportedAt = DateTimeOffset.UtcNow
            };

            var json = JsonSerializer.Serialize(snapshot, _jsonOptions);
            var plainBytes = Encoding.UTF8.GetBytes(json);

            try
            {
                // 2. Mit Datei-Passwort verschlüsseln (neue Salt/Key für Export)
                var salt = RandomNumberGenerator.GetBytes(SaltSizeBytes);
                var key = DeriveKey(filePassword, salt, Pbkdf2Iterations);
                try
                {
                    var encrypted = EncryptWithKey(plainBytes, key);
                    var verifier = CreateVerifier(key);

                    // 3. Format: { salt, verifier, iterations, cipherText }
                    var exportDto = new PortableBackupDto
                    {
                        Salt = Convert.ToBase64String(salt),
                        Verifier = Convert.ToBase64String(verifier),
                        Iterations = Pbkdf2Iterations,
                        CipherText = Convert.ToBase64String(encrypted),
                        CreatedAt = DateTimeOffset.UtcNow
                    };

                    return Encoding.UTF8.GetBytes(JsonSerializer.Serialize(exportDto, _jsonOptions));
                }
                finally
                {
                    Array.Clear(key);
                }
            }
            finally
            {
                // Plain-Text Daten aus dem Speicher löschen
                Array.Clear(plainBytes);
            }
        }
        finally
        {
            _syncLock.Release();
        }
    }

    private static byte[] DeriveKey(string password, byte[] salt, int iterations)
    {
        const int KeySizeBytes = 32;
        using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations, HashAlgorithmName.SHA256);
        return pbkdf2.GetBytes(KeySizeBytes);
    }

    private static byte[] CreateVerifier(byte[] key)
    {
        using var sha = SHA256.Create();
        return sha.ComputeHash(key);
    }

    public async Task ImportWithFilePasswordAsync(Stream stream, string filePassword, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentException.ThrowIfNullOrWhiteSpace(filePassword);
        EnsureUnlocked();

        // 1. Datei lesen und parsen
        using var reader = new StreamReader(stream, Encoding.UTF8, leaveOpen: true);
        var json = await reader.ReadToEndAsync(cancellationToken).ConfigureAwait(false);
        var dto = JsonSerializer.Deserialize<PortableBackupDto>(json, _jsonOptions)
                  ?? throw new InvalidOperationException("Ungültiges Export-Format.");

        // 2. Mit Datei-Passwort entschlüsseln
        var salt = Convert.FromBase64String(dto.Salt);
        var key = DeriveKey(filePassword, salt, dto.Iterations);

        // Verifier prüfen
        var expectedVerifier = Convert.FromBase64String(dto.Verifier);
        var actualVerifier = CreateVerifier(key);
        if (!CryptographicOperations.FixedTimeEquals(expectedVerifier, actualVerifier))
        {
            Array.Clear(key);
            throw new InvalidOperationException("Falsches Datei-Passwort.");
        }

        var encrypted = Convert.FromBase64String(dto.CipherText);
        var plainBytes = DecryptWithKey(encrypted, key);
        Array.Clear(key);

        try
        {
            // 3. Klardaten in Tresor einfügen
            var jsonString = Encoding.UTF8.GetString(plainBytes);
            var snapshot = JsonSerializer.Deserialize<TotpSnapshotDto>(jsonString, _jsonOptions)
                          ?? throw new InvalidOperationException("Ungültiges Snapshot-Format.");
            
            if (snapshot.Entries is null)
            {
                return;
            }

            var entries = snapshot.Entries.Select(e => e.ToModel()).ToList();

            await _syncLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                await SaveEntriesInternalAsync(entries, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                _syncLock.Release();
            }

            EntriesChanged?.Invoke(this, EventArgs.Empty);
        }
        finally
        {
            // Plain-Text Daten aus dem Speicher löschen
            Array.Clear(plainBytes);
        }
    }

    private static byte[] DecryptWithKey(byte[] data, byte[] key)
    {
        const int nonceLength = 12;
        const int tagLength = 16;

        if (data.Length < nonceLength + tagLength)
        {
            return Array.Empty<byte>();
        }

        var cipherLength = data.Length - nonceLength - tagLength;
        if (cipherLength < 0)
        {
            throw new InvalidOperationException("Ungültiges verschlüsseltes Format.");
        }

        var nonce = new byte[nonceLength];
        var cipher = new byte[cipherLength];
        var tag = new byte[tagLength];

        Buffer.BlockCopy(data, 0, nonce, 0, nonceLength);
        Buffer.BlockCopy(data, nonceLength, cipher, 0, cipherLength);
        Buffer.BlockCopy(data, nonceLength + cipherLength, tag, 0, tagLength);

        var plain = new byte[cipherLength];
        using var aes = new AesGcm(key, tagLength);
        aes.Decrypt(nonce, cipher, tag, plain);
        return plain;
    }

    private static byte[] EncryptWithKey(byte[] data, byte[] key)
    {
        var nonce = RandomNumberGenerator.GetBytes(12);
        var cipher = new byte[data.Length];
        var tag = new byte[16];

        using var aes = new AesGcm(key, tag.Length);
        aes.Encrypt(nonce, data, cipher, tag);

        var result = new byte[nonce.Length + cipher.Length + tag.Length];
        Buffer.BlockCopy(nonce, 0, result, 0, nonce.Length);
        Buffer.BlockCopy(cipher, 0, result, nonce.Length, cipher.Length);
        Buffer.BlockCopy(tag, 0, result, nonce.Length + cipher.Length, tag.Length);
        return result;
    }

    public async Task<List<TotpEntry>> GetEntriesForExportAsync(CancellationToken cancellationToken = default)
    {
        EnsureUnlocked();

        await _syncLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return await LoadEntriesInternalAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _syncLock.Release();
        }
    }

    public async Task<Services.Vault.MergeResult<TotpEntry>> MergeEntriesAsync(
        IList<TotpEntry> incomingEntries,
        CancellationToken cancellationToken = default)
    {
        EnsureUnlocked();

        await _syncLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var existingEntries = await LoadEntriesInternalAsync(cancellationToken).ConfigureAwait(false);
            var mergeService = new Services.Vault.VaultMergeService();
            var result = mergeService.MergeEntries(existingEntries, incomingEntries);

            await SaveEntriesInternalAsync(result.MergedEntries, cancellationToken).ConfigureAwait(false);
            return result;
        }
        finally
        {
            _syncLock.Release();
        }
    }



    public async Task RestoreBackupWithMergeAsync(Stream backupStream, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(backupStream);
        EnsureUnlocked();

        using var reader = new StreamReader(backupStream, Encoding.UTF8, leaveOpen: true);
        var json = await reader.ReadToEndAsync(cancellationToken).ConfigureAwait(false);
        var backup = JsonSerializer.Deserialize<Models.AuthenticatorBackupDto>(json, _jsonOptions)
                     ?? throw new InvalidOperationException("Ungültiges Backup-Format.");

        var incomingEntries = backup.Entries.Select(dto => dto.ToModel()).ToList();
        await MergeEntriesAsync(incomingEntries, cancellationToken).ConfigureAwait(false);

        EntriesChanged?.Invoke(this, EventArgs.Empty);
    }

    public async Task ResetVaultAsync(CancellationToken cancellationToken = default)
    {
        await _syncLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            // Delete TOTP data file
            if (File.Exists(_totpFilePath))
            {
                File.Delete(_totpFilePath);
            }

            // Reset encryption service (clears password and key file)
            _encryptionService.Reset();
        }
        finally
        {
            _syncLock.Release();
        }

        EntriesChanged?.Invoke(this, EventArgs.Empty);
    }
}

public record TotpCode(string Code, int RemainingSeconds, int Period);
