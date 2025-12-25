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
    // Backward compatible alias
    public bool HasPin => _encryptionService.HasPin;

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

        byte[] decryptedBytes;
        try 
        {
            decryptedBytes = _encryptionService.Decrypt(encryptedBytes);
        }
        catch
        {
            // Decryption failed
            return new List<TotpEntry>();
        }

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
        catch
        {
             return new List<TotpEntry>();
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
        
        var encryptedBytes = _encryptionService.Encrypt(bytes);
        
        Directory.CreateDirectory(Path.GetDirectoryName(_totpFilePath)!);
        await File.WriteAllBytesAsync(_totpFilePath, encryptedBytes, cancellationToken).ConfigureAwait(false);
    }

    public async Task<byte[]> CreateBackupAsync(CancellationToken cancellationToken = default)
    {
        EnsureUnlocked();

        await _syncLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var entries = await LoadEntriesInternalAsync(cancellationToken).ConfigureAwait(false);
            var dtos = entries.Select(TotpEntryDto.FromModel).ToList();

            var backup = new Models.AuthenticatorBackupDto
            {
                Version = 1,
                Entries = dtos,
                PasswordHash = _encryptionService.HasPassword ? "protected" : string.Empty,
                CreatedAt = DateTimeOffset.UtcNow
            };

            var json = JsonSerializer.Serialize(backup, _jsonOptions);
            return Encoding.UTF8.GetBytes(json);
        }
        finally
        {
            _syncLock.Release();
        }
    }

    public async Task RestoreBackupAsync(Stream backupStream, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(backupStream);
        EnsureUnlocked();

        using var reader = new StreamReader(backupStream, Encoding.UTF8, leaveOpen: true);
        var json = await reader.ReadToEndAsync(cancellationToken).ConfigureAwait(false);
        var backup = JsonSerializer.Deserialize<Models.AuthenticatorBackupDto>(json, _jsonOptions)
                     ?? throw new InvalidOperationException("Ungültiges Backup-Format.");

        var entries = backup.Entries.Select(dto => dto.ToModel()).ToList();

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
}

public record TotpCode(string Code, int RemainingSeconds, int Period);
