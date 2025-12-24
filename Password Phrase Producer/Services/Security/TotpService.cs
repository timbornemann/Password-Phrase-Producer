using System.Text;
using System.Text.Json;
using System.Web;
using Google.Protobuf;
using OtpNet;
using Password_Phrase_Producer.Models;
using Password_Phrase_Producer.Services.Security.Protobuf;
using Password_Phrase_Producer.Services.Vault;

namespace Password_Phrase_Producer.Services.Security;

public class TotpService
{
    private const string TotpFileName = "totp.json.enc";
    private readonly string _totpFilePath;
    private readonly PasswordVaultService _vaultService;
    private readonly JsonSerializerOptions _jsonOptions = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
    private readonly SemaphoreSlim _syncLock = new(1, 1);

    public event EventHandler? EntriesChanged;

    public TotpService(PasswordVaultService vaultService)
    {
        _vaultService = vaultService;
        _totpFilePath = Path.Combine(FileSystem.AppDataDirectory, TotpFileName);
    }

    private void EnsureUnlocked()
    {
        if (!_vaultService.IsUnlocked)
        {
            throw new InvalidOperationException("Der Tresor ist gesperrt.");
        }
    }

    public async Task<List<TotpEntry>> GetEntriesAsync(CancellationToken cancellationToken = default)
    {
        if (!_vaultService.IsUnlocked)
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

        // Using PasswordVaultService's internal methods via the accessible instance?
        // Wait, GetUnlockedKey is internal, but EncryptWithKey/DecryptWithKey are static internal.
        // I can access them via the type PasswordVaultService.
        
        var key = _vaultService.GetUnlockedKey();
        byte[] decryptedBytes;
        try 
        {
            decryptedBytes = PasswordVaultService.DecryptWithKey(encryptedBytes, key);
        }
        catch
        {
            // Decryption failed (maybe wrong key if file was from different setup, or corrupted)
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
        
        var key = _vaultService.GetUnlockedKey();
        var encryptedBytes = PasswordVaultService.EncryptWithKey(bytes, key);

        // Atomic write via temp file could be better but sticking to simple overwrite for now 
        // as per PasswordVaultService pattern (it does WriteAllBytesAsync directly although it creates directory)
        
        Directory.CreateDirectory(Path.GetDirectoryName(_totpFilePath)!);
        await File.WriteAllBytesAsync(_totpFilePath, encryptedBytes, cancellationToken).ConfigureAwait(false);
    }
}

public record TotpCode(string Code, int RemainingSeconds, int Period);
