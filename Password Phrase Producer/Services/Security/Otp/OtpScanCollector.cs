namespace Password_Phrase_Producer.Services.Security.Otp;

public enum OtpScanStatus
{
    /// <summary>All accounts are available, the scan can be imported.</summary>
    Complete,

    /// <summary>A part of a multi-QR Google export was added, more codes are expected.</summary>
    BatchPartial,

    /// <summary>This part of a Google export has already been scanned.</summary>
    AlreadyScanned,

    /// <summary>The QR code does not contain an otpauth:// or otpauth-migration:// URI.</summary>
    NotOtp,

    /// <summary>The QR code looks like an OTP code but could not be decoded.</summary>
    Invalid
}

public sealed record OtpScanResult(OtpScanStatus Status, IReadOnlyList<OtpAccount> Accounts);

/// <summary>
/// Collects scanned QR contents. Single otpauth:// codes are complete immediately, Google
/// exports that are split over several QR codes are gathered until every part was scanned.
/// </summary>
public sealed class OtpScanCollector
{
    private readonly SortedDictionary<int, IReadOnlyList<OtpAccount>> _batchParts = new();
    private int? _batchId;

    public int BatchSize { get; private set; }

    public int ScannedParts => _batchParts.Count;

    public bool HasPendingBatch => _batchParts.Count > 0;

    public IReadOnlyList<int> MissingParts => Enumerable.Range(0, BatchSize).Where(i => !_batchParts.ContainsKey(i)).ToList();

    public IReadOnlyList<OtpAccount> PendingAccounts => _batchParts.Values.SelectMany(a => a).ToList();

    public OtpScanResult Add(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return new OtpScanResult(OtpScanStatus.NotOtp, Array.Empty<OtpAccount>());
        }

        if (OtpAuthUriParser.IsOtpAuthUri(text))
        {
            var account = OtpAuthUriParser.TryParse(text);
            return account is null
                ? new OtpScanResult(OtpScanStatus.Invalid, Array.Empty<OtpAccount>())
                : new OtpScanResult(OtpScanStatus.Complete, new[] { account });
        }

        if (!GoogleAuthenticatorMigrationParser.IsMigrationUri(text))
        {
            return new OtpScanResult(OtpScanStatus.NotOtp, Array.Empty<OtpAccount>());
        }

        if (!GoogleAuthenticatorMigrationParser.TryParse(text, out var batch) || batch is null)
        {
            return new OtpScanResult(OtpScanStatus.Invalid, Array.Empty<OtpAccount>());
        }

        if (batch.BatchSize <= 1)
        {
            return new OtpScanResult(OtpScanStatus.Complete, batch.Accounts);
        }

        if (_batchId != batch.BatchId)
        {
            // A different export was started, discard the parts of the previous one.
            Reset();
            _batchId = batch.BatchId;
        }

        BatchSize = Math.Max(BatchSize, batch.BatchSize);

        if (!_batchParts.TryAdd(batch.BatchIndex, batch.Accounts))
        {
            return new OtpScanResult(OtpScanStatus.AlreadyScanned, PendingAccounts);
        }

        if (_batchParts.Count >= BatchSize)
        {
            var accounts = PendingAccounts;
            Reset();
            return new OtpScanResult(OtpScanStatus.Complete, accounts);
        }

        return new OtpScanResult(OtpScanStatus.BatchPartial, PendingAccounts);
    }

    public void Reset()
    {
        _batchParts.Clear();
        _batchId = null;
        BatchSize = 0;
    }
}
