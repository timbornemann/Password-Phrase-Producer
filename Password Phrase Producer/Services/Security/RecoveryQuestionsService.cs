using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Password_Phrase_Producer.Services.Security;

public sealed record RecoveryQuestion(int Id, string Text);
public sealed record RecoveryQuestionSetup(int QuestionId, string[] Choices, int CorrectChoice);
public sealed record RecoverySetup(string FirstName, string LastName, DateOnly BirthDate,
    RecoveryQuestionSetup[] Questions);
public sealed record RecoveryPromptQuestion(int QuestionId, string Text, string[] Choices);
public sealed record RecoverySubmission(string FirstName, string LastName, DateOnly BirthDate,
    int[] SelectedChoices);

public interface IRecoveryQuestionStore
{
    Task<string?> ReadAsync(string key);
    Task WriteAsync(string key, string value);
    void Remove(string key);
}

public sealed class SecureRecoveryQuestionStore : IRecoveryQuestionStore
{
    public Task<string?> ReadAsync(string key) => SecureStorage.Default.GetAsync(key);
    public Task WriteAsync(string key, string value) => SecureStorage.Default.SetAsync(key, value);
    public void Remove(string key) => SecureStorage.Default.Remove(key);
}

public interface IRecoveryAccessAuthorizer
{
    Task<bool> AllConfiguredVaultsUnlockedAsync();
}

public interface IRecoveryQuestionsService
{
    Task<bool> IsConfiguredAsync();
    Task<IReadOnlyList<RecoveryPromptQuestion>> GetPromptAsync();
    Task ConfigureAsync(RecoverySetup setup);
    Task<bool> RedeemAsync(ProtectedAccess access, RecoverySubmission submission);
    Task RearmAsync(ProtectedAccess access);
}

public sealed class RecoveryQuestionsService : IRecoveryQuestionsService
{
    private const string RecordKey = "RecoveryQuestions_V1";
    private const string KeyPrefix = "RecoveryQuestionsKey_V1_";
    private readonly IRecoveryQuestionStore _store;
    private readonly IRecoveryAccessAuthorizer _authorizer;
    private readonly IUnlockAttemptGate _gate;
    private readonly SemaphoreSlim _saveMutex = new(1, 1);

    public static IReadOnlyList<RecoveryQuestion> AvailableQuestions { get; } =
    [
        new(0, "Wie lautet der Mädchenname deiner Mutter?"),
        new(1, "Wie hieß dein erstes Haustier?"),
        new(2, "Was ist dein Lieblingsessen?"),
        new(3, "Wie hieß deine erste Schule?"),
        new(4, "Wie hieß deine erste Lehrkraft?"),
        new(5, "Wie hieß dein bester Freund oder deine beste Freundin in der Kindheit?"),
        new(6, "In welcher Straße hast du als Kind gewohnt?"),
        new(7, "Was ist dein Lieblingsbuch?"),
        new(8, "Was ist dein Lieblingsfilm?"),
        new(9, "Wie hieß dein erster Urlaubsort?")
    ];

    public RecoveryQuestionsService(IRecoveryQuestionStore store, IRecoveryAccessAuthorizer authorizer,
        IUnlockAttemptGate gate)
    {
        _store = store;
        _authorizer = authorizer;
        _gate = gate;
    }

    public async Task<bool> IsConfiguredAsync() => await LoadRecordAsync().ConfigureAwait(false) is not null;

    public async Task<IReadOnlyList<RecoveryPromptQuestion>> GetPromptAsync()
    {
        var record = await LoadRecordAsync().ConfigureAwait(false)
                     ?? throw new InvalidOperationException("Sicherheitsfragen sind nicht eingerichtet.");
        return record.Questions.Select(q => new RecoveryPromptQuestion(q.QuestionId,
            AvailableQuestions[q.QuestionId].Text, q.Choices.ToArray())).ToArray();
    }

    public async Task ConfigureAsync(RecoverySetup setup)
    {
        ValidateSetup(setup);
        if (!await _authorizer.AllConfiguredVaultsUnlockedAsync().ConfigureAwait(false))
            throw new UnauthorizedAccessException("Für diese Änderung müssen App und alle eingerichteten Tresore geöffnet sein.");

        await _saveMutex.WaitAsync().ConfigureAwait(false);
        try
        {
            var previous = await LoadRecordAsync().ConfigureAwait(false);
            var keyId = Guid.NewGuid().ToString("N");
            var hmacKey = RandomNumberGenerator.GetBytes(32);
            try
            {
                var questions = setup.Questions.Select(q => new StoredQuestion
                {
                    QuestionId = q.QuestionId,
                    Choices = q.Choices.Select(Normalize).ToArray()
                }).ToArray();
                var correct = setup.Questions.Select(q => q.CorrectChoice).ToArray();
                var record = new StoredRecord
                {
                    Version = 1,
                    KeyId = keyId,
                    Digest = Convert.ToBase64String(ComputeDigest(hmacKey, setup.FirstName, setup.LastName,
                        setup.BirthDate, questions, correct)),
                    Questions = questions
                };
                await _store.WriteAsync(KeyPrefix + keyId, Convert.ToBase64String(hmacKey)).ConfigureAwait(false);
                if (!await _authorizer.AllConfiguredVaultsUnlockedAsync().ConfigureAwait(false))
                {
                    _store.Remove(KeyPrefix + keyId);
                    throw new UnauthorizedAccessException("Ein Tresor wurde während der Einrichtung gesperrt.");
                }
                try { await _store.WriteAsync(RecordKey, JsonSerializer.Serialize(record)).ConfigureAwait(false); }
                catch
                {
                    _store.Remove(KeyPrefix + keyId);
                    throw;
                }
                if (previous is not null)
                {
                    try { _store.Remove(KeyPrefix + previous.KeyId); }
                    catch { /* The new record is already committed; an orphaned old key grants no access. */ }
                }
            }
            finally { CryptographicOperations.ZeroMemory(hmacKey); }
        }
        finally { _saveMutex.Release(); }
    }

    public async Task<bool> RedeemAsync(ProtectedAccess access, RecoverySubmission submission)
    {
        ArgumentNullException.ThrowIfNull(submission);
        // Incomplete forms do not spend the sole answer submission.
        if (string.IsNullOrWhiteSpace(submission.FirstName) || string.IsNullOrWhiteSpace(submission.LastName) ||
            submission.BirthDate == default || submission.SelectedChoices?.Length != 3 ||
            submission.SelectedChoices.Any(choice => choice is < 0 or > 4))
            throw new ArgumentException("Bitte alle Angaben ausfüllen.", nameof(submission));

        var record = await LoadRecordAsync().ConfigureAwait(false)
                     ?? throw new InvalidOperationException("Sicherheitsfragen sind nicht eingerichtet.");
        return await _gate.RedeemRecoveryAsync(access, async () =>
        {
            var keyText = await _store.ReadAsync(KeyPrefix + record.KeyId).ConfigureAwait(false)
                          ?? throw new InvalidDataException("Der Frageschlüssel fehlt.");
            var key = Convert.FromBase64String(keyText);
            try
            {
                if (key.Length != 32) throw new InvalidDataException("Der Frageschlüssel ist beschädigt.");
                var actual = ComputeDigest(key, submission.FirstName, submission.LastName, submission.BirthDate,
                    record.Questions, submission.SelectedChoices);
                var expected = Convert.FromBase64String(record.Digest);
                return CryptographicOperations.FixedTimeEquals(actual, expected);
            }
            finally { CryptographicOperations.ZeroMemory(key); }
        }).ConfigureAwait(false);
    }

    public async Task RearmAsync(ProtectedAccess access)
    {
        if (!await IsConfiguredAsync().ConfigureAwait(false))
            throw new InvalidOperationException("Sicherheitsfragen sind nicht eingerichtet.");
        if (!await _authorizer.AllConfiguredVaultsUnlockedAsync().ConfigureAwait(false))
            throw new UnauthorizedAccessException("Für diese Änderung müssen App und alle eingerichteten Tresore geöffnet sein.");
        await _gate.RearmRecoveryAsync(access).ConfigureAwait(false);
    }

    private async Task<StoredRecord?> LoadRecordAsync()
    {
        var json = await _store.ReadAsync(RecordKey).ConfigureAwait(false);
        if (json is null) return null;
        StoredRecord record;
        try { record = JsonSerializer.Deserialize<StoredRecord>(json) ?? throw new JsonException(); }
        catch (JsonException ex) { throw new InvalidDataException("Sicherheitsfragen sind beschädigt.", ex); }
        if (record.Version != 1 || !Guid.TryParseExact(record.KeyId, "N", out _) ||
            record.Questions?.Length != 3 || record.Questions.Any(q => q is null) ||
            record.Questions.Select(q => q.QuestionId).Distinct().Count() != 3 ||
            record.Questions.Any(q => q.QuestionId < 0 || q.QuestionId >= AvailableQuestions.Count ||
                                      q.Choices?.Length != 5 || q.Choices.Any(string.IsNullOrWhiteSpace) ||
                                      q.Choices.Select(Normalize).Distinct(StringComparer.OrdinalIgnoreCase).Count() != 5) ||
            !TryDecodeDigest(record.Digest))
            throw new InvalidDataException("Sicherheitsfragen sind beschädigt.");
        var keyText = await _store.ReadAsync(KeyPrefix + record.KeyId).ConfigureAwait(false);
        if (keyText is null) throw new InvalidDataException("Der Frageschlüssel fehlt.");
        byte[] key;
        try { key = Convert.FromBase64String(keyText); }
        catch (FormatException ex) { throw new InvalidDataException("Der Frageschlüssel ist beschädigt.", ex); }
        try
        {
            if (key.Length != 32) throw new InvalidDataException("Der Frageschlüssel ist beschädigt.");
        }
        finally { CryptographicOperations.ZeroMemory(key); }
        return record;
    }

    private static bool TryDecodeDigest(string? value)
    {
        try { return value is not null && Convert.FromBase64String(value).Length == 32; }
        catch (FormatException) { return false; }
    }

    private static void ValidateSetup(RecoverySetup setup)
    {
        ArgumentNullException.ThrowIfNull(setup);
        if (string.IsNullOrWhiteSpace(setup.FirstName) || string.IsNullOrWhiteSpace(setup.LastName) ||
            setup.BirthDate == default || setup.BirthDate > DateOnly.FromDateTime(DateTime.UtcNow) ||
            setup.Questions?.Length != 3 || setup.Questions.Select(q => q.QuestionId).Distinct().Count() != 3)
            throw new ArgumentException("Vorname, Nachname, Geburtsdatum und drei verschiedene Fragen sind erforderlich.");
        foreach (var question in setup.Questions)
        {
            if (question.QuestionId < 0 || question.QuestionId >= AvailableQuestions.Count ||
                question.Choices?.Length != 5 || question.CorrectChoice is < 0 or > 4 ||
                question.Choices.Any(string.IsNullOrWhiteSpace) ||
                question.Choices.Select(Normalize).Distinct(StringComparer.OrdinalIgnoreCase).Count() != 5)
                throw new ArgumentException("Jede Frage braucht fünf verschiedene Antworten und eine richtige Auswahl.");
        }
    }

    private static byte[] ComputeDigest(byte[] key, string firstName, string lastName, DateOnly birthDate,
        StoredQuestion[] questions, int[] selectedChoices)
    {
        var canonical = JsonSerializer.Serialize(new
        {
            FirstName = Normalize(firstName), LastName = Normalize(lastName),
            BirthDate = birthDate.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture),
            Selections = questions.Select((q, index) => new
            {
                q.QuestionId,
                q.Choices,
                Choice = selectedChoices[index]
            }).ToArray()
        });
        var bytes = Encoding.UTF8.GetBytes(canonical);
        try { return HMACSHA256.HashData(key, bytes); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    private static string Normalize(string value) => value.Trim().Normalize(NormalizationForm.FormC);

    private sealed class StoredRecord
    {
        public int Version { get; set; }
        public string KeyId { get; set; } = string.Empty;
        public string Digest { get; set; } = string.Empty;
        public StoredQuestion[] Questions { get; set; } = [];
    }

    private sealed class StoredQuestion
    {
        public int QuestionId { get; set; }
        public string[] Choices { get; set; } = [];
    }
}
