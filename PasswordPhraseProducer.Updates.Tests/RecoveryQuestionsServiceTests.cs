using Password_Phrase_Producer.Services.Security;
using System.Text.Json.Nodes;
using Xunit;

namespace PasswordPhraseProducer.Updates.Tests;

public sealed class RecoveryQuestionsServiceTests
{
    [Fact]
    public async Task ConfigurationNeedsEveryConfiguredVaultUnlocked()
    {
        var access = new FakeAuthorizer { AllOpen = false };
        var service = NewService(access);
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => service.ConfigureAsync(Setup()));
        Assert.False(await service.IsConfiguredAsync());
        access.AllOpen = true;
        await service.ConfigureAsync(Setup());
        Assert.True(await service.IsConfiguredAsync());
    }

    [Fact]
    public async Task AnswersAreSelectionsAndNeverExposeCorrectChoiceOrIdentity()
    {
        var store = new MemoryStore();
        var access = new FakeAuthorizer { AllOpen = true };
        var service = NewService(access, store);
        await service.ConfigureAsync(Setup());
        var prompt = await service.GetPromptAsync();
        Assert.Equal(3, prompt.Count);
        Assert.All(prompt, question => Assert.Equal(5, question.Choices.Length));
        var raw = store.Data["RecoveryQuestions_V1"];
        Assert.DoesNotContain("Eva", raw);
        Assert.DoesNotContain("Beispiel", raw);
        Assert.DoesNotContain("CorrectChoice", raw);
        Assert.DoesNotContain("1990-01-02", raw);
    }

    [Fact]
    public async Task ExactAnswersGiveTwoPasswordTriesOncePerDomain()
    {
        var store = new MemoryStore();
        var gate = new UnlockAttemptGate(new MemoryAttemptStore());
        var service = new RecoveryQuestionsService(store, new FakeAuthorizer { AllOpen = true }, gate);
        await service.ConfigureAsync(Setup());
        await LockAsync(gate, ProtectedAccess.PasswordVault);
        Assert.True(await service.RedeemAsync(ProtectedAccess.PasswordVault,
            new RecoverySubmission("Eva", "Beispiel", new DateOnly(1990, 1, 2), [1, 3, 4])));
        Assert.Equal(2, (await gate.GetStatusAsync(ProtectedAccess.PasswordVault)).PasswordAttemptsRemaining);
        Assert.False((await gate.GetStatusAsync(ProtectedAccess.PasswordVault)).CanUseBiometrics);
        Assert.False(await service.RedeemAsync(ProtectedAccess.PasswordVault,
            new RecoverySubmission("Eva", "Beispiel", new DateOnly(1990, 1, 2), [1, 3, 4])));
    }

    [Fact]
    public async Task OneWrongSubmissionConsumesOnlyThatDomainsRecovery()
    {
        var gate = new UnlockAttemptGate(new MemoryAttemptStore());
        var service = new RecoveryQuestionsService(new MemoryStore(), new FakeAuthorizer { AllOpen = true }, gate);
        await service.ConfigureAsync(Setup());
        await LockAsync(gate, ProtectedAccess.App);
        await LockAsync(gate, ProtectedAccess.DataVault);
        Assert.False(await service.RedeemAsync(ProtectedAccess.App,
            new RecoverySubmission("eva", "Beispiel", new DateOnly(1990, 1, 2), [1, 3, 4])));
        Assert.False(await service.RedeemAsync(ProtectedAccess.App,
            new RecoverySubmission("Eva", "Beispiel", new DateOnly(1990, 1, 2), [1, 3, 4])));
        Assert.True((await gate.GetStatusAsync(ProtectedAccess.App)).IsLocked);
        Assert.True(await service.RedeemAsync(ProtectedAccess.DataVault,
            new RecoverySubmission("Eva", "Beispiel", new DateOnly(1990, 1, 2), [1, 3, 4])));
    }

    [Fact]
    public async Task RearmingIsExplicitAndNeedsEveryVaultOpen()
    {
        var access = new FakeAuthorizer { AllOpen = true };
        var gate = new UnlockAttemptGate(new MemoryAttemptStore());
        var service = new RecoveryQuestionsService(new MemoryStore(), access, gate);
        await service.ConfigureAsync(Setup());
        await LockAsync(gate, ProtectedAccess.Authenticator);
        Assert.False(await service.RedeemAsync(ProtectedAccess.Authenticator,
            new RecoverySubmission("wrong", "Beispiel", new DateOnly(1990, 1, 2), [1, 3, 4])));
        access.AllOpen = false;
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => service.RearmAsync(ProtectedAccess.Authenticator));
        access.AllOpen = true;
        await service.RearmAsync(ProtectedAccess.Authenticator);
        Assert.True(await service.RedeemAsync(ProtectedAccess.Authenticator,
            new RecoverySubmission("Eva", "Beispiel", new DateOnly(1990, 1, 2), [1, 3, 4])));
    }

    [Fact]
    public async Task IncompleteFormDoesNotSpendSingleSubmission()
    {
        var gate = new UnlockAttemptGate(new MemoryAttemptStore());
        var service = new RecoveryQuestionsService(new MemoryStore(), new FakeAuthorizer { AllOpen = true }, gate);
        await service.ConfigureAsync(Setup());
        await LockAsync(gate, ProtectedAccess.App);
        await Assert.ThrowsAsync<ArgumentException>(() => service.RedeemAsync(ProtectedAccess.App,
            new RecoverySubmission("", "Beispiel", new DateOnly(1990, 1, 2), [1, 3, 4])));
        Assert.True(await service.RedeemAsync(ProtectedAccess.App,
            new RecoverySubmission("Eva", "Beispiel", new DateOnly(1990, 1, 2), [1, 3, 4])));
    }

    [Fact]
    public async Task DamagedQuestionKeyFailsBeforeTheSingleSubmissionIsSpent()
    {
        var store = new MemoryStore();
        var gate = new UnlockAttemptGate(new MemoryAttemptStore());
        var service = new RecoveryQuestionsService(store, new FakeAuthorizer { AllOpen = true }, gate);
        await service.ConfigureAsync(Setup());
        await LockAsync(gate, ProtectedAccess.App);
        var keyName = store.Data.Keys.Single(key => key.StartsWith("RecoveryQuestionsKey_V1_"));
        store.Data[keyName] = "damaged";
        await Assert.ThrowsAsync<InvalidDataException>(() => service.RedeemAsync(ProtectedAccess.App,
            new RecoverySubmission("Eva", "Beispiel", new DateOnly(1990, 1, 2), [1, 3, 4])));
        Assert.False((await gate.GetStatusAsync(ProtectedAccess.App)).RecoveryUsed);
    }

    [Fact]
    public async Task ChangedAnswerOptionsCannotPreserveTheCorrectSelection()
    {
        var store = new MemoryStore();
        var gate = new UnlockAttemptGate(new MemoryAttemptStore());
        var service = new RecoveryQuestionsService(store, new FakeAuthorizer { AllOpen = true }, gate);
        await service.ConfigureAsync(Setup());
        await LockAsync(gate, ProtectedAccess.App);
        var record = JsonNode.Parse(store.Data["RecoveryQuestions_V1"])!;
        record["Questions"]![0]!["Choices"]![1] = "Changed";
        store.Data["RecoveryQuestions_V1"] = record.ToJsonString();

        Assert.False(await service.RedeemAsync(ProtectedAccess.App,
            new RecoverySubmission("Eva", "Beispiel", new DateOnly(1990, 1, 2), [1, 3, 4])));
        Assert.True((await gate.GetStatusAsync(ProtectedAccess.App)).RecoveryUsed);
    }

    private static RecoverySetup Setup() => new("Eva", "Beispiel", new DateOnly(1990, 1, 2),
    [
        new(0, ["A", "B", "C", "D", "E"], 1),
        new(1, ["F", "G", "H", "I", "J"], 3),
        new(2, ["K", "L", "M", "N", "O"], 4)
    ]);

    private static RecoveryQuestionsService NewService(FakeAuthorizer access, MemoryStore? store = null)
        => new(store ?? new MemoryStore(), access, new UnlockAttemptGate(new MemoryAttemptStore()));

    private static async Task LockAsync(UnlockAttemptGate gate, ProtectedAccess access)
    {
        for (var i = 0; i < 4; i++)
            await gate.RunPasswordAsync(access, () => Task.FromResult(false));
    }

    private sealed class FakeAuthorizer : IRecoveryAccessAuthorizer
    {
        public bool AllOpen { get; set; }
        public Task<bool> AllConfiguredVaultsUnlockedAsync() => Task.FromResult(AllOpen);
    }

    private sealed class MemoryStore : IRecoveryQuestionStore
    {
        public Dictionary<string, string> Data { get; } = new();
        public Task<string?> ReadAsync(string key) => Task.FromResult(Data.GetValueOrDefault(key));
        public Task WriteAsync(string key, string value) { Data[key] = value; return Task.CompletedTask; }
        public void Remove(string key) => Data.Remove(key);
    }

    private sealed class MemoryAttemptStore : IUnlockAttemptStore
    {
        private readonly Dictionary<string, string> _data = new();
        public Task<string?> ReadAsync(string key) => Task.FromResult(_data.GetValueOrDefault(key));
        public Task WriteAsync(string key, string value) { _data[key] = value; return Task.CompletedTask; }
    }
}
