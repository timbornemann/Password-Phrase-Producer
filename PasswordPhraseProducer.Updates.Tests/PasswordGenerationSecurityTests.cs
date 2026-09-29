using Password_Phrase_Producer.PasswordGenerationTechniques.DicewareTechnique;
using Password_Phrase_Producer.PasswordGenerationTechniques.RandomPasswordTechnique;
using Password_Phrase_Producer.PasswordGenerationTechniques.SymbolInjectionTechnique;
using Password_Phrase_Producer.Services.EntropyAnalyzer;
using Xunit;

namespace PasswordPhraseProducer.Updates.Tests;

public sealed class PasswordGenerationSecurityTests
{
    [Fact]
    public void RandomPasswordsUseSelectedCharactersAndFreshRandomness()
    {
        var generator = new RandomPasswordTechnique();
        var passwords = Enumerable.Range(0, 32)
            .Select(_ => generator.GeneratePassword(32, true, true, true, true))
            .ToArray();

        Assert.Equal(32, passwords.Distinct().Count());
        Assert.All(passwords, password =>
        {
            Assert.Equal(32, password.Length);
            Assert.Contains(password, char.IsLower);
            Assert.Contains(password, char.IsUpper);
            Assert.Contains(password, char.IsDigit);
            Assert.Contains(password, character => !char.IsLetterOrDigit(character));
        });
    }

    [Fact]
    public void SeededGeneratorsRemainDeterministic()
    {
        var password = new RandomPasswordTechnique();
        Assert.Equal(password.GeneratePassword(24, true, true, true, true, "private seed"),
            password.GeneratePassword(24, true, true, true, true, "private seed"));

        var diceware = new AdaptiveDicewareTechnique();
        Assert.Equal(diceware.Generate(6, "private seed"), diceware.Generate(6, "private seed"));

        var symbols = new SymbolInterleavingTechnique();
        Assert.Equal(symbols.InjectSymbols("long base", 4, true, "private seed"),
            symbols.InjectSymbols("long base", 4, true, "private seed"));
    }

    [Fact]
    public void DicewareLoadsTheCompleteWordlist()
    {
        using var stream = typeof(AdaptiveDicewareTechnique).Assembly.GetManifestResourceStream("EffLargeWordlist");
        Assert.NotNull(stream);
        using var reader = new StreamReader(stream);
        var words = reader.ReadToEnd().Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Select(line => line.TrimEnd('\r').Split('\t')[1]).ToArray();
        Assert.Equal(7776, words.Length);
        Assert.Equal(7776, words.Distinct(StringComparer.Ordinal).Count());

        var phrase = new AdaptiveDicewareTechnique().Generate(6, null);
        var selected = phrase.Split('!')[0].Split('-');
        Assert.Equal(6, selected.Length);
        Assert.All(selected, word => Assert.Contains(word, words));
    }

    [Fact]
    public void AppearanceDoesNotClaimEntropyForDeterministicResults()
    {
        var analysis = new PasswordEntropyAnalyzer().Analyze("ABCDEFGHIJKLMNOPQRSTUVWXYZ123456789!@#");
        Assert.True(double.IsNaN(analysis.Entropy));
        Assert.Equal("Nicht messbar", analysis.StrengthLabel);
    }

    [Fact]
    public void RandomPasswordEstimateIsConservative()
    {
        var bits = RandomPasswordTechnique.MinimumEntropyBits(16, true, true, true, true);
        Assert.InRange(bits, 80, 16 * Math.Log2(100));
        Assert.Equal(16 * Math.Log2(26),
            RandomPasswordTechnique.MinimumEntropyBits(16, false, true, false, false), 8);
    }
}
