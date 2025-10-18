using System.Collections.Generic;
using Password_Phrase_Producer.PasswordGenerationTechniques.ConcatenationTechniques;
using Password_Phrase_Producer.PasswordGenerationTechniques.HashBasedTechniques;
using Password_Phrase_Producer.Windows.PasswordGenerationWindows;
using PasswordPhraseProducer.PasswordGenerationTechniques.TbvTechniques;
using Password_Phrase_Producer.Services.EntropyAnalyzer;

namespace Password_Phrase_Producer.Services;

public static class ModeCatalog
{
    private static readonly IPasswordEntropyAnalyzer EntropyAnalyzer = new PasswordEntropyAnalyzer();

    public static IReadOnlyList<PasswordModeOption> AllModes { get; } = new List<PasswordModeOption>
    {
        new(
            "hash-one",
            "1 Word Password",
            "Deterministisches Hash-Verfahren für ein einzelnes Wort.",
            () => new HachBasedTechniquesUiPage(new DeterministicHashPasswordGenerator(), EntropyAnalyzer),
            "mode-hash-one",
            "🔐"),
        new(
            "alternate",
            "Alternate Words",
            "Kombiniere abwechselnde Wörter zu einer starken Passphrase.",
            () => new ConcatenationTechniquesUiPage(new AlternatingUpDownChaining(), EntropyAnalyzer),
            "mode-alternate",
            "🧩"),
        new(
            "tbv1-errors",
            "TBV1 With Errors",
            "Dreifache Verifizierung mit intelligenter Fehlerbehandlung.",
            () => new TbvUiPage(new TBV1WithErrors(), EntropyAnalyzer),
            "mode-tbv1-errors",
            "🛡️"),
        new(
            "tbv1",
            "TBV1",
            "Klassische dreifache Verifizierung für Passphrasen.",
            () => new TbvUiPage(new TBV1(), EntropyAnalyzer),
            "mode-tbv1",
            "🧱"),
        new(
            "tbv2",
            "TBV2",
            "Erweiterte Verifizierung mit zusätzlichen Sicherheitsstufen.",
            () => new TbvUiPage(new TBV2(), EntropyAnalyzer),
            "mode-tbv2",
            "⚙️"),
        new(
            "tbv3",
            "TBV3",
            "Modernes Verfahren mit erweiterten Prüfungen und Komfort.",
            () => new TbvUiPage(new TBV3(), EntropyAnalyzer),
            "mode-tbv3",
            "🚀")
    };
}
