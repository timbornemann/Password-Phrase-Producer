using System.Collections.Generic;
using Password_Phrase_Producer.PasswordGenerationTechniques.ConcatenationTechniques;
using Password_Phrase_Producer.PasswordGenerationTechniques.HashBasedTechniques;
using Password_Phrase_Producer.PasswordGenerationTechniques.DicewareTechnique;
using Password_Phrase_Producer.PasswordGenerationTechniques.MirrorLockTechnique;
using Password_Phrase_Producer.PasswordGenerationTechniques.PatternCascadeTechnique;
using Password_Phrase_Producer.PasswordGenerationTechniques.SegmentRotationTechnique;
using Password_Phrase_Producer.PasswordGenerationTechniques.SymbolInjectionTechnique;
using Password_Phrase_Producer.PasswordGenerationTechniques.CaesarCipherTechnique;
using Password_Phrase_Producer.PasswordGenerationTechniques.RandomPasswordTechnique;
using Password_Phrase_Producer.PasswordGenerationTechniques.Base64EncoderTechnique;
using Password_Phrase_Producer.PasswordGenerationTechniques.WordSubstitutionTechnique;
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
            "🚀"),
        new(
            "mirror-lock",
            "Mirror Lock",
            "Spiegele eine Phrase und ergänze sie um eine dreistellige Prüfsumme.",
            () => new MirrorTechniqueUiPage(new MirrorLockTechnique(), EntropyAnalyzer),
            "mode-mirror-lock",
            "🪞"),
        new(
            "segment-rotation",
            "Segment Rotation",
            "Zerlege Text in Segmente und rotiere sie für ein strukturiertes Passwort.",
            () => new SegmentRotationTechniqueUiPage(new SegmentRotationTechnique(), EntropyAnalyzer),
            "mode-segment-rotation",
            "🔁"),
        new(
            "diceware-seed",
            "Diceware Seeded",
            "Erzeuge Diceware-Phrasen mit optional deterministischem Seed.",
            () => new DicewareTechniqueUiPage(new AdaptiveDicewareTechnique(), EntropyAnalyzer),
            "mode-diceware-seed",
            "🎲"),
        new(
            "symbol-mixer",
            "Symbol Mixer",
            "Mische Symbole in ein Passwort und steuere die Groß-/Kleinschreibung.",
            () => new SymbolInjectionTechniqueUiPage(new SymbolInterleavingTechnique(), EntropyAnalyzer),
            "mode-symbol-mixer",
            "✨"),
        new(
            "pattern-cascade",
            "Pattern Cascade",
            "Kaskadiere Wörter und Zahlen zu einer wiederholbaren Struktur.",
            () => new PatternCascadeTechniqueUiPage(new PatternCascadeTechnique(), EntropyAnalyzer),
            "mode-pattern-cascade",
            "🧬"),
        new(
            "caesar-cipher",
            "Caesar Cipher",
            "Verschlüssele Text mit der klassischen Caesar-Verschlüsselung.",
            () => new CaesarCipherTechniqueUiPage(new CaesarCipherTechnique(), EntropyAnalyzer),
            "mode-caesar-cipher",
            "🔑"),
        new(
            "random-password",
            "Random Password",
            "Generiere zufällige Passwörter mit konfigurierbaren Zeichentypen und Länge.",
            () => new RandomPasswordTechniqueUiPage(new RandomPasswordTechnique(), EntropyAnalyzer),
            "mode-random-password",
            "🎲"),
        new(
            "base64-encoder",
            "Base64 Encoder",
            "Kodiere Text zu Base64 für sichere Passwort-Generierung.",
            () => new Base64EncoderTechniqueUiPage(new Base64EncoderTechnique(), EntropyAnalyzer),
            "mode-base64-encoder",
            "📦"),
        new(
            "word-substitution",
            "Word Substitution",
            "Transformiere Text mit Leet-Speak und intelligenten Wortersetzungen.",
            () => new WordSubstitutionTechniqueUiPage(new WordSubstitutionTechnique(), EntropyAnalyzer),
            "mode-word-substitution",
            "🔄")
    };
}
