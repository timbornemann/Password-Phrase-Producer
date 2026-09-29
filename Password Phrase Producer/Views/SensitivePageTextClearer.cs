using Microsoft.Maui.Controls;

namespace Password_Phrase_Producer.Views;

internal static class SensitivePageTextClearer
{
    internal static void Clear(Element? root)
    {
        if (root is null) return;

        if (root is InputView input) input.Text = string.Empty;
        else if (root is Label label) label.Text = string.Empty;

        foreach (var child in root.LogicalChildren.OfType<Element>())
            Clear(child);
    }
}
