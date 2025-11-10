using Microsoft.Maui.Controls;

namespace Password_Phrase_Producer.Views;

public interface IPasswordGeneratorActionHost
{
    bool TrySetAddToVaultAction(View actionView);
}
