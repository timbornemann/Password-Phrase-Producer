using System.Linq;
using Microsoft.Maui.Controls;
using Password_Phrase_Producer.Models;

namespace Password_Phrase_Producer.Views;

public partial class VaultEntryEditorPage : ContentPage
{
    private readonly TaskCompletionSource<PasswordVaultEntry?> _resultSource = new();

    public VaultEntryEditorPage(PasswordVaultEntry entry, string title)
    {
        InitializeComponent();
        BindingContext = entry;
        Title = title;
    }

    public Task<PasswordVaultEntry?> Result => _resultSource.Task;

    public static async Task<PasswordVaultEntry?> ShowAsync(INavigation navigation, PasswordVaultEntry entry, string title)
    {
        var page = new VaultEntryEditorPage(entry, title);
        await navigation.PushModalAsync(page);
        return await page.Result.ConfigureAwait(false);
    }

    private async void OnSaveClicked(object? sender, EventArgs e)
    {
        if (BindingContext is PasswordVaultEntry entry)
        {
            entry.ModifiedAt = DateTimeOffset.UtcNow;
            _resultSource.TrySetResult(entry);
        }

        await CloseAsync().ConfigureAwait(false);
    }

    private async void OnCancelClicked(object? sender, EventArgs e)
    {
        _resultSource.TrySetResult(null);
        await CloseAsync().ConfigureAwait(false);
    }

    private void OnCloseTapped(object? sender, TappedEventArgs e)
        => OnCancelClicked(sender, EventArgs.Empty);

    protected override bool OnBackButtonPressed()
    {
        if (!_resultSource.Task.IsCompleted)
        {
            _resultSource.TrySetResult(null);
        }

        return base.OnBackButtonPressed();
    }

    private async Task CloseAsync()
    {
        if (Navigation.ModalStack.Contains(this))
        {
            await Navigation.PopModalAsync().ConfigureAwait(false);
        }
    }
}
