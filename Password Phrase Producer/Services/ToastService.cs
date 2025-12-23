using System;
using System.Threading.Tasks;
using Microsoft.Maui.ApplicationModel;
using Microsoft.Maui.Controls;
using Password_Phrase_Producer.Views.Dialogs;

namespace Password_Phrase_Producer.Services;

/// <summary>
/// Service for displaying non-intrusive toast notifications.
/// </summary>
public static class ToastService
{
    /// <summary>
    /// Shows a brief toast notification at the bottom of the screen.
    /// </summary>
    /// <param name="message">The message to display.</param>
    /// <param name="durationMs">The duration to show the toast in milliseconds (default: 2000).</param>
    public static async Task ShowAsync(string message, int durationMs = 2000)
    {
        try
        {
            // Ensure we're on the main thread - this is critical for toast to display
            if (!MainThread.IsMainThread)
            {
                await MainThread.InvokeOnMainThreadAsync(async () =>
                {
                    await ShowToastAsync(message, durationMs);
                });
            }
            else
            {
                await ShowToastAsync(message, durationMs);
            }
        }
        catch (Exception ex)
        {
            // Log error in debug mode, but silently fail in release
            System.Diagnostics.Debug.WriteLine($"Toast error: {ex.Message}");
        }
    }

    private static async Task ShowToastAsync(string message, int durationMs)
    {
        var page = GetCurrentPage();
        if (page is not null)
        {
            await ToastPopup.ShowAsync(page, message, durationMs);
        }
    }

    private static Page? GetCurrentPage()
    {
        try
        {
            // Try to get the current page from the application
            if (Application.Current?.MainPage is Page mainPage)
            {
                // If it's a Shell, try to get the current page
                if (mainPage is Shell shell)
                {
                    return shell.CurrentPage;
                }
                
                // If it's a NavigationPage, get the current page
                if (mainPage is NavigationPage navPage)
                {
                    return navPage.CurrentPage;
                }
                
                return mainPage;
            }
        }
        catch
        {
            // Silently fail if we can't get the current page
        }

        return null;
    }

    /// <summary>
    /// Shows a "Copied" toast notification.
    /// </summary>
    /// <param name="itemName">Optional name of the copied item (e.g., "Passwort", "Benutzername").</param>
    public static Task ShowCopiedAsync(string? itemName = null)
    {
        var message = string.IsNullOrWhiteSpace(itemName)
            ? "In die Zwischenablage kopiert"
            : $"{itemName} kopiert";

        return ShowAsync(message);
    }
}

