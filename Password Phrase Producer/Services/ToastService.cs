using System;
using System.Threading.Tasks;
using CommunityToolkit.Maui.Alerts;
using CommunityToolkit.Maui.Core;
using Microsoft.Maui.Graphics;

namespace Password_Phrase_Producer.Services;

/// <summary>
/// Service for displaying non-intrusive toast notifications.
/// </summary>
public static class ToastService
{
    private static readonly Color BackgroundColor = Color.FromArgb("#1B2036");
    private static readonly Color TextColor = Color.FromArgb("#E8EBFF");

    /// <summary>
    /// Shows a brief toast notification at the bottom of the screen.
    /// </summary>
    /// <param name="message">The message to display.</param>
    /// <param name="duration">The duration to show the toast (default: short).</param>
    public static async Task ShowAsync(string message, ToastDuration duration = ToastDuration.Short)
    {
        try
        {
            var toast = Toast.Make(
                message,
                duration,
                textSize: 14);

            await toast.Show();
        }
        catch
        {
            // Silently fail if toast cannot be shown
        }
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

