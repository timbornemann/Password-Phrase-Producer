using Camera.MAUI;
using CommunityToolkit.Maui;
using Microsoft.Extensions.Logging;
using Microsoft.Maui.Handlers;
using Password_Phrase_Producer.Services.Security;
using Password_Phrase_Producer.Services.Synchronization;
using Password_Phrase_Producer.Services.Vault;
using Password_Phrase_Producer.ViewModels;
using Password_Phrase_Producer.Views;
using Password_Phrase_Producer.Views.Controls;
using Password_Phrase_Producer.Services.Updates;
using Password_Phrase_Producer.Views.Security;

namespace Password_Phrase_Producer;

public static class MauiProgram
{
    public static MauiApp CreateMauiApp()
    {
        var builder = MauiApp.CreateBuilder();
        builder
            .UseMauiApp<App>()
            .UseMauiCommunityToolkit()
            .UseMauiCameraView()
            .ConfigureFonts(fonts =>
            {
                fonts.AddFont("OpenSans-Regular.ttf", "OpenSansRegular");
                fonts.AddFont("OpenSans-Semibold.ttf", "OpenSansSemibold");
            });

        EntryHandler.Mapper.AppendToMapping("FramedEntry", (handler, view) =>
        {
            if (view is not FramedEntry) return;
#if WINDOWS
            handler.PlatformView.BorderThickness = new Microsoft.UI.Xaml.Thickness(1);
            handler.PlatformView.BorderBrush = new Microsoft.UI.Xaml.Media.SolidColorBrush(
                Microsoft.UI.ColorHelper.FromArgb(255, 49, 59, 68));
            handler.PlatformView.Background = new Microsoft.UI.Xaml.Media.SolidColorBrush(
                Microsoft.UI.ColorHelper.FromArgb(255, 32, 39, 46));
            handler.PlatformView.CornerRadius = new Microsoft.UI.Xaml.CornerRadius(4);
            handler.PlatformView.Padding = new Microsoft.UI.Xaml.Thickness(12, 0, 12, 0);
#elif ANDROID
            var density = handler.PlatformView.Context.Resources?.DisplayMetrics?.Density ?? 1f;
            var frame = new Android.Graphics.Drawables.GradientDrawable();
            frame.SetColor(Android.Graphics.Color.Rgb(32, 39, 46));
            frame.SetStroke(Math.Max(1, (int)Math.Round(density)), Android.Graphics.Color.Rgb(49, 59, 68));
            frame.SetCornerRadius(4 * density);
            handler.PlatformView.Background = frame;
            var inset = (int)Math.Round(12 * density);
            handler.PlatformView.SetPadding(inset, 0, inset, 0);
#elif IOS || MACCATALYST
            handler.PlatformView.BorderStyle = UIKit.UITextBorderStyle.RoundedRect;
            handler.PlatformView.BackgroundColor = UIKit.UIColor.FromRGB(32, 39, 46);
#endif
        });

        EditorHandler.Mapper.AppendToMapping("FramedEditor", (handler, view) =>
        {
            if (view is not FramedEditor) return;
#if WINDOWS
            handler.PlatformView.BorderThickness = new Microsoft.UI.Xaml.Thickness(1);
            handler.PlatformView.BorderBrush = new Microsoft.UI.Xaml.Media.SolidColorBrush(
                Microsoft.UI.ColorHelper.FromArgb(255, 49, 59, 68));
            handler.PlatformView.Background = new Microsoft.UI.Xaml.Media.SolidColorBrush(
                Microsoft.UI.ColorHelper.FromArgb(255, 32, 39, 46));
            handler.PlatformView.CornerRadius = new Microsoft.UI.Xaml.CornerRadius(4);
            handler.PlatformView.Padding = new Microsoft.UI.Xaml.Thickness(12, 8, 12, 8);
#elif ANDROID
            var density = handler.PlatformView.Context.Resources?.DisplayMetrics?.Density ?? 1f;
            var frame = new Android.Graphics.Drawables.GradientDrawable();
            frame.SetColor(Android.Graphics.Color.Rgb(32, 39, 46));
            frame.SetStroke(Math.Max(1, (int)Math.Round(density)), Android.Graphics.Color.Rgb(49, 59, 68));
            frame.SetCornerRadius(4 * density);
            handler.PlatformView.Background = frame;
            var horizontalInset = (int)Math.Round(12 * density);
            var verticalInset = (int)Math.Round(8 * density);
            handler.PlatformView.SetPadding(horizontalInset, verticalInset, horizontalInset, verticalInset);
#elif IOS || MACCATALYST
            handler.PlatformView.Layer.BorderWidth = 1;
            handler.PlatformView.Layer.BorderColor = UIKit.UIColor.FromRGB(49, 59, 68).CGColor;
            handler.PlatformView.Layer.CornerRadius = 4;
            handler.PlatformView.BackgroundColor = UIKit.UIColor.FromRGB(32, 39, 46);
            handler.PlatformView.TextContainerInset = new CoreGraphics.CGEdgeInsets(8, 12, 8, 12);
#endif
        });

#if DEBUG
        builder.Logging.AddDebug();
#endif

        builder.Services.AddSingleton<VaultMergeService>();
        builder.Services.AddAppUpdates();
        builder.Services.AddSingleton<PasswordVaultService>();
        builder.Services.AddSingleton<DataVaultService>();
        builder.Services.AddSingleton<TotpEncryptionService>();
        builder.Services.AddSingleton<TotpService>();
        builder.Services.AddSingleton<IBiometricAuthenticationService, BiometricAuthenticationService>();
        builder.Services.AddSingleton<IUnlockAttemptStore, SecureUnlockAttemptStore>();
        builder.Services.AddSingleton<IUnlockAttemptGate, UnlockAttemptGate>();
        builder.Services.AddSingleton<IRecoveryQuestionStore, SecureRecoveryQuestionStore>();
        builder.Services.AddSingleton<IRecoveryAccessAuthorizer, RecoveryAccessAuthorizer>();
        builder.Services.AddSingleton<IRecoveryQuestionsService, RecoveryQuestionsService>();
        builder.Services.AddTransient<VaultPageViewModel>();
        builder.Services.AddTransient<DataVaultPageViewModel>();
        builder.Services.AddTransient<VaultSettingsViewModel>();
        builder.Services.AddTransient<VaultPage>();
        builder.Services.AddTransient<DataVaultPage>();
        builder.Services.AddTransient<SettingsPage>();
        builder.Services.AddTransient<VaultEntryEditorPage>();
        builder.Services.AddTransient<AuthenticatorViewModel>();
        builder.Services.AddTransient<AuthenticatorPage>();
        builder.Services.AddSingleton<AuthenticatorPinPage>();
        builder.Services.AddTransient<AddEntryPage>();

        builder.Services.AddSingleton<Services.Security.IAppLockService, Services.Security.AppLockService>();
        builder.Services.AddSingleton<Services.LocalTransfer.LocalTransferActivity>();
        builder.Services.AddSingleton<Services.Storage.ISecureFileService, Services.Storage.SecureFileService>();
        builder.Services.AddSingleton<ISynchronizationService, SynchronizationService>();

        builder.Services.AddTransient<Views.Security.AppLoginPage>();
        builder.Services.AddTransient<Views.Security.SetupAppPasswordPage>();

#if WINDOWS
        builder.Services.AddSingleton<Password_Phrase_Producer.Services.Storage.ISyncFileService, Password_Phrase_Producer.Platforms.Windows.Services.WindowsSyncFileService>();
#elif ANDROID
        builder.Services.AddSingleton<Password_Phrase_Producer.Services.Storage.ISyncFileService, Password_Phrase_Producer.Platforms.Android.Services.AndroidSyncFileService>();
#endif

        return builder.Build();
    }
}
