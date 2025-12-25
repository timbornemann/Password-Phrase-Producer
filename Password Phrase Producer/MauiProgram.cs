using Camera.MAUI;
using CommunityToolkit.Maui;
using Microsoft.Extensions.Logging;
using Password_Phrase_Producer.Services.Security;
using Password_Phrase_Producer.Services.Vault;
using Password_Phrase_Producer.ViewModels;
using Password_Phrase_Producer.Views;

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

#if DEBUG
        builder.Logging.AddDebug();
#endif

        builder.Services.AddSingleton<PasswordVaultService>();
        builder.Services.AddSingleton<DataVaultService>();
        builder.Services.AddSingleton<TotpEncryptionService>();
        builder.Services.AddSingleton<TotpService>();
        builder.Services.AddSingleton<IBiometricAuthenticationService, BiometricAuthenticationService>();
        builder.Services.AddTransient<VaultPageViewModel>();
        builder.Services.AddTransient<DataVaultPageViewModel>();
        builder.Services.AddTransient<VaultSettingsViewModel>();
        builder.Services.AddTransient<VaultPage>();
        builder.Services.AddTransient<DataVaultPage>();
        builder.Services.AddTransient<SettingsPage>();
        builder.Services.AddTransient<VaultEntryEditorPage>();
        builder.Services.AddTransient<AuthenticatorViewModel>();
        builder.Services.AddTransient<AuthenticatorPage>();
        builder.Services.AddTransient<AuthenticatorPinPage>();
        builder.Services.AddTransient<AddEntryPage>();

        return builder.Build();
    }
}
