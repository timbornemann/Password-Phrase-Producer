using CommunityToolkit.Maui;
using Microsoft.Extensions.Logging;
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
            .ConfigureFonts(fonts =>
            {
                fonts.AddFont("OpenSans-Regular.ttf", "OpenSansRegular");
                fonts.AddFont("OpenSans-Semibold.ttf", "OpenSansSemibold");
            });

#if DEBUG
        builder.Logging.AddDebug();
#endif

        builder.Services.AddSingleton<PasswordVaultService>();
        builder.Services.AddTransient<VaultPageViewModel>();
        builder.Services.AddTransient<VaultPage>();
        builder.Services.AddTransient<VaultEntryEditorPage>();

        var app = builder.Build();

        var vaultService = app.Services.GetService<PasswordVaultService>();
        vaultService?.EnsureInitializedAsync().GetAwaiter().GetResult();

        return app;
    }
}
