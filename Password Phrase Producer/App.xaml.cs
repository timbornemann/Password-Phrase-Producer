using System;
using System.Threading.Tasks;
using Microsoft.Maui;
using Microsoft.Maui.Controls;
using Microsoft.Extensions.DependencyInjection;
using Password_Phrase_Producer.Services.Security;
using Password_Phrase_Producer.Services.Vault;
using Password_Phrase_Producer.Views.Security;
using Password_Phrase_Producer.Services.Updates;
using PasswordPhraseProducer.Updates;

namespace Password_Phrase_Producer
{
    public partial class App : Application
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly IAppLockService _appLockService;
        private bool _storageChecked;

        public App(IServiceProvider serviceProvider, IAppLockService appLockService)
        {
            InitializeComponent();
            _serviceProvider = serviceProvider;
            _appLockService = appLockService;

            // Initial splash/loading state
            MainPage = CreateSplashPage();
        }

        protected override async void OnStart()
        {
            base.OnStart();
            await InitializeNavigationAsync();
            _serviceProvider.GetRequiredService<UpdateLifecycle>().Start();
        }

        protected override void OnSleep()
        {
            base.OnSleep();
            _serviceProvider.GetRequiredService<UpdateLifecycle>().Stop();
            // Notify service of backgrounding to start timer
            _appLockService.OnAppBackgrounded();

            // NOTE: We do NOT lock immediately anymore to allow for a grace period.
            // We also do NOT replace the MainPage with a splash screen, so the app
            // state is preserved in the task switcher.
        }

        protected override async void OnResume()
        {
            base.OnResume();
            _serviceProvider.GetRequiredService<UpdateLifecycle>().Start();

            // Check if the background grace period has expired
            if (_appLockService.CheckLockTimeout())
            {
                _appLockService.Lock();
                _serviceProvider.GetRequiredService<PasswordVaultService>().Lock();
                _serviceProvider.GetRequiredService<DataVaultService>().Lock();
                _serviceProvider.GetRequiredService<TotpEncryptionService>().Lock();
                VaultNavigationCoordinator.ClearAllPending();

                // Force navigation to login page if locked
                MainThread.BeginInvokeOnMainThread(() =>
                {
                    var appLoginPage = _serviceProvider.GetRequiredService<AppLoginPage>();
                    MainPage = appLoginPage;
                });
            }

            await InitializeNavigationAsync();
        }

        private async Task InitializeNavigationAsync()
        {
             try
             {
#if ANDROID
                 if (Platforms.Android.Services.AndroidUpdateInstaller.RecoveryError is { } recoveryError)
                     throw new InvalidOperationException(recoveryError);
#endif
                 if (!_storageChecked)
                 {
                     await StartupDataGuard.VerifyAsync(FileSystem.AppDataDirectory, key => SecureStorage.Default.GetAsync(key));
#if IOS || MACCATALYST
                     // Previous biometric fallback persisted unwrapped vault keys.
                     SecureStorage.Default.Remove("PasswordVaultBiometricKey_V2");
                     SecureStorage.Default.Remove("DataVaultBiometricKey_V2");
#endif
                     _storageChecked = true;
                 }
                 var isConfigured = await _appLockService.IsConfiguredAsync();

                 MainThread.BeginInvokeOnMainThread(() =>
                 {
                     if (isConfigured)
                     {
                         // Only navigate to login if NOT unlocked and NOT already on login page
                         if (!_appLockService.IsUnlocked && MainPage is not AppLoginPage)
                         {
                             MainPage = _serviceProvider.GetRequiredService<AppLoginPage>();
                         }
                     }
                     else
                     {
                         if (MainPage is not SetupAppPasswordPage)
                         {
                             MainPage = _serviceProvider.GetRequiredService<SetupAppPasswordPage>();
                         }
                     }
                 });
             }
             catch (Exception ex)
             {
                 System.Diagnostics.Debug.WriteLine($"Startup data check: {ex.GetType().Name}");
                 await MainThread.InvokeOnMainThreadAsync(() =>
                 {
                     MainPage = new ContentPage
                     {
                         Title = "Wiederherstellung erforderlich",
                         Content = new VerticalStackLayout
                         {
                             Padding = 24,
                             Spacing = 16,
                             Children =
                             {
                                 new Label { Text = "Gespeicherte Daten können nicht sicher geöffnet werden.", FontSize = 22 },
                                 new Label { Text = "Die vorhandenen Dateien bleiben erhalten. Bitte verwende eine Sicherung oder repariere die Installation. Die App legt keinen neuen Tresor über den bestehenden Daten an." }
                             }
                         }
                     };
                 });
             }
        }

        private ContentPage CreateSplashPage()
        {
            return new ContentPage
            {
                BackgroundColor = Color.FromArgb("#512BD4"),
                Content = new ActivityIndicator
                {
                    IsRunning = true,
                    Color = Colors.White,
                    VerticalOptions = LayoutOptions.Center,
                    HorizontalOptions = LayoutOptions.Center
                }
            };
        }

        protected override Window CreateWindow(IActivationState? activationState)
        {
            var window = base.CreateWindow(activationState);

            #if WINDOWS
                  window.Width = 350;
                  window.Height = 600;
            #endif

            return window;
        }
    }
}
