using System;
using System.Threading.Tasks;
using Microsoft.Maui;
using Microsoft.Maui.Controls;
using Microsoft.Extensions.DependencyInjection;
using Password_Phrase_Producer.Services.Security;
using Password_Phrase_Producer.Views.Security;

namespace Password_Phrase_Producer
{
    public partial class App : Application
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly IAppLockService _appLockService;

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
        }

        protected override void OnSleep()
        {
            base.OnSleep();
            // Notify service of backgrounding to start timer
            _appLockService.OnAppBackgrounded();
            
            // NOTE: We do NOT lock immediately anymore to allow for a grace period.
            // We also do NOT replace the MainPage with a splash screen, so the app 
            // state is preserved in the task switcher.
        }

        protected override async void OnResume()
        {
            base.OnResume();
            
            // Check if the background grace period has expired
            if (_appLockService.CheckLockTimeout())
            {
                _appLockService.Lock();
                
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
                 System.Diagnostics.Debug.WriteLine($"Startup Error: {ex}");
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
