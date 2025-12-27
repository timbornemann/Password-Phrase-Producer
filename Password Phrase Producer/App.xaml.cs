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
            _appLockService.Lock();
            // Secure the view to prevent snapshots of sensitive data
            MainPage = CreateSplashPage();
        }

        protected override async void OnResume()
        {
            base.OnResume();
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
                         if (MainPage is not AppLoginPage)
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
