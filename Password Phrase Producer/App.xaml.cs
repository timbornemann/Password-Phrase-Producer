namespace Password_Phrase_Producer
{
    public partial class App : Application
    {
        public App()
        {
            InitializeComponent();

            MainPage = new AppShell();
        }

        protected override Window CreateWindow(IActivationState? activationState)
        {
            var window = base.CreateWindow(activationState);

            #if WINDOWS
                if (DeviceInfo.Idiom == DeviceIdiom.Desktop)
                {
                  window.Width = 300;
                  window.Height = 500;
                }
            #endif

            return window;
        }
    }
}
