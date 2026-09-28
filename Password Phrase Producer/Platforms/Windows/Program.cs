using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Velopack;

namespace Password_Phrase_Producer.WinUI;

internal static class Program
{
    [STAThread]
    public static void Main(string[] args)
    {
        // Installer hooks must exit before MAUI, storage or vault services are initialized.
        VelopackApp.Build().SetAutoApplyOnStartup(false).Run();
        using var instance = new Mutex(true, "Local\\PasswordPhraseProducer.UpdateInstance", out var isFirstInstance);
        if (!isFirstInstance) return;
        WinRT.ComWrappersSupport.InitializeComWrappers();
        Microsoft.UI.Xaml.Application.Start(initialization =>
        {
            SynchronizationContext.SetSynchronizationContext(
                new DispatcherQueueSynchronizationContext(DispatcherQueue.GetForCurrentThread()));
            _ = new App();
        });
    }
}
