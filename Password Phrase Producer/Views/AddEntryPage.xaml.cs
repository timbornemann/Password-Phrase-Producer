using Camera.MAUI;
using Camera.MAUI.ZXingHelper;
using Password_Phrase_Producer.Services.Security;
using Password_Phrase_Producer.Models;

namespace Password_Phrase_Producer.Views;

public partial class AddEntryPage : ContentPage
{
    private readonly TotpService _totpService;
    private bool _isScanning = false;

    public BarcodeDecodeOptions BarCodeOptions { get; set; }

    public AddEntryPage(TotpService totpService)
    {
        InitializeComponent();
        _totpService = totpService;
        
        BarCodeOptions = new BarcodeDecodeOptions
        {
            AutoRotate = true,
            PossibleFormats = { BarcodeFormat.QR_CODE },
            ReadMultipleCodes = false,
            TryHarder = true,
            TryInverted = true
        };
        
        BindingContext = this;
    }

    private async void OnCloseClicked(object sender, EventArgs e)
    {
        await CloseCameraAsync();
        await Navigation.PopModalAsync();
    }

    private async void OnTabClicked(object sender, EventArgs e)
    {
        if (sender is Button btn)
        {
            if (btn == BtnManual)
            {
                ManualView.IsVisible = true;
                ScanView.IsVisible = false;
                BtnManual.BackgroundColor = Color.FromArgb("#7B8CFF");
                BtnManual.TextColor = Colors.White;
                BtnScan.BackgroundColor = Colors.Transparent;
                BtnScan.TextColor = Color.FromArgb("#A0A5BD");
                await CloseCameraAsync();
            }
            else
            {
                ManualView.IsVisible = false;
                ScanView.IsVisible = true;
                BtnScan.BackgroundColor = Color.FromArgb("#7B8CFF");
                BtnScan.TextColor = Colors.White;
                BtnManual.BackgroundColor = Colors.Transparent;
                BtnManual.TextColor = Color.FromArgb("#A0A5BD");
                await StartCameraAsync();
            }
        }
    }

    private async void OnSaveClicked(object sender, EventArgs e)
    {
        var issuer = EntryIssuer.Text?.Trim();
        var account = EntryAccount.Text?.Trim();
        var secretStr = EntrySecret.Text?.Trim()?.Replace(" ", "").ToUpperInvariant();

        if (string.IsNullOrEmpty(secretStr))
        {
            await DisplayAlert("Fehler", "Bitte Secret eingeben.", "OK");
            return;
        }

        try
        {
            var secretBytes = OtpNet.Base32Encoding.ToBytes(secretStr);
            var entry = new TotpEntry
            {
                Issuer = issuer ?? "",
                AccountName = account ?? "Unbenannt",
                Secret = secretBytes
            };

            await _totpService.AddOrUpdateEntryAsync(entry);
            await CloseCameraAsync();
            await Navigation.PopModalAsync();
        }
        catch
        {
            await DisplayAlert("Fehler", "Ungültiges Secret Format (Base32).", "OK");
        }
    }

    private async Task StartCameraAsync()
    {
        if (cameraView.Cameras.Count > 0)
        {
            cameraView.Camera = cameraView.Cameras.First();
            await cameraView.StartCameraAsync();
            _isScanning = true;
        }
        else
        {
            await DisplayAlert("Fehler", "Keine Kamera gefunden.", "OK");
        }
    }

    private async Task CloseCameraAsync()
    {
        if (_isScanning)
        {
            await cameraView.StopCameraAsync();
            _isScanning = false;
        }
    }

    private async void OnBarcodeDetected(object sender, Camera.MAUI.ZXingHelper.BarcodeEventArgs args)
    {
        if (!_isScanning) return;

        var result = args.Result?.First()?.Text;
        if (string.IsNullOrEmpty(result)) return;

        _isScanning = false; // Pause scanning

        MainThread.BeginInvokeOnMainThread(async () =>
        {
            try
            {
                await cameraView.StopCameraAsync(); // Stop camera while processing

                var imported = await _totpService.ImportFromUriAsync(result);
                if (imported.Count > 0)
                {
                    await DisplayAlert("Erfolg", $"{imported.Count} Einträge hinzugefügt.", "OK");
                    await Navigation.PopModalAsync();
                }
                else
                {
                    await DisplayAlert("Fehler", "QR-Code konnte nicht verarbeitet werden oder ist kein gültiger Authenticator-Code.", "OK");
                    await StartCameraAsync(); // Resume if failed
                }
            }
            catch (Exception ex)
            {
                await DisplayAlert("Fehler", ex.Message, "OK");
                await StartCameraAsync();
            }
        });
    }

    private void OnFlashlightClicked(object sender, EventArgs e)
    {
        cameraView.TorchEnabled = !cameraView.TorchEnabled;
    }

    protected override async void OnAppearing()
    {
        base.OnAppearing();
        // Check permissions
        var status = await Permissions.RequestAsync<Permissions.Camera>();
        if (status != PermissionStatus.Granted)
        {
            await DisplayAlert("Berechtigung", "Kamerazugriff erforderlich für Scan.", "OK");
        }
    }
    
    protected override async void OnDisappearing()
    {
        base.OnDisappearing();
        await CloseCameraAsync();
    }
}
