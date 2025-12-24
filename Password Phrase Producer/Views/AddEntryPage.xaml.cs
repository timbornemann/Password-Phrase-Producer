using Camera.MAUI;
using Camera.MAUI.ZXingHelper;
using Microsoft.Maui.ApplicationModel;
using Password_Phrase_Producer.Services.Security;
using Password_Phrase_Producer.Models;
using ZXing;
using CameraBarcodeFormat = Camera.MAUI.BarcodeFormat;
using ZXingBarcodeFormat = ZXing.BarcodeFormat;

namespace Password_Phrase_Producer.Views;

public partial class AddEntryPage : ContentPage
{
    private readonly TotpService _totpService;
    private bool _isScanning = false;
    private bool _isProcessing = false;
    private System.Threading.Timer? _autoScanTimer;

    public BarcodeDecodeOptions BarCodeOptions { get; set; }

    public AddEntryPage(TotpService totpService)
    {
        InitializeComponent();
        _totpService = totpService;
        
        // IMPORTANT: Create fresh BarcodeDecodeOptions
        BarCodeOptions = new BarcodeDecodeOptions
        {
            AutoRotate = true,
            TryHarder = true,
            TryInverted = true,
            ReadMultipleCodes = false
        };
        
        // Add QR_CODE format only once
        BarCodeOptions.PossibleFormats.Clear(); // Clear any defaults
        BarCodeOptions.PossibleFormats.Add(CameraBarcodeFormat.QR_CODE);
        
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
                BtnManual.BackgroundColor = Color.FromArgb("#4A5CFF");
                BtnManual.TextColor = Colors.White;
                BtnScan.BackgroundColor = Colors.Transparent;
                BtnScan.TextColor = Color.FromArgb("#7F85B2");
                await CloseCameraAsync();
            }
            else
            {
                ManualView.IsVisible = false;
                ScanView.IsVisible = true;
                BtnScan.BackgroundColor = Color.FromArgb("#4A5CFF");
                BtnScan.TextColor = Colors.White;
                BtnManual.BackgroundColor = Colors.Transparent;
                BtnManual.TextColor = Color.FromArgb("#7F85B2");

                var cameraStarted = await StartCameraAsync();
                if (!cameraStarted)
                {
                    ManualView.IsVisible = true;
                    ScanView.IsVisible = false;
                    BtnManual.BackgroundColor = Color.FromArgb("#4A5CFF");
                    BtnManual.TextColor = Colors.White;
                    BtnScan.BackgroundColor = Colors.Transparent;
                    BtnScan.TextColor = Color.FromArgb("#7F85B2");
                }
            }
        }
    }

    private async void OnSaveClicked(object sender, EventArgs e)
    {
        var issuer = EntryIssuer.Text?.Trim();
        var account = EntryAccount.Text?.Trim();
        var secretStr = NormalizeBase32Secret(EntrySecret.Text);

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
        catch (System.FormatException)
        {
            await DisplayAlert("Fehler", "Ungültiges Secret Format (Base32). Erlaubt sind A–Z und 2–7. Leerzeichen/Bindestriche sind ok.", "OK");
        }
        catch
        {
            await DisplayAlert("Fehler", "Ungültiges Secret Format (Base32).", "OK");
        }
    }

    private static string NormalizeBase32Secret(string? input)
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            return string.Empty;
        }

        // Many providers group secrets with spaces/dashes or contain non-breaking spaces/newlines.
        // Normalize by removing all whitespace, hyphens and padding '='.
        var cleaned = new string(input
            .Trim()
            .Where(c => !char.IsWhiteSpace(c) && c != '-' && c != '=')
            .ToArray());

        return cleaned.ToUpperInvariant();
    }

    private async Task<bool> StartCameraAsync()
    {
        try
        {
            var permissionGranted = await EnsureCameraPermissionAsync();
            if (!permissionGranted)
            {
                return false;
            }

            if (cameraView.Cameras.Count > 0)
            {
                cameraView.Camera = cameraView.Cameras.First();
                
                // Set zoom
                cameraView.ZoomFactor = 1.0f;
                
                await cameraView.StartCameraAsync();
                
                _isScanning = true;
                _isProcessing = false;
                
                // Start auto-scan timer (Windows workaround)
                StartAutoScanTimer();
                
                MainThread.BeginInvokeOnMainThread(() =>
                {
                    ScanStatusLabel.Text = "Bereit zum Scannen";
                    ScanStatusLabel.TextColor = Color.FromArgb("#4A5CFF");
                    DetectionFrame.IsVisible = false;
                    UpdateZoomButtonText();
                });

                return true;
            }
            else
            {
                await DisplayAlert("Fehler", "Keine Kamera gefunden.", "OK");
            }
        }
        catch (Exception ex)
        {
            await DisplayAlert("Fehler", $"Kamera konnte nicht gestartet werden: {ex.Message}", "OK");
        }

        return false;
    }
    
    private void StartAutoScanTimer()
    {
        // Auto-scan every 2 seconds as fallback for Windows
        _autoScanTimer?.Dispose();
        _autoScanTimer = new System.Threading.Timer(async _ =>
        {
            if (_isScanning && !_isProcessing)
            {
                await TryCaptureAndScan(autoMode: true);
            }
        }, null, TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(2));
    }
    
    private void StopAutoScanTimer()
    {
        _autoScanTimer?.Dispose();
        _autoScanTimer = null;
    }

    private async Task<bool> EnsureCameraPermissionAsync()
    {
        var status = await Permissions.CheckStatusAsync<Permissions.Camera>();
        if (status != PermissionStatus.Granted)
        {
            status = await Permissions.RequestAsync<Permissions.Camera>();
        }

        if (status != PermissionStatus.Granted)
        {
            await DisplayAlert("Kamera benötigt", "Bitte erlaube den Kamera-Zugriff, um QR-Codes zu scannen.", "OK");
            return false;
        }

        return true;
    }

    private async Task CloseCameraAsync()
    {
        if (_isScanning)
        {
            StopAutoScanTimer();
            await cameraView.StopCameraAsync();
            _isScanning = false;
        }
    }
    
    private async void OnCaptureClicked(object sender, EventArgs e)
    {
        await TryCaptureAndScan(autoMode: false);
    }
    
    private async Task TryCaptureAndScan(bool autoMode)
    {
        if (_isProcessing) return;
        
        _isProcessing = true;
        
        try
        {
            MainThread.BeginInvokeOnMainThread(() =>
            {
                if (!autoMode)
                {
                    ScanStatusLabel.Text = "Erfasse Bild...";
                    ScanStatusLabel.TextColor = Color.FromArgb("#FFD700");
                    CaptureButton.IsEnabled = false;
                }
            });
            
            // Take snapshot from camera
            var imageStream = await cameraView.TakePhotoAsync(Camera.MAUI.ImageFormat.PNG);
            
            if (imageStream != null && imageStream.Length > 0)
            {
                MainThread.BeginInvokeOnMainThread(() =>
                {
                    ScanStatusLabel.Text = "Analysiere QR-Code...";
                });
                
                // Convert stream to byte array
                using var memoryStream = new MemoryStream();
                await imageStream.CopyToAsync(memoryStream);
                var imageBytes = memoryStream.ToArray();
                
                // Decode QR code using ZXing
                var reader = new ZXing.BarcodeReaderGeneric();
                reader.Options.TryHarder = true;
                reader.Options.PossibleFormats = new List<ZXingBarcodeFormat> { ZXingBarcodeFormat.QR_CODE };
                
                // Convert bytes to LuminanceSource
                using var ms = new MemoryStream(imageBytes);
                var bitmap = SkiaSharp.SKBitmap.Decode(ms);
                
                if (bitmap != null)
                {
                    var luminanceSource = new ZXing.SkiaSharp.SKBitmapLuminanceSource(bitmap);
                    var result = reader.Decode(luminanceSource);
                    
                    if (result != null && !string.IsNullOrEmpty(result.Text))
                    {
                        await ProcessQRCode(result.Text, autoMode);
                    }
                    else
                    {
                        if (!autoMode)
                        {
                            MainThread.BeginInvokeOnMainThread(async () =>
                            {
                                ScanStatusLabel.Text = "Kein QR-Code gefunden";
                                ScanStatusLabel.TextColor = Color.FromArgb("#FF6B00");
                                CaptureButton.IsEnabled = true;
                                await Task.Delay(2000);
                                ScanStatusLabel.Text = "Bereit zum Scannen";
                                ScanStatusLabel.TextColor = Color.FromArgb("#4A5CFF");
                            });
                        }
                    }
                }
                else
                {
                }
            }
            else
            {
                if (!autoMode)
                {
                    MainThread.BeginInvokeOnMainThread(() =>
                    {
                        ScanStatusLabel.Text = "Fehler beim Erfassen";
                        ScanStatusLabel.TextColor = Color.FromArgb("#FF0000");
                        CaptureButton.IsEnabled = true;
                    });
                }
            }
        }
        catch (Exception ex)
        {
            if (!autoMode)
            {
                MainThread.BeginInvokeOnMainThread(() =>
                {
                    ScanStatusLabel.Text = $"Fehler: {ex.Message}";
                    ScanStatusLabel.TextColor = Color.FromArgb("#FF0000");
                    CaptureButton.IsEnabled = true;
                });
            }
        }
        finally
        {
            _isProcessing = false;
        }
    }
    
    private async Task ProcessQRCode(string qrText, bool autoMode)
    {
        StopAutoScanTimer(); // Stop auto-scanning
        _isScanning = false;
        
        MainThread.BeginInvokeOnMainThread(async () =>
        {
            DetectionFrame.IsVisible = true;
            ScanStatusLabel.Text = "QR-Code erkannt! ✓";
            ScanStatusLabel.TextColor = Color.FromArgb("#00FF00");
            _ = AnimateDetectionFrame();
            
            await Task.Delay(1000);
            
            try
            {
                await cameraView.StopCameraAsync();
                
                ScanStatusLabel.Text = "Verarbeite QR-Code...";
                ScanStatusLabel.TextColor = Color.FromArgb("#FFD700");

                var imported = await _totpService.ImportFromUriAsync(qrText);
                if (imported.Count > 0)
                {
                    await DisplayAlert("Erfolg", $"{imported.Count} Einträge hinzugefügt.", "OK");
                    await Navigation.PopModalAsync();
                }
                else
                {
                    DetectionFrame.IsVisible = false;
                    ScanStatusLabel.Text = "Ungültiger QR-Code";
                    ScanStatusLabel.TextColor = Color.FromArgb("#FF0000");
                    await DisplayAlert("Fehler", "QR-Code konnte nicht verarbeitet werden.\n\nErwartetes Format: otpauth://totp/...", "OK");
                    CaptureButton.IsEnabled = true;
                    await StartCameraAsync();
                }
            }
            catch (Exception ex)
            {
                DetectionFrame.IsVisible = false;
                ScanStatusLabel.Text = "Fehler beim Scannen";
                ScanStatusLabel.TextColor = Color.FromArgb("#FF0000");
                await DisplayAlert("Fehler", $"Fehler beim Verarbeiten: {ex.Message}", "OK");
                CaptureButton.IsEnabled = true;
                await StartCameraAsync();
            }
        });
    }
    
    private void OnCamerasLoaded(object sender, EventArgs e)
    {
    }

    private async void OnBarcodeDetected(object sender, Camera.MAUI.ZXingHelper.BarcodeEventArgs args)
    {
        if (!_isScanning || _isProcessing)
        {
            return;
        }

        var result = args.Result?.FirstOrDefault();
        if (result == null || string.IsNullOrEmpty(result.Text)) 
        {
            return;
        }

        _isProcessing = true; // Prevent multiple detections

        // Show detection frame and update status
        MainThread.BeginInvokeOnMainThread(async () =>
        {
            try
            {
                // Show centered detection frame (since we don't have position data)
                DetectionFrame.IsVisible = true;
                DetectionFrame.WidthRequest = 250;
                DetectionFrame.HeightRequest = 250;
                
                ScanStatusLabel.Text = "QR-Code erkannt! ✓";
                ScanStatusLabel.TextColor = Color.FromArgb("#00FF00");
                
                // Animate the detection frame
                _ = AnimateDetectionFrame();
                
                // Auto-zoom if zoom is still at minimum for better recognition
                if (cameraView.ZoomFactor < 1.5f)
                {
                    await AnimateZoomTo(2.0f);
                    await Task.Delay(400); // Give time for zoom to stabilize
                }
            }
            catch (Exception ex)
            {
            }
        });

        _isScanning = false; // Pause scanning

        // Wait a moment for the visual feedback
        await Task.Delay(1000);

        MainThread.BeginInvokeOnMainThread(async () =>
        {
            try
            {
                await cameraView.StopCameraAsync(); // Stop camera while processing
                
                ScanStatusLabel.Text = "Verarbeite QR-Code...";
                ScanStatusLabel.TextColor = Color.FromArgb("#FFD700");

                var imported = await _totpService.ImportFromUriAsync(result.Text);
                if (imported.Count > 0)
                {
                    await DisplayAlert("Erfolg", $"{imported.Count} Einträge hinzugefügt.", "OK");
                    await Navigation.PopModalAsync();
                }
                else
                {
                    DetectionFrame.IsVisible = false;
                    ScanStatusLabel.Text = "Ungültiger QR-Code";
                    ScanStatusLabel.TextColor = Color.FromArgb("#FF0000");
                    await DisplayAlert("Fehler", "QR-Code konnte nicht verarbeitet werden oder ist kein gültiger Authenticator-Code.\n\nErwartetes Format: otpauth://totp/...", "OK");
                    _isProcessing = false;
                    await StartCameraAsync(); // Resume if failed
                }
            }
            catch (Exception ex)
            {
                DetectionFrame.IsVisible = false;
                ScanStatusLabel.Text = "Fehler beim Scannen";
                ScanStatusLabel.TextColor = Color.FromArgb("#FF0000");
                await DisplayAlert("Fehler", $"Fehler beim Verarbeiten: {ex.Message}", "OK");
                _isProcessing = false;
                await StartCameraAsync();
            }
        });
    }
    
    private async Task AnimateDetectionFrame()
    {
        // Pulse animation for the detection frame
        try
        {
            for (int i = 0; i < 3; i++)
            {
                await DetectionFrame.ScaleTo(1.1, 150);
                await DetectionFrame.ScaleTo(1.0, 150);
            }
        }
        catch { }
    }
    
    private async Task AnimateZoomTo(float targetZoom)
    {
        try
        {
            float startZoom = cameraView.ZoomFactor;
            int steps = 10;
            float increment = (targetZoom - startZoom) / steps;
            
            for (int i = 0; i < steps; i++)
            {
                cameraView.ZoomFactor = startZoom + (increment * (i + 1));
                UpdateZoomButtonText();
                await Task.Delay(30);
            }
        }
        catch { }
    }

    private void OnFlashlightClicked(object sender, EventArgs e)
    {
        cameraView.TorchEnabled = !cameraView.TorchEnabled;
        
        // Update button appearance
        if (cameraView.TorchEnabled)
        {
            FlashlightButton.BackgroundColor = Color.FromArgb("#7B8CFF");
        }
        else
        {
            FlashlightButton.BackgroundColor = Color.FromArgb("#2A2A3A");
        }
    }
    
    private void OnZoomInClicked(object sender, EventArgs e)
    {
        try
        {
            if (cameraView.ZoomFactor < cameraView.MaxZoomFactor)
            {
                cameraView.ZoomFactor = Math.Min(cameraView.ZoomFactor + 0.5f, cameraView.MaxZoomFactor);
                UpdateZoomButtonText();
            }
        }
        catch (Exception ex)
        {
        }
    }
    
    private void OnZoomOutClicked(object sender, EventArgs e)
    {
        try
        {
            if (cameraView.ZoomFactor > cameraView.MinZoomFactor)
            {
                cameraView.ZoomFactor = Math.Max(cameraView.ZoomFactor - 0.5f, cameraView.MinZoomFactor);
                UpdateZoomButtonText();
            }
        }
        catch (Exception ex)
        {
        }
    }
    
    private void UpdateZoomButtonText()
    {
        try
        {
            float zoom = cameraView.ZoomFactor;
            ZoomLevelLabel.Text = $"{zoom:F1}x";
        }
        catch { }
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
