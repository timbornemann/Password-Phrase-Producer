using Camera.MAUI;
using Camera.MAUI.ZXingHelper;
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
        
        System.Diagnostics.Debug.WriteLine("=== AddEntryPage Constructor ===");
        System.Diagnostics.Debug.WriteLine($"BarCodeOptions.PossibleFormats count: {BarCodeOptions.PossibleFormats.Count}");
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
        try
        {
            System.Diagnostics.Debug.WriteLine("=== StartCameraAsync called ===");
            System.Diagnostics.Debug.WriteLine($"Available cameras: {cameraView.Cameras.Count}");
            
            if (cameraView.Cameras.Count > 0)
            {
                cameraView.Camera = cameraView.Cameras.First();
                System.Diagnostics.Debug.WriteLine($"Selected camera: {cameraView.Camera.Name}");
                
                // Set zoom
                cameraView.ZoomFactor = 1.0f;
                
                await cameraView.StartCameraAsync();
                System.Diagnostics.Debug.WriteLine("Camera started successfully");
                
                _isScanning = true;
                _isProcessing = false;
                
                // Start auto-scan timer (Windows workaround)
                StartAutoScanTimer();
                
                MainThread.BeginInvokeOnMainThread(() =>
                {
                    ScanStatusLabel.Text = "Bereit zum Scannen - Klicke '📸 QR-Code erfassen'";
                    ScanStatusLabel.TextColor = Color.FromArgb("#7B8CFF");
                    DetectionFrame.IsVisible = false;
                    UpdateZoomButtonText();
                });
            }
            else
            {
                System.Diagnostics.Debug.WriteLine("ERROR: No cameras found!");
                await DisplayAlert("Fehler", "Keine Kamera gefunden.", "OK");
            }
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"ERROR in StartCameraAsync: {ex.Message}");
            await DisplayAlert("Fehler", $"Kamera konnte nicht gestartet werden: {ex.Message}", "OK");
        }
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
        
        System.Diagnostics.Debug.WriteLine("Auto-scan timer started (Windows workaround)");
    }
    
    private void StopAutoScanTimer()
    {
        _autoScanTimer?.Dispose();
        _autoScanTimer = null;
        System.Diagnostics.Debug.WriteLine("Auto-scan timer stopped");
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
            if (!autoMode)
            {
                System.Diagnostics.Debug.WriteLine("=== Manual Capture Button Clicked ===");
            }
            
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
                System.Diagnostics.Debug.WriteLine($"Snapshot captured: {imageStream.Length} bytes");
                
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
                        System.Diagnostics.Debug.WriteLine($"QR Code detected: {result.Text}");
                        await ProcessQRCode(result.Text, autoMode);
                    }
                    else
                    {
                        System.Diagnostics.Debug.WriteLine("No QR code found in snapshot");
                        if (!autoMode)
                        {
                            MainThread.BeginInvokeOnMainThread(async () =>
                            {
                                ScanStatusLabel.Text = "Kein QR-Code gefunden";
                                ScanStatusLabel.TextColor = Color.FromArgb("#FF6B00");
                                CaptureButton.IsEnabled = true;
                                await Task.Delay(2000);
                                ScanStatusLabel.Text = "Bereit zum Scannen";
                                ScanStatusLabel.TextColor = Color.FromArgb("#7B8CFF");
                            });
                        }
                    }
                }
                else
                {
                    System.Diagnostics.Debug.WriteLine("Failed to decode bitmap");
                }
            }
            else
            {
                System.Diagnostics.Debug.WriteLine("Failed to capture snapshot");
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
            System.Diagnostics.Debug.WriteLine($"Error in TryCaptureAndScan: {ex.Message}");
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
        System.Diagnostics.Debug.WriteLine("=== OnCamerasLoaded called ===");
        System.Diagnostics.Debug.WriteLine($"Cameras available: {cameraView.Cameras.Count}");
    }

    private async void OnBarcodeDetected(object sender, Camera.MAUI.ZXingHelper.BarcodeEventArgs args)
    {
        System.Diagnostics.Debug.WriteLine($"=== OnBarcodeDetected called === Time: {DateTime.Now:HH:mm:ss.fff}");
        System.Diagnostics.Debug.WriteLine($"_isScanning: {_isScanning}, _isProcessing: {_isProcessing}");
        System.Diagnostics.Debug.WriteLine($"args.Result count: {args.Result?.Length ?? 0}");
        
        if (!_isScanning || _isProcessing)
        {
            System.Diagnostics.Debug.WriteLine("Skipping - not scanning or already processing");
            return;
        }

        // Debug info - show that we're receiving barcode events
        MainThread.BeginInvokeOnMainThread(() =>
        {
            DebugLabel.IsVisible = true;
            DebugLabel.Text = $"Event! Frames: {args.Result?.Length ?? 0} | {DateTime.Now:HH:mm:ss}";
        });

        var result = args.Result?.FirstOrDefault();
        if (result == null || string.IsNullOrEmpty(result.Text)) 
        {
            System.Diagnostics.Debug.WriteLine("No valid result found");
            return;
        }

        System.Diagnostics.Debug.WriteLine($"SUCCESS! QR Code detected!");
        System.Diagnostics.Debug.WriteLine($"Text: {result.Text}");
        System.Diagnostics.Debug.WriteLine($"Format: {result.BarcodeFormat}");

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
                
                DebugLabel.Text = $"QR erkannt: {result.BarcodeFormat}";
                
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
                System.Diagnostics.Debug.WriteLine($"Error showing detection frame: {ex.Message}");
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
                DebugLabel.Text = "Verarbeite URI...";

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
                    DebugLabel.Text = "Import fehlgeschlagen";
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
                DebugLabel.Text = $"Error: {ex.Message}";
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
            System.Diagnostics.Debug.WriteLine($"Zoom In Error: {ex.Message}");
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
            System.Diagnostics.Debug.WriteLine($"Zoom Out Error: {ex.Message}");
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
    
    private void OnTestClicked(object sender, EventArgs e)
    {
        System.Diagnostics.Debug.WriteLine("=== TEST BUTTON CLICKED ===");
        System.Diagnostics.Debug.WriteLine($"Camera: {cameraView.Camera?.Name ?? "NULL"}");
        System.Diagnostics.Debug.WriteLine($"BarCodeDetectionEnabled: {cameraView.BarCodeDetectionEnabled}");
        System.Diagnostics.Debug.WriteLine($"IsScanning: {_isScanning}");
        System.Diagnostics.Debug.WriteLine($"IsProcessing: {_isProcessing}");
        System.Diagnostics.Debug.WriteLine($"BarCodeOptions: {BarCodeOptions != null}");
        if (BarCodeOptions != null)
        {
            System.Diagnostics.Debug.WriteLine($"  - TryHarder: {BarCodeOptions.TryHarder}");
            System.Diagnostics.Debug.WriteLine($"  - AutoRotate: {BarCodeOptions.AutoRotate}");
            System.Diagnostics.Debug.WriteLine($"  - TryInverted: {BarCodeOptions.TryInverted}");
            System.Diagnostics.Debug.WriteLine($"  - ReadMultipleCodes: {BarCodeOptions.ReadMultipleCodes}");
            System.Diagnostics.Debug.WriteLine($"  - PossibleFormats: {BarCodeOptions.PossibleFormats?.Count ?? 0}");
        }
        
        MainThread.BeginInvokeOnMainThread(() =>
        {
            DebugLabel.Text = $"Test: Cam={cameraView.Camera != null}, BarcodeEnabled={cameraView.BarCodeDetectionEnabled}, Scanning={_isScanning}";
        });
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
