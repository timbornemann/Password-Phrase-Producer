using Camera.MAUI;
using Camera.MAUI.ZXingHelper;
using Microsoft.Maui.ApplicationModel;
using System.Security.Cryptography;
using System.Text;
using Password_Phrase_Producer.Models;
using Password_Phrase_Producer.Services;
using Password_Phrase_Producer.Services.Qr;
using Password_Phrase_Producer.Services.Security;
using Password_Phrase_Producer.Services.Security.Otp;

namespace Password_Phrase_Producer.Views;

public partial class AddEntryPage : ContentPage
{
    private static readonly Color AccentColor = Color.FromArgb("#4A5CFF");
    private static readonly Color InactiveTabColor = Color.FromArgb("#7F85B2");
    private static readonly Color ViewfinderColor = Color.FromArgb("#7B8CFF");
    private static readonly Color SuccessColor = Color.FromArgb("#3DDC84");
    private static readonly Color WarningColor = Color.FromArgb("#FFB347");
    private static readonly Color ErrorColor = Color.FromArgb("#FF6B6B");

    private const string DefaultStatus = "Suche nach QR-Code …";
    private const string DefaultHint = "Halte den QR-Code in den Rahmen – er wird automatisch erkannt. Auch Google-Authenticator-Exporte werden unterstützt.";

    private readonly TotpService _totpService;
    private readonly OtpScanCollector _collector = new();
    private readonly TaskCompletionSource _camerasLoaded = new(TaskCreationOptions.RunContinuationsAsynchronously);

    private bool _initialized;
    private bool _cameraRunning;
    private bool _busy;
    private bool _closing;
    private bool _discardWhenIdle;
    private int _cameraIndex = -1;
    private byte[]? _lastFeedbackDigest;
    private DateTime _lastFeedbackAt;
    private CancellationTokenSource? _statusResetCts;

    public AddEntryPage(TotpService totpService)
    {
        InitializeComponent();
        _totpService = totpService;

        cameraView.BarCodeDecoder = new CameraQrDecoder();
        cameraView.BarCodeDetectionFrameRate = 3;
        cameraView.BarCodeDetectionMaxThreads = 2;
        cameraView.BarCodeDetectionEnabled = false;
    }

    protected override async void OnAppearing()
    {
        base.OnAppearing();
        _discardWhenIdle = false;

        if (!_initialized)
        {
            _initialized = true;

            // On phones and tablets scanning is the common case, so start right away.
            if (DeviceInfo.Idiom == DeviceIdiom.Phone || DeviceInfo.Idiom == DeviceIdiom.Tablet)
            {
                await ShowTabAsync(scan: true);
            }

            return;
        }

        if (ScanView.IsVisible)
        {
            await StartScanningAsync();
        }
    }

    protected override async void OnDisappearing()
    {
        base.OnDisappearing();
        EntrySecret.Text = string.Empty;
        _lastFeedbackDigest = null;
        if (_busy) _discardWhenIdle = true;
        else _collector.Discard();
        await StopScanningAsync();
    }

    private async void OnCloseClicked(object sender, EventArgs e)
    {
        await CloseAsync();
    }

    private async void OnTabClicked(object sender, EventArgs e)
    {
        await ShowTabAsync(scan: sender == BtnScan);
    }

    private async Task ShowTabAsync(bool scan)
    {
        ManualView.IsVisible = !scan;
        ScanView.IsVisible = scan;

        BtnScan.BackgroundColor = scan ? AccentColor : Colors.Transparent;
        BtnScan.TextColor = scan ? Colors.White : InactiveTabColor;
        BtnManual.BackgroundColor = scan ? Colors.Transparent : AccentColor;
        BtnManual.TextColor = scan ? InactiveTabColor : Colors.White;

        if (scan)
        {
            await StartScanningAsync();
        }
        else
        {
            await StopScanningAsync();
        }
    }

    private async void OnSaveClicked(object sender, EventArgs e)
    {
        var secretInput = EntrySecret.Text?.Trim() ?? string.Empty;

        // Allow pasting a complete otpauth:// or Google export link into the secret field.
        if (OtpAuthUriParser.IsOtpAuthUri(secretInput) || GoogleAuthenticatorMigrationParser.IsMigrationUri(secretInput))
        {
            await HandleScannedTextsAsync(new[] { secretInput }, fromCamera: false);
            if (_collector.HasPendingBatch)
            {
                // Part of a multi-QR Google export: continue with the scanner to collect the rest.
                await ShowTabAsync(scan: true);
            }
            return;
        }

        var issuer = EntryIssuer.Text?.Trim();
        var account = EntryAccount.Text?.Trim();
        var secretStr = NormalizeBase32Secret(secretInput);

        if (string.IsNullOrEmpty(secretStr))
        {
            await DisplayAlert("Fehler", "Bitte Secret eingeben.", "OK");
            return;
        }

        byte[]? secretBytes = null;
        try
        {
            secretBytes = OtpNet.Base32Encoding.ToBytes(secretStr);
            var entry = new TotpEntry
            {
                Issuer = issuer ?? "",
                AccountName = string.IsNullOrEmpty(account) ? "Unbenannt" : account,
                Secret = secretBytes
            };

            await _totpService.AddOrUpdateEntryAsync(entry);
            await CloseAsync();
        }
        catch (System.FormatException)
        {
            await DisplayAlert("Fehler", "Ungültiges Secret Format (Base32). Erlaubt sind A–Z und 2–7. Leerzeichen/Bindestriche sind ok.", "OK");
        }
        catch
        {
            await DisplayAlert("Fehler", "Ungültiges Secret Format (Base32).", "OK");
        }
        finally
        {
            if (secretBytes is not null)
                CryptographicOperations.ZeroMemory(secretBytes);
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

    // ------------------------------------------------------------------ Camera --

    private async Task StartScanningAsync()
    {
        if (_closing)
        {
            return;
        }

        if (_cameraRunning)
        {
            cameraView.BarCodeDetectionEnabled = true;
            return;
        }

        if (!await EnsureCameraPermissionAsync())
        {
            ShowNoCamera("Kein Kamerazugriff");
            return;
        }

        var camera = await SelectCameraAsync();
        if (camera is null)
        {
            ShowNoCamera("Keine Kamera gefunden");
            return;
        }

        cameraView.Camera = camera;
        var resolution = ChooseResolution(camera);
        var started = await TryStartCameraAsync(resolution);
        if (!started && resolution != default)
        {
            // Not every listed resolution is available for the preview stream.
            started = await TryStartCameraAsync(default);
        }

        if (!started)
        {
            ShowNoCamera("Kamera konnte nicht gestartet werden");
            return;
        }

        // The page may have been left while the camera was starting.
        if (!ScanView.IsVisible || _closing)
        {
            await cameraView.StopCameraAsync();
            return;
        }

        _cameraRunning = true;
        NoCameraPanel.IsVisible = false;
        CameraControls.IsVisible = true;
        Viewfinder.IsVisible = true;
        SwitchCameraButton.IsVisible = cameraView.Cameras.Count > 1;
        UpdateTorchButton();
        UpdateZoomLabel();
        ShowDefaultStatus();

        cameraView.BarCodeDetectionEnabled = true;
    }

    private async Task<bool> TryStartCameraAsync(Size resolution)
    {
        try
        {
            return await cameraView.StartCameraAsync(resolution) == CameraResult.Success;
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"Camera start failed: {ex}");
            return false;
        }
    }

    private async Task StopScanningAsync()
    {
        cameraView.BarCodeDetectionEnabled = false;
        if (!_cameraRunning)
        {
            return;
        }

        _cameraRunning = false;
        try
        {
            if (cameraView.TorchEnabled)
            {
                cameraView.TorchEnabled = false;
            }

            await cameraView.StopCameraAsync();
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"Camera stop failed: {ex}");
        }
    }

    private async Task<CameraInfo?> SelectCameraAsync()
    {
        if (cameraView.Cameras.Count == 0)
        {
            // Cameras are enumerated asynchronously after the view was created.
            await Task.WhenAny(_camerasLoaded.Task, Task.Delay(TimeSpan.FromSeconds(3)));
        }

        var cameras = cameraView.Cameras;
        if (cameras.Count == 0)
        {
            return null;
        }

        if (_cameraIndex < 0 || _cameraIndex >= cameras.Count)
        {
            var back = cameras.FirstOrDefault(c => c.Position == CameraPosition.Back);
            _cameraIndex = back is null ? 0 : cameras.IndexOf(back);
        }

        return cameras[_cameraIndex];
    }

    private static Size ChooseResolution(CameraInfo camera)
    {
#if WINDOWS
        // Windows otherwise uses the largest format (often 4K). 1080p is sharp enough for dense
        // export codes and keeps every frame cheap to analyse.
        return camera.AvailableResolutions?
            .Where(r => Math.Max(r.Width, r.Height) <= 1920 && Math.Min(r.Width, r.Height) >= 480)
            .OrderByDescending(r => r.Width * r.Height)
            .FirstOrDefault() ?? default;
#else
        return default;
#endif
    }

    private void ShowNoCamera(string title)
    {
        _cameraRunning = false;
        NoCameraTitle.Text = title;
        NoCameraPanel.IsVisible = true;
        CameraControls.IsVisible = false;
        Viewfinder.IsVisible = false;
        SetStatus("Import über Bild oder Link", "Lade einen Screenshot des QR-Codes oder füge einen otpauth://-Link ein.", Colors.White);
    }

    private async Task<bool> EnsureCameraPermissionAsync()
    {
        try
        {
            var status = await Permissions.CheckStatusAsync<Permissions.Camera>();
            if (status != PermissionStatus.Granted)
            {
                status = await Permissions.RequestAsync<Permissions.Camera>();
            }

            return status == PermissionStatus.Granted;
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"Camera permission failed: {ex}");
            return false;
        }
    }

    private void OnCamerasLoaded(object sender, EventArgs e)
    {
        _camerasLoaded.TrySetResult();
    }

    private void OnBarcodeDetected(object sender, BarcodeEventArgs args)
    {
        // Called on a camera worker thread.
        var texts = args.Result?
            .Select(r => r.Text)
            .Where(t => !string.IsNullOrWhiteSpace(t))
            .ToList();

        if (texts is null || texts.Count == 0)
        {
            return;
        }

        MainThread.BeginInvokeOnMainThread(async () =>
        {
            if (_cameraRunning && cameraView.BarCodeDetectionEnabled)
            {
                await HandleScannedTextsAsync(texts, fromCamera: true);
            }
        });
    }

    private void OnCameraTapped(object sender, TappedEventArgs e)
    {
        if (!_cameraRunning)
        {
            return;
        }

        try
        {
            cameraView.ForceAutoFocus();
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"Autofocus failed: {ex.Message}");
        }
    }

    private void OnFlashlightClicked(object sender, EventArgs e)
    {
        try
        {
            cameraView.TorchEnabled = !cameraView.TorchEnabled;
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"Torch failed: {ex.Message}");
        }

        UpdateTorchButton();
    }

    private void UpdateTorchButton()
    {
        FlashlightButton.BackgroundColor = cameraView.TorchEnabled ? Color.FromArgb("#7B8CFF") : Color.FromArgb("#CC1F2338");
    }

    private async void OnSwitchCameraClicked(object sender, EventArgs e)
    {
        if (cameraView.Cameras.Count < 2 || _busy)
        {
            return;
        }

        await StopScanningAsync();
        _cameraIndex = (_cameraIndex + 1) % cameraView.Cameras.Count;
        await StartScanningAsync();
    }

    private void OnZoomInClicked(object sender, EventArgs e) => ChangeZoom(0.5f);

    private void OnZoomOutClicked(object sender, EventArgs e) => ChangeZoom(-0.5f);

    private void ChangeZoom(float delta)
    {
        try
        {
            var zoom = Math.Clamp(cameraView.ZoomFactor + delta, cameraView.MinZoomFactor, cameraView.MaxZoomFactor);
            cameraView.ZoomFactor = zoom;
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"Zoom failed: {ex.Message}");
        }

        UpdateZoomLabel();
    }

    private void UpdateZoomLabel()
    {
        try
        {
            ZoomLevelLabel.Text = $"{cameraView.ZoomFactor:F1}x";
        }
        catch
        {
            ZoomLevelLabel.Text = "1.0x";
        }
    }

    // ------------------------------------------------- Image / clipboard import --

    private async void OnPickImageClicked(object sender, EventArgs e)
    {
        if (_busy)
        {
            return;
        }

        FileResult? file;
        try
        {
            file = await FilePicker.Default.PickAsync(new PickOptions
            {
                PickerTitle = "Bild mit QR-Code auswählen",
                FileTypes = FilePickerFileType.Images
            });
        }
        catch (Exception ex)
        {
            await DisplayAlert("Fehler", $"Bild konnte nicht geöffnet werden: {ex.Message}", "OK");
            return;
        }

        if (file is null)
        {
            return;
        }

        _busy = true;
        SetStatus("Analysiere Bild …", "Einen Moment bitte.", Colors.White);

        IReadOnlyList<string>? texts;
        try
        {
            texts = await Task.Run(async () =>
            {
                await using var stream = await file.OpenReadAsync();
                var image = QrImageLoader.Load(stream);
                return image is null ? null : new QrCodeDecoder().DecodeImage(image.Value);
            });
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"Image decode failed: {ex}");
            texts = null;
        }
        finally
        {
            _busy = false;
            if (_discardWhenIdle)
            {
                _collector.Discard();
                _discardWhenIdle = false;
            }
        }

        if (texts is null)
        {
            ShowDefaultStatus();
            await DisplayAlert("Fehler", "Das Bild konnte nicht gelesen werden.", "OK");
            return;
        }

        if (texts.Count == 0)
        {
            ShowDefaultStatus();
            await DisplayAlert("Kein QR-Code gefunden", "Im Bild wurde kein QR-Code erkannt. Achte darauf, dass der Code vollständig und scharf zu sehen ist.", "OK");
            return;
        }

        await HandleScannedTextsAsync(texts, fromCamera: false);
    }

    private async void OnPasteClicked(object sender, EventArgs e)
    {
        if (_busy)
        {
            return;
        }

        string? text = null;
        try
        {
            if (Clipboard.Default.HasText)
            {
                text = await Clipboard.Default.GetTextAsync();
            }
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"Clipboard read failed: {ex.Message}");
        }

        if (string.IsNullOrWhiteSpace(text))
        {
            await DisplayAlert("Zwischenablage leer", "Kopiere zuerst einen otpauth://- oder otpauth-migration://-Link.", "OK");
            return;
        }

        // The clipboard may contain several links, e.g. one per line.
        var links = text
            .Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries)
            .Where(t => OtpAuthUriParser.IsOtpAuthUri(t) || GoogleAuthenticatorMigrationParser.IsMigrationUri(t))
            .ToList();

        var imported = await HandleScannedTextsAsync(links.Count > 0 ? links : new List<string> { text.Trim() }, fromCamera: false);
        if (imported)
        {
            // The clipboard contains secrets in plain text, do not leave them behind.
            try
            {
                await Clipboard.Default.SetTextAsync(null);
            }
            catch
            {
                // Clearing the clipboard is best effort.
            }
        }
    }

    // ------------------------------------------------------ Scan processing --

    /// <summary>
    /// Processes decoded QR contents. Returns <c>true</c> when accounts were imported.
    /// </summary>
    private async Task<bool> HandleScannedTextsAsync(IReadOnlyList<string> texts, bool fromCamera)
    {
        if (_busy || _closing)
        {
            return false;
        }

        _busy = true;
        try
        {
            var completeAccounts = new List<OtpAccount>();
            OtpScanResult? feedback = null;
            string? feedbackText = null;

            foreach (var text in texts)
            {
                var result = _collector.Add(text);
                if (result.Status == OtpScanStatus.Complete)
                {
                    completeAccounts.AddRange(result.Accounts);
                }
                else if (feedback is null || Priority(result.Status) > Priority(feedback.Status))
                {
                    feedback = result;
                    feedbackText = text;
                }
            }

            if (completeAccounts.Count > 0)
            {
                return await ImportAsync(completeAccounts);
            }

            if (feedback is not null)
            {
                await ShowScanFeedbackAsync(feedback, feedbackText!, fromCamera);
            }

            return false;
        }
        finally
        {
            _busy = false;
            if (_discardWhenIdle)
            {
                _collector.Discard();
                _discardWhenIdle = false;
            }
        }
    }

    private static int Priority(OtpScanStatus status) => status switch
    {
        OtpScanStatus.BatchPartial => 4,
        OtpScanStatus.AlreadyScanned => 3,
        OtpScanStatus.Invalid => 2,
        _ => 1
    };

    private async Task ShowScanFeedbackAsync(OtpScanResult result, string text, bool fromCamera)
    {
        var digest = GetFeedbackDigest(text);
        if (result.Status == OtpScanStatus.BatchPartial)
        {
            PerformHaptic();
            _ = FlashViewfinderAsync(SuccessColor);
            UpdateBatchPanel();
            SetStatus(
                $"Teil {_collector.ScannedParts} von {_collector.BatchSize} erkannt",
                "Blättere im Google Authenticator zum nächsten QR-Code – er wird automatisch hinzugefügt.",
                SuccessColor);
            _lastFeedbackDigest = digest;
            _lastFeedbackAt = DateTime.UtcNow;
            return;
        }

        // The camera reports the same code many times per second; do not flicker.
        if (fromCamera && _lastFeedbackDigest is { } previous &&
            CryptographicOperations.FixedTimeEquals(digest, previous) &&
            DateTime.UtcNow - _lastFeedbackAt < TimeSpan.FromSeconds(3))
        {
            return;
        }

        _lastFeedbackDigest = digest;
        _lastFeedbackAt = DateTime.UtcNow;

        var (title, hint, color) = result.Status switch
        {
            OtpScanStatus.AlreadyScanned => (
                "Dieser Teil wurde bereits gescannt",
                $"Noch fehlend: {string.Join(", ", _collector.MissingParts.Select(i => i + 1))}. Zeige den nächsten QR-Code des Exports.",
                WarningColor),
            OtpScanStatus.Invalid => (
                "2FA-Code ungültig",
                "Der QR-Code enthält einen beschädigten oder unvollständigen otpauth-Link.",
                ErrorColor),
            _ => (
                "Kein 2FA-QR-Code",
                "Dieser QR-Code enthält keinen otpauth://- oder Google-Authenticator-Export-Link.",
                WarningColor)
        };

        if (!fromCamera && result.Status != OtpScanStatus.AlreadyScanned)
        {
            ShowDefaultStatus();
            await DisplayAlert(title, hint, "OK");
            return;
        }

        SetStatus(title, hint, color, resetAfter: TimeSpan.FromSeconds(3));
    }

    private static byte[] GetFeedbackDigest(string text)
    {
        var bytes = Encoding.UTF8.GetBytes(text);
        try { return SHA256.HashData(bytes); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    private void UpdateBatchPanel()
    {
        if (!_collector.HasPendingBatch)
        {
            BatchPanel.IsVisible = false;
            return;
        }

        var accounts = _collector.PendingAccounts.Count;
        BatchPanel.IsVisible = true;
        BatchProgress.Progress = _collector.BatchSize == 0 ? 0 : (double)_collector.ScannedParts / _collector.BatchSize;
        BatchLabel.Text = $"Google-Export: {_collector.ScannedParts}/{_collector.BatchSize} QR-Codes · {accounts} {(accounts == 1 ? "Konto" : "Konten")} gesammelt";
    }

    private async void OnImportPartialClicked(object sender, EventArgs e)
    {
        if (_busy || !_collector.HasPendingBatch)
        {
            return;
        }

        var missing = _collector.BatchSize - _collector.ScannedParts;
        var confirm = await DisplayAlert(
            "Unvollständiger Export",
            $"Es fehlen noch {missing} von {_collector.BatchSize} QR-Codes. Trotzdem die bisher gescannten Konten importieren?",
            "Importieren",
            "Weiter scannen");

        if (!confirm || _busy)
        {
            return;
        }

        _busy = true;
        try
        {
            await ImportAsync(_collector.PendingAccounts);
        }
        finally
        {
            _busy = false;
            if (_discardWhenIdle)
            {
                _collector.Discard();
                _discardWhenIdle = false;
            }
        }
    }

    private async Task<bool> ImportAsync(IReadOnlyList<OtpAccount> accounts)
    {
        cameraView.BarCodeDetectionEnabled = false;
        PerformHaptic();
        _ = FlashViewfinderAsync(SuccessColor);
        SetStatus("QR-Code erkannt ✓", accounts.Count == 1 ? "Konto wird hinzugefügt …" : $"{accounts.Count} Konten werden hinzugefügt …", SuccessColor);

        TotpImportResult result;
        try
        {
            result = await _totpService.ImportAccountsAsync(accounts);
        }
        catch (Exception ex)
        {
            await DisplayAlert("Fehler", $"Import fehlgeschlagen: {ex.Message}", "OK");
            ResumeAfterImport();
            return false;
        }

        _collector.Discard();
        foreach (var account in accounts)
            CryptographicOperations.ZeroMemory(account.Secret);

        if (result.Added.Count > 0)
        {
            await CloseAsync();
            await ToastService.ShowAsync(BuildImportSummary(result), result.Added.Count == 1 && result.Duplicates == 0 && result.Unsupported == 0 ? 2000 : 4000);
            return true;
        }

        var message = result.Unsupported > 0 && result.Duplicates == 0
            ? "Die gescannten Konten verwenden ein Verfahren, das noch nicht unterstützt wird (HOTP/zählerbasiert oder MD5)."
            : BuildImportSummary(result);
        await DisplayAlert("Nichts hinzugefügt", message, "OK");
        ResumeAfterImport();
        return false;
    }

    private static string BuildImportSummary(TotpImportResult result)
    {
        var parts = new List<string>();
        if (result.Added.Count == 1)
        {
            var entry = result.Added[0];
            var name = string.IsNullOrWhiteSpace(entry.Issuer) ? entry.AccountName : entry.Issuer;
            parts.Add($"„{name}“ hinzugefügt");
        }
        else if (result.Added.Count > 1)
        {
            parts.Add($"{result.Added.Count} Konten hinzugefügt");
        }

        if (result.Duplicates > 0)
        {
            parts.Add(result.Duplicates == 1 ? "1 Konto war bereits vorhanden" : $"{result.Duplicates} Konten waren bereits vorhanden");
        }

        if (result.Unsupported > 0)
        {
            parts.Add(result.Unsupported == 1 ? "1 Konto wird nicht unterstützt (HOTP)" : $"{result.Unsupported} Konten werden nicht unterstützt (HOTP)");
        }

        return string.Join(" · ", parts);
    }

    private void ResumeAfterImport()
    {
        UpdateBatchPanel();
        if (_cameraRunning)
        {
            ShowDefaultStatus();
            cameraView.BarCodeDetectionEnabled = true;
        }
        else if (NoCameraPanel.IsVisible)
        {
            SetStatus("Import über Bild oder Link", "Lade einen Screenshot des QR-Codes oder füge einen otpauth://-Link ein.", Colors.White);
        }
        else
        {
            ShowDefaultStatus();
        }
    }

    // --------------------------------------------------------------- UI helpers --

    private void ShowDefaultStatus()
    {
        if (_collector.HasPendingBatch)
        {
            SetStatus(
                $"Teil {_collector.ScannedParts} von {_collector.BatchSize} erkannt",
                "Blättere im Google Authenticator zum nächsten QR-Code – er wird automatisch hinzugefügt.",
                SuccessColor);
            return;
        }

        SetStatus(DefaultStatus, DefaultHint, Colors.White);
    }

    private void SetStatus(string title, string hint, Color color, TimeSpan? resetAfter = null)
    {
        _statusResetCts?.Cancel();
        _statusResetCts = null;

        ScanStatusLabel.Text = title;
        ScanStatusLabel.TextColor = color;
        ScanHintLabel.Text = hint;

        if (resetAfter is null)
        {
            return;
        }

        var cts = new CancellationTokenSource();
        _statusResetCts = cts;
        MainThread.BeginInvokeOnMainThread(async () =>
        {
            try
            {
                await Task.Delay(resetAfter.Value, cts.Token);
                if (_cameraRunning)
                {
                    ShowDefaultStatus();
                }
            }
            catch (TaskCanceledException)
            {
                // A newer status replaced this one.
            }
        });
    }

    private async Task FlashViewfinderAsync(Color color)
    {
        try
        {
            SetViewfinderColor(color);
            await Viewfinder.ScaleTo(1.06, 120, Easing.CubicOut);
            await Viewfinder.ScaleTo(1.0, 160, Easing.CubicIn);
            await Task.Delay(500);
        }
        catch
        {
            // Animations are cosmetic.
        }
        finally
        {
            SetViewfinderColor(ViewfinderColor);
        }
    }

    private void SetViewfinderColor(Color color)
    {
        foreach (var child in Viewfinder.Children.OfType<BoxView>())
        {
            child.Color = color;
        }
    }

    private static void PerformHaptic()
    {
        try
        {
            if (HapticFeedback.Default.IsSupported)
            {
                HapticFeedback.Default.Perform(HapticFeedbackType.Click);
            }
        }
        catch
        {
            // Not every device supports haptic feedback.
        }
    }

    private async Task CloseAsync()
    {
        if (_closing)
        {
            return;
        }

        _closing = true;
        _statusResetCts?.Cancel();
        await StopScanningAsync();
        await Navigation.PopModalAsync();
    }
}
