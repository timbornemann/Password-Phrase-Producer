using Camera.MAUI;
using Camera.MAUI.ZXingHelper;
using Microsoft.Maui.ApplicationModel;
using Microsoft.Maui.Controls;
using Microsoft.Maui.Graphics;
using Password_Phrase_Producer.Services.LocalTransfer;
using Password_Phrase_Producer.Services.Qr;
using Password_Phrase_Producer.Views.Controls;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using ZXing;
using ZXing.Common;
using ZXing.QrCode;

namespace Password_Phrase_Producer.Views;

internal sealed record LocalReceivedBackup(byte[] Bytes, string Phrase);

internal sealed class LocalSendPage : ContentPage
{
    private readonly IPAddress _address;
    private string _phrase;
    private readonly byte[] _backup;
    private readonly LocalTransferActivity _activity;
    private readonly Label _endpoint = new() { FontSize = 18, TextColor = Colors.White };
    private readonly Label _code = new() { FontSize = 18, TextColor = Colors.White };
    private readonly Label _countdown = new() { FontSize = 13, TextColor = Color.FromArgb("#9EAAB5") };
    private readonly Label _status = new() { FontSize = 13, TextColor = Color.FromArgb("#9EAAB5") };
    private readonly GraphicsView _qr = new() { HeightRequest = 250, WidthRequest = 250,
        BackgroundColor = Colors.White, HorizontalOptions = LayoutOptions.Center };
    private LocalTransferProtocol.LocalSendSession? _session;
    private CancellationTokenSource? _activityToken;
    private bool _closing;

    internal LocalSendPage(IPAddress address, string phrase, byte[] backup, LocalTransferActivity activity)
    {
        _address = address;
        _phrase = phrase;
        _backup = backup;
        _activity = activity;
        Title = "Lokaler Transfer";
        BackgroundColor = Color.FromArgb("#0D1013");
        var close = new Button { Text = "Schließen", BackgroundColor = Color.FromArgb("#20272E"),
            TextColor = Colors.White, CornerRadius = 4 };
        close.Clicked += async (_, _) => await CloseAsync();
        Content = new ScrollView { Content = new VerticalStackLayout
        {
            Padding = new Thickness(24, 30), Spacing = 18,
            Children =
            {
                new Label { Text = "Senden", FontSize = 28, FontAttributes = FontAttributes.Bold,
                    TextColor = Colors.White },
                _qr,
                new Label { Text = "QR-Code und Wörter nur dem Empfänger zeigen.", FontSize = 12,
                    TextColor = Color.FromArgb("#8797A4"), HorizontalTextAlignment = TextAlignment.Center },
                new Label { Text = "Adresse", FontSize = 12, TextColor = Color.FromArgb("#8797A4") },
                _endpoint,
                new Label { Text = "Sitzungswörter", FontSize = 12, TextColor = Color.FromArgb("#8797A4") },
                _code,
                _countdown,
                _status,
                close
            }
        }};
    }

    protected override void OnAppearing()
    {
        base.OnAppearing();
        if (_activityToken is not null) return;
        _activityToken = _activity.Begin();
        try
        {
            _session = LocalTransferProtocol.StartSend(_address, _phrase, _backup,
                () => MainThread.InvokeOnMainThreadAsync(() => DisplayAlert("Transfer freigeben",
                    "Ein Gerät mit dem Sitzungscode möchte die Tresore empfangen.", "Senden", "Ablehnen")),
                _activityToken.Token);
            _endpoint.Text = $"{_session.Ticket.Address}:{_session.Ticket.Port}";
            _code.Text = _phrase;
            var matrix = new QRCodeWriter().encode(_session.Ticket.ToQrText(), ZXing.BarcodeFormat.QR_CODE, 0, 0);
            _qr.Drawable = new TransferQrDrawable(matrix);
            _qr.Invalidate();
            _status.Text = "Warte auf ein Gerät im gleichen Netzwerk …";
            Dispatcher.StartTimer(TimeSpan.FromSeconds(1), () =>
            {
                if (_closing || _session is null) return false;
                var remaining = _session.ExpiresAt - DateTimeOffset.UtcNow;
                _countdown.Text = remaining > TimeSpan.Zero
                    ? $"Verbleibend: {remaining.Minutes:00}:{remaining.Seconds:00}"
                    : "Sitzung abgelaufen";
                return remaining > TimeSpan.Zero;
            });
            _ = WatchSessionAsync(_session);
        }
        catch (Exception ex)
        {
            _session?.Cancel();
            if (_session is not null) _ = DisposeSessionAsync(_session);
            CryptographicOperations.ZeroMemory(_backup);
            ClearAccessCode();
            _status.Text = ex is SocketException ? "Lokaler Port konnte nicht geöffnet werden. Firewall prüfen." : ex.Message;
            _activity.End(_activityToken);
            _activityToken = null;
        }
    }

    private async Task WatchSessionAsync(LocalTransferProtocol.LocalSendSession session)
    {
        try
        {
            await session.Completion;
            await MainThread.InvokeOnMainThreadAsync(() =>
            {
                ClearAccessCode();
                _status.Text = "Verschlüsselte Sicherung übertragen.";
            });
        }
        catch (Exception ex)
        {
            if (!_closing)
                await MainThread.InvokeOnMainThreadAsync(() =>
                {
                    ClearAccessCode();
                    _status.Text = ex.Message;
                });
        }
        finally
        {
            await session.DisposeAsync();
            if (ReferenceEquals(_session, session)) _session = null;
        }
    }

    protected override void OnDisappearing()
    {
        base.OnDisappearing();
        _closing = true;
        _session?.Cancel();
        _activityToken?.Cancel();
        ClearAccessCode();
        if (_activityToken is not null) { _activity.End(_activityToken); _activityToken = null; }
    }

    private async Task CloseAsync()
    {
        if (_closing) return;
        _closing = true;
        _session?.Cancel();
        await Navigation.PopModalAsync();
    }

    private static async Task DisposeSessionAsync(LocalTransferProtocol.LocalSendSession session)
    {
        await session.DisposeAsync();
    }

    private void ClearAccessCode()
    {
        _qr.Drawable = null;
        _qr.Invalidate();
        _code.Text = string.Empty;
        _endpoint.Text = string.Empty;
        _phrase = string.Empty;
    }

    private sealed class TransferQrDrawable(BitMatrix matrix) : IDrawable
    {
        public void Draw(ICanvas canvas, RectF dirtyRect)
        {
            canvas.FillColor = Colors.White;
            canvas.FillRectangle(dirtyRect);
            var modules = Math.Max(matrix.Width, matrix.Height) + 8;
            var size = MathF.Min(dirtyRect.Width, dirtyRect.Height) / modules;
            var left = (dirtyRect.Width - size * modules) / 2 + 4 * size;
            var top = (dirtyRect.Height - size * modules) / 2 + 4 * size;
            canvas.FillColor = Colors.Black;
            for (var y = 0; y < matrix.Height; y++)
                for (var x = 0; x < matrix.Width; x++)
                    if (matrix[x, y]) canvas.FillRectangle(left + x * size, top + y * size, size + .15f, size + .15f);
        }
    }
}

internal sealed class LocalReceivePage : ContentPage
{
    private readonly LocalTransferActivity _activity;
    private readonly TaskCompletionSource<LocalReceivedBackup?> _result = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly Entry _address = Field("192.168.1.10");
    private readonly Entry _port = Field("Port");
    private readonly Entry _phrase = Field("Sechs Wörter");
    private readonly Label _status = new() { FontSize = 13, TextColor = Color.FromArgb("#9EAAB5") };
    private readonly Button _connect = new() { Text = "Empfangen", BackgroundColor = Color.FromArgb("#536D81"),
        TextColor = Colors.White, CornerRadius = 4 };
    private readonly CameraView _camera = new() { HeightRequest = 270, IsVisible = false };
    private CancellationTokenSource? _activityToken;
    private bool _busy;
    private bool _closing;
    private bool _scanHandled;
    private Guid? _sessionId;

    internal LocalReceivePage(LocalTransferActivity activity)
    {
        _activity = activity;
        Title = "Lokaler Transfer";
        BackgroundColor = Color.FromArgb("#0D1013");
        _port.Keyboard = Keyboard.Numeric;
        _phrase.AutomationId = "LocalTransferWords";
        _phrase.Completed += async (_, _) => await ConnectAsync();
        _camera.BarCodeDecoder = new CameraQrDecoder();
        _camera.BarCodeDetectionFrameRate = 3;
        _camera.BarCodeDetectionMaxThreads = 2;
        _camera.BarcodeDetected += OnBarcodeDetected;
        var scan = new Button { Text = "QR-Code scannen", BackgroundColor = Color.FromArgb("#20272E"),
            TextColor = Colors.White, CornerRadius = 4 };
        scan.Clicked += async (_, _) => await StartCameraAsync();
        _connect.Clicked += async (_, _) => await ConnectAsync();
        var cancel = new Button { Text = "Abbrechen", BackgroundColor = Colors.Transparent,
            TextColor = Color.FromArgb("#9EAAB5") };
        cancel.Clicked += async (_, _) => await CloseAsync();
        Content = new ScrollView { Content = new VerticalStackLayout
        {
            Padding = new Thickness(24, 30), Spacing = 14,
            Children =
            {
                new Label { Text = "Empfangen", FontSize = 28, FontAttributes = FontAttributes.Bold,
                    TextColor = Colors.White },
                scan, _camera,
                new Label { Text = "IP-Adresse", TextColor = Color.FromArgb("#9EAAB5") }, _address,
                new Label { Text = "Port", TextColor = Color.FromArgb("#9EAAB5") }, _port,
                new Label { Text = "Sitzungswörter", TextColor = Color.FromArgb("#9EAAB5") }, _phrase,
                _connect, _status, cancel
            }
        }};
    }

    internal Task<LocalReceivedBackup?> WaitForResultAsync() => _result.Task;

    protected override void OnAppearing()
    {
        base.OnAppearing();
        _activityToken ??= _activity.Begin();
    }

    protected override async void OnDisappearing()
    {
        base.OnDisappearing();
        _closing = true;
        _activityToken?.Cancel();
        await StopCameraAsync();
        _phrase.Text = string.Empty;
        _result.TrySetResult(null);
        if (_activityToken is not null) { _activity.End(_activityToken); _activityToken = null; }
    }

    private static Entry Field(string placeholder) => new FramedEntry
    {
        Placeholder = placeholder,
        BackgroundColor = Color.FromArgb("#20272E"),
        TextColor = Colors.White,
        PlaceholderColor = Color.FromArgb("#8797A4"),
        HeightRequest = 44
    };

    private async Task StartCameraAsync()
    {
        if (_busy || _closing) return;
        _scanHandled = false;
        try
        {
            var permission = await Permissions.RequestAsync<Permissions.Camera>();
            if (permission != PermissionStatus.Granted)
                throw new InvalidOperationException("Kamerazugriff fehlt. IP und Wörter können manuell eingegeben werden.");
            _camera.IsVisible = true;
            if (_camera.Cameras.Count == 0)
            {
                var ready = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                void Loaded(object? sender, EventArgs args) => ready.TrySetResult();
                _camera.CamerasLoaded += Loaded;
                try { await Task.WhenAny(ready.Task, Task.Delay(5000)); }
                finally { _camera.CamerasLoaded -= Loaded; }
            }
            var camera = _camera.Cameras.FirstOrDefault();
            if (camera is null) throw new InvalidOperationException("Keine Kamera gefunden.");
            _camera.Camera = camera;
            if (await _camera.StartCameraAsync(default) != CameraResult.Success)
                throw new InvalidOperationException("Kamera konnte nicht gestartet werden.");
            _camera.BarCodeDetectionEnabled = true;
            _status.Text = "QR-Code scannen …";
        }
        catch (Exception ex) { _status.Text = ex.Message; }
    }

    private void OnBarcodeDetected(object? sender, BarcodeEventArgs args)
    {
        var text = args.Result?.Select(result => result.Text)
            .FirstOrDefault(value => value?.StartsWith("ppp-transfer:v1:", StringComparison.Ordinal) == true);
        if (text is null) return;
        MainThread.BeginInvokeOnMainThread(async () =>
        {
            if (_busy || _closing || _scanHandled) return;
            _scanHandled = true;
            try
            {
                var ticket = LocalTransferTicket.ParseQrText(text);
                _address.Text = ticket.Address.ToString();
                _port.Text = ticket.Port.ToString();
                _phrase.Text = ticket.Phrase;
                _sessionId = ticket.SessionId;
                await StopCameraAsync();
                await ConnectAsync();
            }
            catch (Exception ex) { _status.Text = ex.Message; _scanHandled = false; }
        });
    }

    private async Task StopCameraAsync()
    {
        _camera.BarCodeDetectionEnabled = false;
        try { await _camera.StopCameraAsync(); }
        catch { /* Camera may already be stopped during page teardown. */ }
        _camera.IsVisible = false;
    }

    private async Task ConnectAsync()
    {
        if (_busy || _closing || _activityToken is null) return;
        _busy = true;
        _connect.IsEnabled = false;
        try
        {
            var ticket = LocalTransferTicket.ParseManual(_address.Text, _port.Text, _phrase.Text, _sessionId);
            _status.Text = "Verbinde verschlüsselt …";
            var bytes = await LocalTransferProtocol.ReceiveAsync(ticket, _activityToken.Token);
            if (_closing || _activityToken.IsCancellationRequested)
            {
                CryptographicOperations.ZeroMemory(bytes);
                return;
            }
            _result.TrySetResult(new LocalReceivedBackup(bytes, ticket.Phrase));
            await Navigation.PopModalAsync();
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !_closing)
        {
            _status.Text = ex is SocketException ? "Verbindung fehlgeschlagen. IP, Port und Firewall prüfen." :
                ex is InvalidDataException ? ex.Message :
                ex is IOException ? "Die Übertragung wurde unterbrochen." :
                ex is OperationCanceledException ? "Verbindung abgebrochen oder abgelaufen." : ex.Message;
        }
        finally { _busy = false; _connect.IsEnabled = true; }
    }

    private async Task CloseAsync()
    {
        if (_closing) return;
        _closing = true;
        _activityToken?.Cancel();
        _result.TrySetResult(null);
        await Navigation.PopModalAsync();
    }
}
