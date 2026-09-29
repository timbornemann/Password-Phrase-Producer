using Password_Phrase_Producer.Services.Security;

namespace Password_Phrase_Producer.Views.Security;

public sealed class RecoveryChallengePage : ContentPage
{
    private readonly IRecoveryQuestionsService _questions;
    private readonly IUnlockAttemptGate _gate;
    private readonly ProtectedAccess _access;
    private readonly Entry _firstName = new() { Placeholder = "Vorname" };
    private readonly Entry _lastName = new() { Placeholder = "Nachname" };
    private readonly DatePicker _birthDate = new() { MaximumDate = DateTime.Today };
    private bool _birthDateSelected;
    private readonly Picker[] _answerPickers = [new(), new(), new()];
    private readonly VerticalStackLayout _form = new() { Spacing = 12 };
    private readonly Label _message = new() { TextColor = Colors.OrangeRed };
    private readonly TaskCompletionSource<bool> _closed = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private bool _loaded;
    private bool _busy;

    public RecoveryChallengePage(IRecoveryQuestionsService questions, IUnlockAttemptGate gate, ProtectedAccess access)
    {
        _questions = questions;
        _gate = gate;
        _access = access;
        Title = "Einmaliger Notzugang";
        BackgroundColor = Color.FromArgb("#101018");
        _firstName.TextColor = _lastName.TextColor = Colors.White;
        _birthDate.TextColor = Colors.White;
        _birthDate.DateSelected += (_, _) => _birthDateSelected = true;
        foreach (var picker in _answerPickers) picker.TextColor = Colors.White;

        var submit = new Button { Text = "Antworten einmalig abgeben", BackgroundColor = Color.FromArgb("#4A5CFF"), TextColor = Colors.White };
        submit.Clicked += OnSubmit;
        var cancel = new Button { Text = "Abbrechen" };
        cancel.Clicked += async (_, _) => await CloseAsync(false);
        _form.Children.Add(new Label
        {
            Text = "Nur eine Abgabe ist möglich. Eine falsche Antwort verbraucht diesen Notzugang. Richtige Antworten geben zwei weitere Passwortversuche frei.",
            TextColor = Colors.White
        });
        _form.Children.Add(_firstName);
        _form.Children.Add(_lastName);
        _form.Children.Add(new Label { Text = "Geburtsdatum", TextColor = Colors.White });
        _form.Children.Add(_birthDate);
        _form.Children.Add(_message);
        _form.Children.Add(submit);
        _form.Children.Add(cancel);
        Content = new ScrollView { Padding = 20, Content = _form };
    }

    public Task<bool> WaitForCloseAsync() => _closed.Task;

    protected override async void OnAppearing()
    {
        base.OnAppearing();
        if (_loaded) return;
        _loaded = true;
        try
        {
            var prompts = await _questions.GetPromptAsync();
            for (var i = 0; i < 3; i++)
            {
                var index = i;
                var picker = _answerPickers[i];
                picker.Title = "Antwort auswählen";
                foreach (var choice in prompts[i].Choices) picker.Items.Add(choice);
                var location = _form.Children.IndexOf(_message);
                _form.Children.Insert(location, new Label { Text = prompts[index].Text, TextColor = Colors.White });
                _form.Children.Insert(location + 1, picker);
            }
        }
        catch (Exception ex) { _message.Text = ex.Message; }
    }

    private async void OnSubmit(object? sender, EventArgs e)
    {
        if (_busy) return;
        if (string.IsNullOrWhiteSpace(_firstName.Text) || string.IsNullOrWhiteSpace(_lastName.Text) || !_birthDateSelected ||
            _answerPickers.Any(picker => picker.SelectedIndex < 0))
        {
            _message.Text = "Bitte alle Angaben und Antworten auswählen.";
            return;
        }

        var submission = new RecoverySubmission(_firstName.Text, _lastName.Text,
            DateOnly.FromDateTime(_birthDate.Date), _answerPickers.Select(picker => picker.SelectedIndex).ToArray());
        _busy = true;
        try
        {
            if (!await DisplayAlert("Einziger Versuch",
                    "Eine falsche Abgabe verbraucht den Notzugang dieses Tresors dauerhaft, bis er in den Einstellungen erneut aktiviert wird.",
                    "Abgeben", "Zurück")) return;
            if (await _questions.RedeemAsync(_access, submission))
            {
                await DisplayAlert("Zwei Versuche freigegeben", "Gib jetzt das richtige Passwort ein.", "OK");
                await CloseAsync(true);
                return;
            }

            var status = await _gate.GetStatusAsync(_access);
            await DisplayAlert("Notzugang nicht verfügbar",
                status.RecoveryUsed ? "Die Angaben stimmen nicht. Dieser Notzugang ist verbraucht." :
                    "Die Sperrzeit ist inzwischen abgelaufen. Melde dich normal an.", "OK");
            await CloseAsync(false);
        }
        catch (Exception ex) { _message.Text = ex.Message; }
        finally { _busy = false; }
    }

    private async Task CloseAsync(bool redeemed)
    {
        _closed.TrySetResult(redeemed);
        await Navigation.PopModalAsync();
    }

    protected override void OnDisappearing()
    {
        base.OnDisappearing();
        _firstName.Text = _lastName.Text = string.Empty;
        foreach (var picker in _answerPickers) picker.SelectedIndex = -1;
        _closed.TrySetResult(false);
    }
}
