using Password_Phrase_Producer.Services.Security;

namespace Password_Phrase_Producer.Views.Security;

public sealed class RecoverySettingsPage : ContentPage
{
    private readonly IRecoveryQuestionsService _questions;
    private readonly IUnlockAttemptGate _gate;
    private readonly Entry _firstName = new() { Placeholder = "Vorname" };
    private readonly Entry _lastName = new() { Placeholder = "Nachname" };
    private readonly DatePicker _birthDate = new() { MaximumDate = DateTime.Today };
    private bool _birthDateSelected;
    private readonly Picker[] _questionPickers = [new(), new(), new()];
    private readonly Picker[] _correctPickers = [new(), new(), new()];
    private readonly Entry[,] _choices = new Entry[3, 5];
    private readonly Dictionary<ProtectedAccess, Button> _rearmButtons = new();
    private readonly Label _message = new() { TextColor = Colors.OrangeRed };
    private readonly TaskCompletionSource _closed = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private bool _busy;

    public RecoverySettingsPage(IRecoveryQuestionsService questions, IUnlockAttemptGate gate)
    {
        _questions = questions;
        _gate = gate;
        Title = "Sicherheitsfragen";
        BackgroundColor = Color.FromArgb("#0D1013");
        _firstName.TextColor = _lastName.TextColor = Colors.White;
        _birthDate.TextColor = Colors.White;
        _birthDate.DateSelected += (_, _) => _birthDateSelected = true;

        var form = new VerticalStackLayout { Spacing = 12 };
        form.Children.Add(new Label { Text = "Sicherheitsfragen", FontSize = 22, FontAttributes = FontAttributes.Bold, TextColor = Colors.White });
        form.Children.Add(new Label
        {
            Text = "Zum Speichern und Erneuern müssen die App und alle eingerichteten Tresore geöffnet sein. Bei einer Änderung alle Angaben neu eingeben. Fünf verschiedene Antwortmöglichkeiten pro Frage festlegen.",
            TextColor = Colors.White
        });
        form.Children.Add(_firstName);
        form.Children.Add(_lastName);
        form.Children.Add(new Label { Text = "Geburtsdatum", TextColor = Colors.White });
        form.Children.Add(_birthDate);

        for (var questionIndex = 0; questionIndex < 3; questionIndex++)
        {
            var picker = _questionPickers[questionIndex];
            picker.Title = $"Frage {questionIndex + 1} wählen";
            picker.TextColor = Colors.White;
            foreach (var question in RecoveryQuestionsService.AvailableQuestions) picker.Items.Add(question.Text);
            form.Children.Add(picker);
            for (var choiceIndex = 0; choiceIndex < 5; choiceIndex++)
            {
                var entry = new Entry { Placeholder = $"Antwortmöglichkeit {choiceIndex + 1}", TextColor = Colors.White };
                _choices[questionIndex, choiceIndex] = entry;
                form.Children.Add(entry);
            }
            var correct = _correctPickers[questionIndex];
            correct.Title = "Richtige Antwort wählen";
            correct.TextColor = Colors.White;
            for (var choiceIndex = 0; choiceIndex < 5; choiceIndex++) correct.Items.Add($"Antwortmöglichkeit {choiceIndex + 1}");
            form.Children.Add(correct);
        }

        var save = new Button { Text = "Fragen speichern", BackgroundColor = Color.FromArgb("#536D81"), TextColor = Colors.White };
        save.Clicked += OnSave;
        form.Children.Add(save);
        form.Children.Add(new Label { Text = "Einmaligen Notzugang bewusst erneuern", TextColor = Colors.White, FontAttributes = FontAttributes.Bold });
        foreach (var (access, name) in new[]
                 {
                     (ProtectedAccess.App, "App"), (ProtectedAccess.PasswordVault, "Passworttresor"),
                     (ProtectedAccess.DataVault, "Datentresor"), (ProtectedAccess.Authenticator, "2FA-Tresor")
                 })
        {
            var button = new Button { Text = $"Notzugang erneuern: {name}", IsEnabled = false };
            button.Clicked += async (_, _) => await RearmAsync(access);
            _rearmButtons[access] = button;
            form.Children.Add(button);
        }
        form.Children.Add(_message);
        var back = new Button { Text = "Zurück" };
        back.Clicked += async (_, _) => await CloseAsync();
        form.Children.Add(back);
        Content = new ScrollView { Padding = 20, Content = form };
    }

    public Task WaitForCloseAsync() => _closed.Task;

    protected override async void OnAppearing()
    {
        base.OnAppearing();
        await RefreshAsync();
    }

    private async Task RefreshAsync()
    {
        try
        {
            var configured = await _questions.IsConfiguredAsync();
            foreach (var (access, button) in _rearmButtons)
                button.IsEnabled = configured && (await _gate.GetStatusAsync(access)).RecoveryUsed;
        }
        catch (Exception ex) { _message.Text = ex.Message; }
    }

    private async void OnSave(object? sender, EventArgs e)
    {
        if (_busy) return;
        _busy = true;
        try
        {
            if (!_birthDateSelected) throw new ArgumentException("Bitte das Geburtsdatum ausdrücklich auswählen.");
            var selected = new RecoveryQuestionSetup[3];
            for (var i = 0; i < 3; i++)
            {
                selected[i] = new RecoveryQuestionSetup(_questionPickers[i].SelectedIndex,
                    Enumerable.Range(0, 5).Select(choice => _choices[i, choice].Text ?? string.Empty).ToArray(),
                    _correctPickers[i].SelectedIndex);
            }
            await _questions.ConfigureAsync(new RecoverySetup(_firstName.Text ?? string.Empty, _lastName.Text ?? string.Empty,
                DateOnly.FromDateTime(_birthDate.Date), selected));
            ClearForm();
            _message.Text = "Sicherheitsfragen gespeichert. Verbrauchte Notzugänge werden nur über die Schaltflächen unten erneuert.";
            await RefreshAsync();
        }
        catch (Exception ex) { _message.Text = ex.Message; }
        finally { _busy = false; }
    }

    private async Task RearmAsync(ProtectedAccess access)
    {
        if (_busy) return;
        _busy = true;
        try
        {
            await _questions.RearmAsync(access);
            _message.Text = "Der Notzugang wurde für diesen Zugang erneut aktiviert.";
            await RefreshAsync();
        }
        catch (Exception ex) { _message.Text = ex.Message; }
        finally { _busy = false; }
    }

    private void ClearForm()
    {
        _firstName.Text = _lastName.Text = string.Empty;
        _birthDateSelected = false;
        foreach (var picker in _questionPickers) picker.SelectedIndex = -1;
        foreach (var picker in _correctPickers) picker.SelectedIndex = -1;
        foreach (var entry in _choices) entry.Text = string.Empty;
    }

    private async Task CloseAsync()
    {
        ClearForm();
        _closed.TrySetResult();
        await Navigation.PopModalAsync();
    }

    protected override void OnDisappearing()
    {
        base.OnDisappearing();
        ClearForm();
        _closed.TrySetResult();
    }
}
