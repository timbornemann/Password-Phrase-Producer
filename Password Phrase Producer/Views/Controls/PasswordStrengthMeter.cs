using Password_Phrase_Producer.Services.Security;

namespace Password_Phrase_Producer.Views.Controls;

public sealed class PasswordStrengthMeter : VerticalStackLayout
{
    public static readonly BindableProperty PasswordProperty = BindableProperty.Create(
        nameof(Password), typeof(string), typeof(PasswordStrengthMeter), default(string),
        propertyChanged: (bindable, _, value) =>
            ((PasswordStrengthMeter)bindable).Update((string?)value));

    private readonly ProgressBar _bar;

    public string? Password
    {
        get => (string?)GetValue(PasswordProperty);
        set => SetValue(PasswordProperty, value);
    }

    public PasswordStrengthMeter()
    {
        Spacing = 5;
        var title = new Label { Text = "Passwortstärke", FontSize = 11 };
        title.SetDynamicResource(Label.TextColorProperty, "TextTertiary");
        Children.Add(title);

        _bar = new ProgressBar
        {
            Progress = 0,
            HeightRequest = 4,
            HorizontalOptions = LayoutOptions.Fill,
            BackgroundColor = Color.FromArgb("#2B343D"),
            ProgressColor = Color.FromArgb("#C45155")
        };
        Children.Add(_bar);
    }

    private void Update(string? password)
    {
        var strength = PasswordStrengthEstimator.Estimate(password);
        _bar.Progress = strength;

        var firstHalf = strength <= 0.5;
        var position = firstHalf ? strength * 2 : (strength - 0.5) * 2;
        var start = firstHalf ? (R: 196, G: 81, B: 85) : (R: 207, G: 163, B: 87);
        var end = firstHalf ? (R: 207, G: 163, B: 87) : (R: 92, G: 168, B: 118);
        _bar.ProgressColor = Color.FromRgb(
            Blend(start.R, end.R, position),
            Blend(start.G, end.G, position),
            Blend(start.B, end.B, position));
    }

    private static byte Blend(int from, int to, double position)
        => (byte)Math.Round(from + (to - from) * position);
}
