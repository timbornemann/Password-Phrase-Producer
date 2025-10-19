using System;
using System.Globalization;
using Microsoft.Maui.Controls;

namespace Password_Phrase_Producer.Converters;

public class PasswordMaskConverter : IValueConverter
{
    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is not string password || password.Length == 0)
        {
            return "••••••";
        }

        var visibleLength = Math.Min(password.Length, 16);
        return new string('•', visibleLength);
    }

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => value;
}
