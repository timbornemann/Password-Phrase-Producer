using System;
using Microsoft.Maui.Controls;

namespace Password_Phrase_Producer;

public class PasswordModeOption
{
    public PasswordModeOption(string key, string title, string description, Func<ContentView> contentFactory, string route, string? icon = null)
    {
        Key = key;
        Title = title;
        Description = description;
        Icon = icon;
        Route = route;
        ContentFactory = contentFactory;
    }

    public string Key { get; }

    public string Title { get; }

    public string Description { get; }

    public string Route { get; }

    public string? Icon { get; }

    private Func<ContentView> ContentFactory { get; }

    public ContentView CreateView() => ContentFactory();
}
