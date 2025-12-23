using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Text.Json.Serialization;

namespace Password_Phrase_Producer.Models;

public class PasswordVaultEntry : INotifyPropertyChanged
{
    private Guid _id = Guid.NewGuid();
    private string _label = string.Empty;
    private string _username = string.Empty;
    private string _password = string.Empty;
    private string _category = string.Empty;
    private string _url = string.Empty;
    private string _notes = string.Empty;
    private string _freeText = string.Empty;
    private DateTimeOffset _modifiedAt = DateTimeOffset.UtcNow;
    private bool _isPasswordVisible;

    public event PropertyChangedEventHandler? PropertyChanged;

    public Guid Id
    {
        get => _id;
        set => SetProperty(ref _id, value);
    }

    public string Label
    {
        get => _label;
        set => SetProperty(ref _label, value);
    }

    public string Username
    {
        get => _username;
        set => SetProperty(ref _username, value);
    }

    public string Password
    {
        get => _password;
        set => SetProperty(ref _password, value);
    }

    public string Category
    {
        get => _category;
        set => SetProperty(ref _category, value ?? string.Empty);
    }

    public string Url
    {
        get => _url;
        set => SetProperty(ref _url, value);
    }

    public string Notes
    {
        get => _notes;
        set => SetProperty(ref _notes, value);
    }

    public string FreeText
    {
        get => _freeText;
        set => SetProperty(ref _freeText, value);
    }

    public DateTimeOffset ModifiedAt
    {
        get => _modifiedAt;
        set => SetProperty(ref _modifiedAt, value);
    }

    [JsonIgnore]
    public string DisplayCategory => string.IsNullOrWhiteSpace(Category) ? "Allgemein" : Category?.Trim() ?? "Allgemein";

    [JsonIgnore]
    public DateTimeOffset LocalModifiedAt => ModifiedAt.ToLocalTime();

    [JsonIgnore]
    public bool IsPasswordVisible
    {
        get => _isPasswordVisible;
        set => SetProperty(ref _isPasswordVisible, value);
    }

    public PasswordVaultEntry Clone()
    {
        return new PasswordVaultEntry
        {
            Id = Id,
            Label = Label,
            Username = Username,
            Password = Password,
            Category = Category,
            Url = Url,
            Notes = Notes,
            FreeText = FreeText,
            ModifiedAt = ModifiedAt
        };
    }

    private bool SetProperty<T>(ref T field, T value, [CallerMemberName] string? propertyName = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value))
        {
            return false;
        }

        field = value;
        OnPropertyChanged(propertyName);

        if (propertyName == nameof(Category))
        {
            OnPropertyChanged(nameof(DisplayCategory));
        }
        else if (propertyName == nameof(ModifiedAt))
        {
            OnPropertyChanged(nameof(LocalModifiedAt));
        }

        return true;
    }

    private void OnPropertyChanged(string? propertyName)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
}
