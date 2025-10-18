using System.Text.Json.Serialization;

namespace Password_Phrase_Producer.Models;

public class PasswordVaultEntry
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public string Label { get; set; } = string.Empty;

    public string Username { get; set; } = string.Empty;

    public string Password { get; set; } = string.Empty;

    public string Category { get; set; } = string.Empty;

    public string Url { get; set; } = string.Empty;

    public string Notes { get; set; } = string.Empty;

    public string FreeText { get; set; } = string.Empty;

    public DateTimeOffset ModifiedAt { get; set; } = DateTimeOffset.UtcNow;

    [JsonIgnore]
    public string DisplayCategory => string.IsNullOrWhiteSpace(Category) ? "Allgemein" : Category.Trim();

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
}
