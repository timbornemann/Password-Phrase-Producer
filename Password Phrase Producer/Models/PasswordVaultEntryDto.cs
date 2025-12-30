namespace Password_Phrase_Producer.Models;

public class PasswordVaultEntryDto
{
    public Guid Id { get; set; }

    public string Label { get; set; } = string.Empty;

    public string Username { get; set; } = string.Empty;

    public string Password { get; set; } = string.Empty;

    public string Category { get; set; } = string.Empty;

    public string Url { get; set; } = string.Empty;

    public string Notes { get; set; } = string.Empty;

    public string FreeText { get; set; } = string.Empty;

    public DateTimeOffset ModifiedAt { get; set; }
    public bool IsDeleted { get; set; }

    public static PasswordVaultEntryDto FromModel(PasswordVaultEntry entry)
    {
        return new PasswordVaultEntryDto
        {
            Id = entry.Id,
            Label = entry.Label,
            Username = entry.Username,
            Password = entry.Password,
            Category = entry.Category,
            Url = entry.Url,
            Notes = entry.Notes,
            FreeText = entry.FreeText,
            ModifiedAt = entry.ModifiedAt,
            IsDeleted = entry.IsDeleted
        };
    }

    public PasswordVaultEntry ToModel()
    {
        return new PasswordVaultEntry
        {
            Id = Id == Guid.Empty ? Guid.NewGuid() : Id,
            Label = Label,
            Username = Username,
            Password = Password,
            Category = Category,
            Url = Url,
            Notes = Notes,
            FreeText = FreeText,
            ModifiedAt = ModifiedAt == default ? DateTimeOffset.UtcNow : ModifiedAt,
            IsDeleted = IsDeleted
        };
    }
}
