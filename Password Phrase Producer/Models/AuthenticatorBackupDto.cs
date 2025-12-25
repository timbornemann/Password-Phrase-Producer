using System;
using System.Collections.Generic;
using Password_Phrase_Producer.Services.Security;

namespace Password_Phrase_Producer.Models;

public class AuthenticatorBackupDto
{
    public int Version { get; set; } = 1;
    public List<TotpEntryDto> Entries { get; set; } = new();
    public string PasswordHash { get; set; } = string.Empty;
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
}

