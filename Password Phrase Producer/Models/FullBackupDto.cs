using System;

namespace Password_Phrase_Producer.Models;

public class FullBackupDto
{
    public int Version { get; set; } = 1;
    public PasswordVaultBackupDto? PasswordVault { get; set; }
    public PasswordVaultBackupDto? DataVault { get; set; }
    public AuthenticatorBackupDto? Authenticator { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
}

