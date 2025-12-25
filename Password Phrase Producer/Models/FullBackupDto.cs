using System;

namespace Password_Phrase_Producer.Models;

public class FullBackupDto
{
    public int Version { get; set; } = 2;
    public PortableBackupDto? PasswordVault { get; set; }
    public PortableBackupDto? DataVault { get; set; }
    [Obsolete("Use AuthenticatorEncrypted for secure encrypted backups")]
    public AuthenticatorBackupDto? Authenticator { get; set; }
    public PortableBackupDto? AuthenticatorEncrypted { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
}

