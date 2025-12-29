using System;
using System.Collections.Generic;
using Password_Phrase_Producer.Services.Security;

namespace Password_Phrase_Producer.Models;

public class SyncModels
{
    public class ExternalVaultHeader
    {
        public int Version { get; set; } = 1;
        public string Salt { get; set; } = ""; // Base64
        public string Verifier { get; set; } = ""; // Base64
        public int Iterations { get; set; } = 200_000;
    }

    public class ExternalVaultContent
    {
        public List<PasswordVaultEntryDto> PasswordVault { get; set; } = new();
        public List<PasswordVaultEntryDto> DataVault { get; set; } = new();
        public List<TotpEntryDto> Authenticator { get; set; } = new();
        public DateTimeOffset LastModified { get; set; } = DateTimeOffset.UtcNow;
    }

    public class ExternalVaultFile
    {
        public ExternalVaultHeader Header { get; set; } = new();
        public string CipherText { get; set; } = ""; // Base64 Encrypted JSON of ExternalVaultContent
    }
}
