using Password_Phrase_Producer.Services.Vault;

namespace Password_Phrase_Producer.Services.Security;

public sealed class RecoveryAccessAuthorizer : IRecoveryAccessAuthorizer
{
    private readonly IAppLockService _appLock;
    private readonly PasswordVaultService _passwordVault;
    private readonly DataVaultService _dataVault;
    private readonly TotpEncryptionService _authenticator;

    public RecoveryAccessAuthorizer(IAppLockService appLock, PasswordVaultService passwordVault,
        DataVaultService dataVault, TotpEncryptionService authenticator)
    {
        _appLock = appLock;
        _passwordVault = passwordVault;
        _dataVault = dataVault;
        _authenticator = authenticator;
    }

    public async Task<bool> AllConfiguredVaultsUnlockedAsync()
    {
        if (!_appLock.IsUnlocked) return false;
        if (await _passwordVault.HasMasterPasswordAsync().ConfigureAwait(false) && !_passwordVault.IsUnlocked) return false;
        if (await _dataVault.HasMasterPasswordAsync().ConfigureAwait(false) && !_dataVault.IsUnlocked) return false;
        if (await _authenticator.HasPasswordAsync().ConfigureAwait(false) && !_authenticator.IsUnlocked) return false;
        return _appLock.IsUnlocked;
    }
}
