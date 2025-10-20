using System.Collections.Generic;
using System.Collections.ObjectModel;
using Password_Phrase_Producer.Models;

namespace Password_Phrase_Producer.ViewModels;

public class VaultEntryGroup : ObservableCollection<PasswordVaultEntry>
{
    public VaultEntryGroup(string category, IEnumerable<PasswordVaultEntry> entries)
        : base(entries)
    {
        Category = category;
    }

    public string Category { get; }
}
