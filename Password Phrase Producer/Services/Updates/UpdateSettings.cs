using System.Text.Json;
using System.Text.Json.Serialization;
using PasswordPhraseProducer.Updates;

namespace Password_Phrase_Producer.Services.Updates;

// Keep updater housekeeping out of MAUI's shared preferences file: background checks must not
// race with vault settings writes. This file stays in the existing version-independent data directory.
public sealed class UpdateSettings : IUpdateSettings
{
    private readonly object _sync = new();
    private readonly string _path = Path.Combine(FileSystem.AppDataDirectory, "update-settings.json");
    private UpdatePreferences _values = new();

    public UpdateSettings()
    {
        if (!File.Exists(_path)) return;
        try { _values = JsonSerializer.Deserialize(File.ReadAllText(_path), UpdateSettingsJsonContext.Default.UpdatePreferences) ?? new(); }
        catch { _values = new() { AutomaticChecks = false, AutomaticDownloads = false }; }
    }

    public bool AutomaticChecks
    {
        get { lock (_sync) return _values.AutomaticChecks; }
        set { lock (_sync) Save(_values with { AutomaticChecks = value }); }
    }
    public bool AutomaticDownloads
    {
        get { lock (_sync) return _values.AutomaticDownloads; }
        set { lock (_sync) Save(_values with { AutomaticDownloads = value }); }
    }
    public DateTimeOffset? LastCheckUtc
    {
        get { lock (_sync) return _values.LastCheckUtc; }
        set { lock (_sync) Save(_values with { LastCheckUtc = value }); }
    }
    private void Save(UpdatePreferences values)
    {
        var temporary = _path + ".tmp";
        try
        {
            File.WriteAllBytes(temporary, JsonSerializer.SerializeToUtf8Bytes(values, UpdateSettingsJsonContext.Default.UpdatePreferences));
            File.Move(temporary, _path, overwrite: true);
            _values = values;
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }
}

internal sealed record UpdatePreferences
{
    public bool AutomaticChecks { get; init; } = true;
    public bool AutomaticDownloads { get; init; } = true;
    public DateTimeOffset? LastCheckUtc { get; init; }
}

[JsonSerializable(typeof(UpdatePreferences))]
internal partial class UpdateSettingsJsonContext : JsonSerializerContext;
