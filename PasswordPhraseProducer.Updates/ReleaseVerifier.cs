using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace PasswordPhraseProducer.Updates;

public sealed partial class ReleaseVerifier(string publicKeyPem)
{
    public const int MaxManifestBytes = 128 * 1024;
    public static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        TypeInfoResolver = UpdateJsonContext.Default
    };

    public SignedRelease Verify(byte[] bytes, byte[] signature)
    {
        if (bytes.Length is 0 or > MaxManifestBytes || signature.Length != 64)
            throw new InvalidDataException("Ungültige Update-Metadaten.");
        using var key = ECDsa.Create();
        key.ImportFromPem(publicKeyPem);
        if (key.KeySize != 256 || !key.VerifyData(bytes, signature, HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
            throw new CryptographicException("Die Signatur des Updates ist ungültig.");
        var manifest = JsonSerializer.Deserialize<UpdateManifest>(bytes, JsonOptions)
            ?? throw new InvalidDataException("Das Update-Manifest ist leer.");
        ValidateManifest(manifest);
        return new(manifest, bytes, signature);
    }

    public static void ValidateManifest(UpdateManifest manifest)
    {
        _ = ParseVersion(manifest.Version);
        if (manifest.SchemaVersion != 1 || manifest.BuildNumber is <= 0 or > int.MaxValue ||
            (manifest.ReleaseTag != "v" + manifest.Version && manifest.ReleaseTag != manifest.Version) ||
            manifest.Notes is null || manifest.Notes.Length > 20000 ||
            manifest.Artifacts is null || manifest.Artifacts.Length != 3)
            throw new InvalidDataException("Das Update-Manifest wird nicht unterstützt.");
        var expected = new HashSet<string>(StringComparer.Ordinal)
            { "windows/x64/full", "windows/x64/installer", "android/universal/apk" };
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var a in manifest.Artifacts)
        {
            if (a is null || !expected.Remove($"{a.Platform}/{a.Architecture}/{a.Kind}") ||
                a.FileName is null || !FileNamePattern().IsMatch(a.FileName) || !names.Add(a.FileName) ||
                a.FileName.Contains("..", StringComparison.Ordinal) || a.Size is <= 0 or > 2_147_483_647 ||
                a.Sha256 is null || !HashPattern().IsMatch(a.Sha256))
                throw new InvalidDataException("Ungültige Update-Datei.");
            var extension = a.Kind switch { "full" => ".nupkg", "installer" => ".exe", _ => ".apk" };
            if (!a.FileName.EndsWith(extension, StringComparison.Ordinal))
                throw new InvalidDataException("Ungültiges Update-Dateiformat.");
        }
    }

    public static Version ParseVersion(string version)
    {
        if (version is null || !VersionPattern().IsMatch(version) || !Version.TryParse(version, out var result))
            throw new InvalidDataException("Ungültige Versionsnummer.");
        return result;
    }

    public static Version ParseReleaseTag(string tag) => ParseVersion(tag.StartsWith('v') ? tag[1..] : tag);

    public static UpdateRelease? Select(SignedRelease signed, InstalledApplication installed)
    {
        if (ParseVersion(signed.Manifest.Version) <= ParseVersion(installed.Version) ||
            signed.Manifest.BuildNumber <= installed.BuildNumber)
            return null;
        var artifact = signed.Manifest.Artifacts.SingleOrDefault(a => a.Platform == installed.Platform &&
            a.Architecture == installed.Architecture && a.Kind == (installed.Platform == "windows" ? "full" : "apk"));
        return artifact is null ? null : new(signed, artifact);
    }

    public static Uri AssetUri(string tag, string fileName) =>
        new($"https://github.com/{UpdateIdentity.Repository}/releases/download/{Uri.EscapeDataString(tag)}/{Uri.EscapeDataString(fileName)}");

    public static async Task VerifyPackageAsync(string path, UpdateArtifact artifact, CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, true);
        if (stream.Length != artifact.Size)
            throw new InvalidDataException("Die Update-Datei ist unvollständig.");
        var hash = await SHA256.HashDataAsync(stream, cancellationToken);
        if (!CryptographicOperations.FixedTimeEquals(hash, Convert.FromHexString(artifact.Sha256)))
            throw new CryptographicException("Die Prüfsumme des Updates ist ungültig.");
    }

    [GeneratedRegex(@"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")]
    private static partial Regex VersionPattern();
    [GeneratedRegex(@"^[A-Za-z0-9][A-Za-z0-9._-]{0,180}$")]
    private static partial Regex FileNamePattern();
    [GeneratedRegex(@"^[a-fA-F0-9]{64}$")]
    private static partial Regex HashPattern();
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow)]
[JsonSerializable(typeof(UpdateManifest))]
internal partial class UpdateJsonContext : JsonSerializerContext;
