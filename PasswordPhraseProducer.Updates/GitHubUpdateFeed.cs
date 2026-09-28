using System.Net;
using System.Text.Json;

namespace PasswordPhraseProducer.Updates;

public sealed class GitHubUpdateFeed(HttpClient http, ReleaseVerifier verifier) : IUpdateFeed
{
    public async Task<SignedRelease?> GetLatestAsync(CancellationToken cancellationToken)
    {
        // A just-created release may already be GitHub's "latest" while its build is pending.
        // Find the highest complete stable version instead, with bounded pagination and response sizes.
        var candidates = new List<(Version Version, string Tag, JsonElement[] Assets)>();
        for (var page = 1; page <= 5; page++)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get,
                $"https://api.github.com/repos/{UpdateIdentity.Repository}/releases?per_page=100&page={page}");
            request.Headers.UserAgent.ParseAdd("PasswordPhraseProducer-Updater/1.0");
            request.Headers.Accept.ParseAdd("application/vnd.github+json");
            using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            if (response.StatusCode == HttpStatusCode.NotFound) break;
            response.EnsureSuccessStatusCode();
            using var document = JsonDocument.Parse(await ReadLimitedAsync(response, 2 * 1024 * 1024, cancellationToken));
            foreach (var release in document.RootElement.EnumerateArray())
            {
                if (release.GetProperty("draft").GetBoolean() || release.GetProperty("prerelease").GetBoolean()) continue;
                var tag = release.GetProperty("tag_name").GetString() ?? "";
                Version version;
                try { version = ReleaseVerifier.ParseReleaseTag(tag); }
                catch (InvalidDataException) { continue; }
                var assets = release.GetProperty("assets").EnumerateArray().Select(a => a.Clone()).ToArray();
                if (!HasUploadedAsset(assets, UpdateIdentity.SignatureName, 64) ||
                    !assets.Any(a => a.GetProperty("name").GetString() == UpdateIdentity.ManifestName && IsUploaded(a) &&
                        a.GetProperty("size").GetInt64() is > 0 and <= ReleaseVerifier.MaxManifestBytes)) continue;
                candidates.Add((version, tag, assets));
            }
            if (document.RootElement.GetArrayLength() < 100) break;
        }
        foreach (var candidate in candidates.OrderByDescending(c => c.Version))
        {
            var manifest = await ReadAssetAsync(candidate.Tag, UpdateIdentity.ManifestName, ReleaseVerifier.MaxManifestBytes, cancellationToken);
            var signature = await ReadAssetAsync(candidate.Tag, UpdateIdentity.SignatureName, 64, cancellationToken);
            if (manifest is null || signature is null) continue; // Upload/CDN publication still in progress.
            var verified = verifier.Verify(manifest, signature);
            if (verified.Manifest.ReleaseTag != candidate.Tag)
                throw new InvalidDataException("Die Veröffentlichung stimmt nicht mit dem signierten Manifest überein.");
            if (verified.Manifest.Artifacts.Any(a => !HasUploadedAsset(candidate.Assets, a.FileName, a.Size))) continue;
            return verified;
        }
        return null;
    }

    private static bool IsUploaded(JsonElement asset) =>
        asset.TryGetProperty("state", out var state) && state.GetString() == "uploaded";

    private static bool HasUploadedAsset(JsonElement[] assets, string name, long size) =>
        assets.Count(a => a.GetProperty("name").GetString() == name && IsUploaded(a) && a.GetProperty("size").GetInt64() == size) == 1;

    private async Task<byte[]?> ReadAssetAsync(string tag, string name, int limit, CancellationToken ct)
    {
        using var response = await http.GetAsync(ReleaseVerifier.AssetUri(tag, name), HttpCompletionOption.ResponseHeadersRead, ct);
        if (response.StatusCode == HttpStatusCode.NotFound) return null;
        response.EnsureSuccessStatusCode();
        return await ReadLimitedAsync(response, limit, ct);
    }

    internal static async Task<byte[]> ReadLimitedAsync(HttpResponseMessage response, int limit, CancellationToken ct)
    {
        if (response.Content.Headers.ContentLength > limit) throw new InvalidDataException("Die Antwort ist zu groß.");
        await using var input = await response.Content.ReadAsStreamAsync(ct);
        using var output = new MemoryStream();
        var buffer = new byte[8192];
        int count;
        while ((count = await input.ReadAsync(buffer, ct)) != 0)
        {
            if (output.Length + count > limit) throw new InvalidDataException("Die Antwort ist zu groß.");
            output.Write(buffer, 0, count);
        }
        return output.ToArray();
    }
}
