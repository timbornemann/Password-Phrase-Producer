using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using Xunit;

namespace PasswordPhraseProducer.Updates.Tests;

public sealed partial class UpdateTests
{
    private static Dictionary<string, object?> Listing(SignedRelease signed, string? omit = null, string? incomplete = null)
    {
        var assets = signed.Manifest.Artifacts.Select(a => (a.FileName, a.Size))
            .Concat([(UpdateIdentity.ManifestName, (long)signed.ManifestBytes.Length), (UpdateIdentity.SignatureName, 64L)])
            .Where(a => a.Item1 != omit)
            .Select(a => new { name = a.Item1, size = a.Item2, state = a.Item1 == incomplete ? "starter" : "uploaded" }).ToArray();
        return new() { ["tag_name"] = signed.Manifest.ReleaseTag, ["draft"] = false, ["prerelease"] = false, ["assets"] = assets };
    }

    [Theory]
    [InlineData("update-manifest.json")]
    [InlineData("update-manifest.sig")]
    [InlineData("app.apk")]
    [InlineData("app-Setup.exe")]
    [InlineData("app-full.nupkg")]
    public async Task PendingReleaseDoesNotHideThePreviousCompleteRelease(string missing)
    {
        using var f = new Fixture();
        var pending = f.Sign(f.Signed.Manifest with { Version = "2.6.0", BuildNumber = 2006000, ReleaseTag = "v2.6.0" });
        using var http = FeedClient([Listing(pending, omit: missing), Listing(f.Signed)], f.Signed, pending);
        var result = await new GitHubUpdateFeed(http, f.Verifier).GetLatestAsync(default);
        Assert.Equal("2.5.9", result!.Manifest.Version);
    }

    [Theory]
    [InlineData("update-manifest.json")]
    [InlineData("update-manifest.sig")]
    [InlineData("app.apk")]
    public async Task UnfinishedUploadsAreIgnoredWithoutReportingAnUpdateError(string uploading)
    {
        using var f = new Fixture();
        using var http = FeedClient([Listing(f.Signed, incomplete: uploading)], f.Signed);
        Assert.Null(await new GitHubUpdateFeed(http, f.Verifier).GetLatestAsync(default));
    }

    [Fact]
    public async Task ReleaseOnlyBecomesAvailableAfterLastSignatureUpload()
    {
        using var f = new Fixture();
        var listing = Listing(f.Signed, omit: UpdateIdentity.SignatureName);
        using var http = FeedClient([listing], f.Signed);
        var feed = new GitHubUpdateFeed(http, f.Verifier);
        Assert.Null(await feed.GetLatestAsync(default));
        listing["assets"] = Listing(f.Signed)["assets"];
        Assert.Equal("2.5.9", (await feed.GetLatestAsync(default))!.Manifest.Version);
    }

    [Fact]
    public async Task HighestCompleteVersionWinsEvenIfAnOlderReleaseWasPublishedLater()
    {
        using var f = new Fixture();
        var newer = f.Sign(f.Signed.Manifest with { Version = "2.10.0", BuildNumber = 2010000, ReleaseTag = "2.10.0" });
        using var http = FeedClient([Listing(f.Signed), Listing(newer)], f.Signed, newer);
        Assert.Equal("2.10.0", (await new GitHubUpdateFeed(http, f.Verifier).GetLatestAsync(default))!.Manifest.Version);
    }

    [Fact]
    public async Task PublicationRaceWithMetadata404FallsBackToPreviousRelease()
    {
        using var f = new Fixture();
        var newer = f.Sign(f.Signed.Manifest with { Version = "2.6.0", BuildNumber = 2006000, ReleaseTag = "v2.6.0" });
        using var http = new HttpClient(new FeedHandler(uri =>
        {
            if (uri.Host == "api.github.com") return JsonResponse(new[] { Listing(newer), Listing(f.Signed) });
            if (uri.AbsolutePath.Contains("v2.6.0")) return new(HttpStatusCode.NotFound);
            return ByteResponse(uri.AbsolutePath.EndsWith(".sig") ? f.Signed.Signature : f.Signed.ManifestBytes);
        }));
        Assert.Equal("2.5.9", (await new GitHubUpdateFeed(http, f.Verifier).GetLatestAsync(default))!.Manifest.Version);
    }

    [Fact]
    public async Task CompleteReleaseWithInvalidSignatureIsStillRejected()
    {
        using var f = new Fixture();
        using var http = new HttpClient(new FeedHandler(uri => uri.Host == "api.github.com"
            ? JsonResponse(new[] { Listing(f.Signed) })
            : ByteResponse(uri.AbsolutePath.EndsWith(".sig") ? new byte[64] : f.Signed.ManifestBytes)));
        await Assert.ThrowsAsync<CryptographicException>(() => new GitHubUpdateFeed(http, f.Verifier).GetLatestAsync(default));
    }

    [Fact]
    public async Task CompleteReleaseCanBeFoundOnTheNextPage()
    {
        using var f = new Fixture();
        var pages = 0;
        using var http = new HttpClient(new FeedHandler(uri =>
        {
            if (uri.Host != "api.github.com")
                return ByteResponse(uri.AbsolutePath.EndsWith(".sig") ? f.Signed.Signature : f.Signed.ManifestBytes);
            pages++;
            return uri.Query.Contains("&page=1") ? JsonResponse(Enumerable.Repeat(Listing(f.Signed, omit: UpdateIdentity.SignatureName), 100))
                : JsonResponse(new[] { Listing(f.Signed) });
        }));
        Assert.NotNull(await new GitHubUpdateFeed(http, f.Verifier).GetLatestAsync(default));
        Assert.Equal(2, pages);
    }

    private static HttpClient FeedClient(Dictionary<string, object?>[] listings, params SignedRelease[] releases) =>
        new(new FeedHandler(uri =>
        {
            if (uri.Host == "api.github.com") return JsonResponse(listings);
            var release = releases.Single(r => uri.AbsolutePath.Contains($"/download/{r.Manifest.ReleaseTag}/"));
            return ByteResponse(uri.AbsolutePath.EndsWith(".sig") ? release.Signature : release.ManifestBytes);
        }));
    private static HttpResponseMessage JsonResponse(object value) => ByteResponse(JsonSerializer.SerializeToUtf8Bytes(value));
    private static HttpResponseMessage ByteResponse(byte[] bytes) => new(HttpStatusCode.OK) { Content = new ByteArrayContent(bytes) };
    private sealed class FeedHandler(Func<Uri, HttpResponseMessage> response) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) =>
            Task.FromResult(response(request.RequestUri!));
    }
}
