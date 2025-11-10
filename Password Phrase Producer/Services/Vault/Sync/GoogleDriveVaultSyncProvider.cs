using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;

namespace Password_Phrase_Producer.Services.Vault.Sync;

public sealed class GoogleDriveVaultSyncProvider : IVaultSyncProvider
{
    public const string ProviderKey = "GoogleDrive";
    public const string ClientIdParameterKey = "clientId";
    public const string ClientSecretParameterKey = "clientSecret";
    public const string RefreshTokenParameterKey = "refreshToken";
    public const string FileIdParameterKey = "fileId";
    public const string FileNameParameterKey = "fileName";
    public const string FolderIdParameterKey = "folderId";

    private const string MerklePropertyKey = "vaultMerkleHash";
    private const string DefaultFileName = "vault.json.enc";
    private static readonly Uri TokenEndpoint = new("https://oauth2.googleapis.com/token");
    private static readonly Uri DriveApiBaseUri = new("https://www.googleapis.com/drive/v3/");
    private static readonly Uri DriveUploadBaseUri = new("https://www.googleapis.com/upload/drive/v3/");
    private static readonly HttpClient SharedHttpClient = new()
    {
        Timeout = TimeSpan.FromSeconds(100)
    };

    private readonly HttpClient _httpClient;
    private readonly JsonSerializerOptions _jsonOptions = new()
    {
        PropertyNameCaseInsensitive = true
    };

    public GoogleDriveVaultSyncProvider(HttpClient? httpClient = null)
    {
        _httpClient = httpClient ?? SharedHttpClient;
    }

    public string Key => ProviderKey;

    public string DisplayName => "Google Drive";

    public bool SupportsAutomaticSync => true;

    public Task<bool> IsConfiguredAsync(VaultSyncConfiguration configuration, CancellationToken cancellationToken = default)
    {
        var hasCoreParameters = configuration.Parameters.TryGetValue(ClientIdParameterKey, out var clientId) && !string.IsNullOrWhiteSpace(clientId)
            && configuration.Parameters.TryGetValue(ClientSecretParameterKey, out var clientSecret) && !string.IsNullOrWhiteSpace(clientSecret)
            && configuration.Parameters.TryGetValue(RefreshTokenParameterKey, out var refreshToken) && !string.IsNullOrWhiteSpace(refreshToken);

        if (!hasCoreParameters)
        {
            return Task.FromResult(false);
        }

        if (configuration.Parameters.TryGetValue(FileIdParameterKey, out var fileId) && !string.IsNullOrWhiteSpace(fileId))
        {
            return Task.FromResult(true);
        }

        if (configuration.Parameters.TryGetValue(FileNameParameterKey, out var fileName) && !string.IsNullOrWhiteSpace(fileName))
        {
            return Task.FromResult(true);
        }

        return Task.FromResult(false);
    }

    public async Task<VaultSyncRemoteState?> GetRemoteStateAsync(VaultSyncConfiguration configuration, CancellationToken cancellationToken = default)
    {
        if (!await IsConfiguredAsync(configuration, cancellationToken).ConfigureAwait(false))
        {
            return null;
        }

        var accessToken = await AcquireAccessTokenAsync(configuration, cancellationToken).ConfigureAwait(false);
        var file = await ResolveFileAsync(configuration, accessToken, cancellationToken).ConfigureAwait(false);
        if (file is null)
        {
            return null;
        }

        return CreateRemoteState(file);
    }

    public async Task<VaultSyncDownloadResult?> DownloadAsync(VaultSyncConfiguration configuration, CancellationToken cancellationToken = default)
    {
        if (!await IsConfiguredAsync(configuration, cancellationToken).ConfigureAwait(false))
        {
            return null;
        }

        var accessToken = await AcquireAccessTokenAsync(configuration, cancellationToken).ConfigureAwait(false);
        var file = await ResolveFileAsync(configuration, accessToken, cancellationToken).ConfigureAwait(false);
        if (file is null || string.IsNullOrWhiteSpace(file.Id))
        {
            return null;
        }

        var payload = await DownloadFileAsync(file.Id, accessToken, cancellationToken).ConfigureAwait(false);
        return new VaultSyncDownloadResult
        {
            Payload = payload,
            RemoteState = CreateRemoteState(file)
        };
    }

    public async Task UploadAsync(VaultSyncUploadRequest request, VaultSyncConfiguration configuration, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (!await IsConfiguredAsync(configuration, cancellationToken).ConfigureAwait(false))
        {
            throw new InvalidOperationException("Die Google-Drive-Synchronisation ist nicht vollständig konfiguriert.");
        }

        var accessToken = await AcquireAccessTokenAsync(configuration, cancellationToken).ConfigureAwait(false);
        var file = await ResolveFileAsync(configuration, accessToken, cancellationToken).ConfigureAwait(false);

        if (file is not null && request.RemoteStateBeforeUpload is not null)
        {
            var remoteHash = file.AppProperties is not null && file.AppProperties.TryGetValue(MerklePropertyKey, out var merkle)
                ? merkle
                : string.Empty;
            if (!string.Equals(remoteHash, request.RemoteStateBeforeUpload.MerkleHash, StringComparison.Ordinal))
            {
                throw new InvalidOperationException("Der entfernte Tresor wurde seit der letzten Synchronisation verändert.");
            }
        }

        if (file is null || string.IsNullOrWhiteSpace(file.Id))
        {
            await CreateFileAsync(request, configuration, accessToken, cancellationToken).ConfigureAwait(false);
        }
        else
        {
            await UpdateFileAsync(file.Id, request, configuration, accessToken, cancellationToken).ConfigureAwait(false);
        }
    }

    private static VaultSyncRemoteState CreateRemoteState(DriveFileMetadata file)
    {
        var lastModified = file.ModifiedTimeRaw is null
            ? DateTimeOffset.UtcNow
            : DateTimeOffset.Parse(file.ModifiedTimeRaw, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal);

        var merkleHash = file.AppProperties is not null && file.AppProperties.TryGetValue(MerklePropertyKey, out var merkle)
            ? merkle
            : string.Empty;

        var contentLength = 0L;
        if (file.SizeRaw is not null && long.TryParse(file.SizeRaw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsedSize))
        {
            contentLength = parsedSize;
        }

        return new VaultSyncRemoteState
        {
            LastModifiedUtc = lastModified,
            MerkleHash = merkleHash,
            ContentLength = contentLength,
            EntityTag = file.HeadRevisionId
        };
    }

    private async Task<string> AcquireAccessTokenAsync(VaultSyncConfiguration configuration, CancellationToken cancellationToken)
    {
        var parameters = new Dictionary<string, string>
        {
            ["client_id"] = configuration.Parameters[ClientIdParameterKey],
            ["client_secret"] = configuration.Parameters[ClientSecretParameterKey],
            ["refresh_token"] = configuration.Parameters[RefreshTokenParameterKey],
            ["grant_type"] = "refresh_token"
        };

        using var request = new HttpRequestMessage(HttpMethod.Post, TokenEndpoint)
        {
            Content = new FormUrlEncodedContent(parameters)
        };

        using var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        var content = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            var error = JsonSerializer.Deserialize<TokenErrorResponse>(content, _jsonOptions);
            var message = error?.ErrorDescription ?? error?.Error ?? response.ReasonPhrase ?? "Unbekannter Fehler beim Abrufen des Tokens.";
            throw new InvalidOperationException($"Google Drive Zugriffstoken konnte nicht aktualisiert werden: {message}");
        }

        var token = JsonSerializer.Deserialize<TokenSuccessResponse>(content, _jsonOptions);
        if (token is null || string.IsNullOrWhiteSpace(token.AccessToken))
        {
            throw new InvalidOperationException("Google Drive hat kein gültiges Zugriffstoken zurückgegeben.");
        }

        return token.AccessToken;
    }

    private async Task<DriveFileMetadata?> ResolveFileAsync(VaultSyncConfiguration configuration, string accessToken, CancellationToken cancellationToken)
    {
        var fileId = GetOptionalParameter(configuration, FileIdParameterKey);
        if (!string.IsNullOrWhiteSpace(fileId))
        {
            var metadata = await GetFileByIdAsync(fileId!, accessToken, cancellationToken).ConfigureAwait(false);
            if (metadata is not null)
            {
                return metadata;
            }
        }

        var fileName = GetFileName(configuration);
        var folderId = GetOptionalParameter(configuration, FolderIdParameterKey);
        return await FindFileByNameAsync(fileName, folderId, accessToken, cancellationToken).ConfigureAwait(false);
    }

    private async Task<DriveFileMetadata?> GetFileByIdAsync(string fileId, string accessToken, CancellationToken cancellationToken)
    {
        var requestUri = new Uri(DriveApiBaseUri, $"files/{Uri.EscapeDataString(fileId)}?fields=id,name,modifiedTime,size,headRevisionId,appProperties&supportsAllDrives=true");
        using var request = new HttpRequestMessage(HttpMethod.Get, requestUri);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

        using var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
        {
            return null;
        }

        response.EnsureSuccessStatusCode();
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        var metadata = await JsonSerializer.DeserializeAsync<DriveFileMetadata>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
        return metadata;
    }

    private async Task<DriveFileMetadata?> FindFileByNameAsync(string fileName, string? folderId, string accessToken, CancellationToken cancellationToken)
    {
        var sanitizedName = fileName.Replace("'", "\\'");
        var queryBuilder = new StringBuilder();
        queryBuilder.Append($"name = '{sanitizedName}' and trashed = false");
        if (!string.IsNullOrWhiteSpace(folderId))
        {
            var sanitizedFolderId = folderId.Replace("'", "\\'");
            queryBuilder.Append($" and '{sanitizedFolderId}' in parents");
        }

        var requestUri = new Uri(DriveApiBaseUri, $"files?q={Uri.EscapeDataString(queryBuilder.ToString())}&fields=files(id,name,modifiedTime,size,headRevisionId,appProperties)&pageSize=1&supportsAllDrives=true&includeItemsFromAllDrives=true");
        using var request = new HttpRequestMessage(HttpMethod.Get, requestUri);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

        using var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        var list = await JsonSerializer.DeserializeAsync<DriveFileListResponse>(stream, _jsonOptions, cancellationToken).ConfigureAwait(false);
        return list?.Files is { Count: > 0 } ? list.Files[0] : null;
    }

    private async Task<byte[]> DownloadFileAsync(string fileId, string accessToken, CancellationToken cancellationToken)
    {
        var requestUri = new Uri(DriveApiBaseUri, $"files/{Uri.EscapeDataString(fileId)}?alt=media&supportsAllDrives=true");
        using var request = new HttpRequestMessage(HttpMethod.Get, requestUri);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

        using var response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
    }

    private async Task CreateFileAsync(VaultSyncUploadRequest request, VaultSyncConfiguration configuration, string accessToken, CancellationToken cancellationToken)
    {
        var metadata = BuildMetadata(configuration, request.LocalState.MerkleHash, includeParents: true);
        var uriBuilder = new StringBuilder("files?uploadType=multipart&supportsAllDrives=true");
        var requestUri = new Uri(DriveUploadBaseUri, uriBuilder.ToString());

        using var content = CreateMultipartContent(metadata, request.Payload);
        using var httpRequest = new HttpRequestMessage(HttpMethod.Post, requestUri)
        {
            Content = content
        };
        httpRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

        using var response = await _httpClient.SendAsync(httpRequest, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
    }

    private async Task UpdateFileAsync(string fileId, VaultSyncUploadRequest request, VaultSyncConfiguration configuration, string accessToken, CancellationToken cancellationToken)
    {
        var metadata = BuildMetadata(configuration, request.LocalState.MerkleHash, includeParents: false);
        var requestUri = new Uri(DriveUploadBaseUri, $"files/{Uri.EscapeDataString(fileId)}?uploadType=multipart&supportsAllDrives=true");

        using var content = CreateMultipartContent(metadata, request.Payload);
        using var httpRequest = new HttpRequestMessage(HttpMethod.Patch, requestUri)
        {
            Content = content
        };
        httpRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

        using var response = await _httpClient.SendAsync(httpRequest, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
    }

    private static MultipartContent CreateMultipartContent(GoogleDriveFileMetadata metadata, byte[] payload)
    {
        var multipart = new MultipartContent("related");
        var metadataJson = JsonSerializer.Serialize(metadata);
        var metadataContent = new StringContent(metadataJson, Encoding.UTF8, "application/json");
        multipart.Add(metadataContent);

        var fileContent = new ByteArrayContent(payload);
        fileContent.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        multipart.Add(fileContent);

        return multipart;
    }

    private static GoogleDriveFileMetadata BuildMetadata(VaultSyncConfiguration configuration, string merkleHash, bool includeParents)
    {
        var metadata = new GoogleDriveFileMetadata
        {
            Name = GetFileName(configuration),
            AppProperties = new Dictionary<string, string>
            {
                [MerklePropertyKey] = merkleHash
            }
        };

        if (includeParents)
        {
            var folderId = GetOptionalParameter(configuration, FolderIdParameterKey);
            if (!string.IsNullOrWhiteSpace(folderId))
            {
                metadata.Parents = new List<string> { folderId! };
            }
        }

        return metadata;
    }

    private static string GetFileName(VaultSyncConfiguration configuration)
    {
        if (configuration.Parameters.TryGetValue(FileNameParameterKey, out var fileName) && !string.IsNullOrWhiteSpace(fileName))
        {
            return fileName.Trim();
        }

        return DefaultFileName;
    }

    private static string? GetOptionalParameter(VaultSyncConfiguration configuration, string key)
    {
        if (configuration.Parameters.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value))
        {
            return value.Trim();
        }

        return null;
    }

    private sealed class TokenSuccessResponse
    {
        [JsonPropertyName("access_token")]
        public string AccessToken { get; set; } = string.Empty;
    }

    private sealed class TokenErrorResponse
    {
        [JsonPropertyName("error")]
        public string? Error { get; set; }

        [JsonPropertyName("error_description")]
        public string? ErrorDescription { get; set; }
    }

    private sealed class DriveFileMetadata
    {
        [JsonPropertyName("id")]
        public string? Id { get; set; }

        [JsonPropertyName("name")]
        public string? Name { get; set; }

        [JsonPropertyName("modifiedTime")]
        public string? ModifiedTimeRaw { get; set; }

        [JsonPropertyName("size")]
        public string? SizeRaw { get; set; }

        [JsonPropertyName("headRevisionId")]
        public string? HeadRevisionId { get; set; }

        [JsonPropertyName("appProperties")]
        public Dictionary<string, string>? AppProperties { get; set; }

        [JsonPropertyName("parents")]
        public List<string>? Parents { get; set; }
    }

    private sealed class DriveFileListResponse
    {
        [JsonPropertyName("files")]
        public List<DriveFileMetadata> Files { get; set; } = new();
    }

    private sealed class GoogleDriveFileMetadata
    {
        [JsonPropertyName("name")]
        public string Name { get; set; } = DefaultFileName;

        [JsonPropertyName("appProperties")]
        public Dictionary<string, string> AppProperties { get; set; } = new();

        [JsonPropertyName("parents")]
        public List<string>? Parents { get; set; }
    }
}
