using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Amazon;
using Amazon.Runtime;
using Amazon.S3;
using Amazon.S3.Model;

namespace Password_Phrase_Producer.Services.Vault.Sync;

public sealed class S3VaultSyncProvider : IVaultSyncProvider
{
    public const string ProviderKey = "S3";
    public const string BucketParameterKey = "bucket";
    public const string ObjectKeyParameterKey = "objectKey";
    public const string RegionParameterKey = "region";
    public const string AccessKeyIdParameterKey = "accessKeyId";
    public const string SecretAccessKeyParameterKey = "secretAccessKey";
    private const string MerkleMetadataKey = "vault-merkle-hash";

    public string Key => ProviderKey;

    public string DisplayName => "Amazon S3";

    public bool SupportsAutomaticSync => true;

    public Task<bool> IsConfiguredAsync(VaultSyncConfiguration configuration, CancellationToken cancellationToken = default)
    {
        var isConfigured = configuration.Parameters.TryGetValue(BucketParameterKey, out var bucket) && !string.IsNullOrWhiteSpace(bucket)
            && configuration.Parameters.TryGetValue(ObjectKeyParameterKey, out var objectKey) && !string.IsNullOrWhiteSpace(objectKey)
            && configuration.Parameters.TryGetValue(RegionParameterKey, out var region) && !string.IsNullOrWhiteSpace(region)
            && configuration.Parameters.TryGetValue(AccessKeyIdParameterKey, out var accessKeyId) && !string.IsNullOrWhiteSpace(accessKeyId)
            && configuration.Parameters.TryGetValue(SecretAccessKeyParameterKey, out var secret) && !string.IsNullOrWhiteSpace(secret);

        return Task.FromResult(isConfigured);
    }

    public async Task<VaultSyncRemoteState?> GetRemoteStateAsync(VaultSyncConfiguration configuration, CancellationToken cancellationToken = default)
    {
        if (!await IsConfiguredAsync(configuration, cancellationToken).ConfigureAwait(false))
        {
            return null;
        }

        using var client = CreateClient(configuration);
        var request = new GetObjectMetadataRequest
        {
            BucketName = configuration.Parameters[BucketParameterKey],
            Key = configuration.Parameters[ObjectKeyParameterKey]
        };

        try
        {
            var response = await client.GetObjectMetadataAsync(request, cancellationToken).ConfigureAwait(false);
            return new VaultSyncRemoteState
            {
                LastModifiedUtc = response.LastModified.ToUniversalTime(),
                ContentLength = response.Headers.ContentLength,
                MerkleHash = response.Metadata[$"x-amz-meta-{MerkleMetadataKey}"] ?? string.Empty,
                EntityTag = response.ETag
            };
        }
        catch (AmazonS3Exception ex) when (string.Equals(ex.ErrorCode, "NotFound", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }
    }

    public async Task<VaultSyncDownloadResult?> DownloadAsync(VaultSyncConfiguration configuration, CancellationToken cancellationToken = default)
    {
        if (!await IsConfiguredAsync(configuration, cancellationToken).ConfigureAwait(false))
        {
            return null;
        }

        using var client = CreateClient(configuration);
        var request = new GetObjectRequest
        {
            BucketName = configuration.Parameters[BucketParameterKey],
            Key = configuration.Parameters[ObjectKeyParameterKey]
        };

        try
        {
            using var response = await client.GetObjectAsync(request, cancellationToken).ConfigureAwait(false);
            await using var memoryStream = new MemoryStream();
            await response.ResponseStream.CopyToAsync(memoryStream, cancellationToken).ConfigureAwait(false);
            var payload = memoryStream.ToArray();
            return new VaultSyncDownloadResult
            {
                Payload = payload,
                RemoteState = new VaultSyncRemoteState
                {
                    LastModifiedUtc = response.LastModified.ToUniversalTime(),
                    ContentLength = payload.LongLength,
                    MerkleHash = response.Metadata[$"x-amz-meta-{MerkleMetadataKey}"] ?? string.Empty,
                    EntityTag = response.ETag
                }
            };
        }
        catch (AmazonS3Exception ex) when (string.Equals(ex.ErrorCode, "NotFound", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }
    }

    public async Task UploadAsync(VaultSyncUploadRequest request, VaultSyncConfiguration configuration, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!await IsConfiguredAsync(configuration, cancellationToken).ConfigureAwait(false))
        {
            throw new InvalidOperationException("Die S3-Synchronisation ist nicht vollständig konfiguriert.");
        }

        using var client = CreateClient(configuration);
        var bucketName = configuration.Parameters[BucketParameterKey];
        var objectKey = configuration.Parameters[ObjectKeyParameterKey];

        if (request.RemoteStateBeforeUpload is not null)
        {
            var metadataRequest = new GetObjectMetadataRequest
            {
                BucketName = bucketName,
                Key = objectKey
            };

            try
            {
                var metadataResponse = await client.GetObjectMetadataAsync(metadataRequest, cancellationToken).ConfigureAwait(false);
                var currentHash = metadataResponse.Metadata[$"x-amz-meta-{MerkleMetadataKey}"] ?? string.Empty;
                if (!string.Equals(currentHash, request.RemoteStateBeforeUpload.MerkleHash, StringComparison.Ordinal))
                {
                    throw new InvalidOperationException("Der entfernte Tresor wurde seit der letzten Synchronisation verändert.");
                }
            }
            catch (AmazonS3Exception ex) when (string.Equals(ex.ErrorCode, "NotFound", StringComparison.OrdinalIgnoreCase))
            {
                // Objekt existiert nicht mehr, Upload kann fortgesetzt werden.
            }
        }

        using var payloadStream = new MemoryStream(request.Payload, writable: false);
        var putRequest = new PutObjectRequest
        {
            BucketName = bucketName,
            Key = objectKey,
            InputStream = payloadStream,
            AutoCloseStream = false
        };
        putRequest.Metadata.Add(MerkleMetadataKey, request.LocalState.MerkleHash);
        putRequest.Headers.ContentType = "application/octet-stream";

        await client.PutObjectAsync(putRequest, cancellationToken).ConfigureAwait(false);
    }

    private static IAmazonS3 CreateClient(VaultSyncConfiguration configuration)
    {
        var region = RegionEndpoint.GetBySystemName(configuration.Parameters[RegionParameterKey]);
        var credentials = new BasicAWSCredentials(configuration.Parameters[AccessKeyIdParameterKey], configuration.Parameters[SecretAccessKeyParameterKey]);
        return new AmazonS3Client(credentials, region);
    }
}
