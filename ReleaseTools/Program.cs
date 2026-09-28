using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using PasswordPhraseProducer.Updates;

if (args.Length == 0) throw new ArgumentException("Commands: manifest, verify, provision");
switch (args[0])
{
    case "manifest":
    {
        // manifest <version> <build> <directory> <public-key-path>
        var directory = Path.GetFullPath(args[3]);
        using var key = ECDsa.Create();
        key.ImportFromPem(Environment.GetEnvironmentVariable("UPDATE_SIGNING_PRIVATE_KEY")
            ?? throw new InvalidOperationException("UPDATE_SIGNING_PRIVATE_KEY is required."));
        using var expectedKey = ECDsa.Create();
        expectedKey.ImportFromPem(File.ReadAllText(args[4]));
        if (!key.ExportSubjectPublicKeyInfo().SequenceEqual(expectedKey.ExportSubjectPublicKeyInfo()))
            throw new InvalidOperationException("Signing key does not match the app's pinned public key.");
        var artifacts = new List<UpdateArtifact>();
        foreach (var (pattern, platform, architecture, kind) in new[]
        {
            ("*-full.nupkg", "windows", "x64", "full"),
            ("*-Setup.exe", "windows", "x64", "installer"),
            ("*_android_signed.apk", "android", "universal", "apk")
        })
        {
            var path = Directory.GetFiles(directory, pattern).Single();
            await using var stream = File.OpenRead(path);
            artifacts.Add(new UpdateArtifact { Platform = platform, Architecture = architecture, Kind = kind,
                FileName = Path.GetFileName(path), Size = stream.Length, Sha256 = Convert.ToHexString(await SHA256.HashDataAsync(stream)) });
        }
        var notesPath = Environment.GetEnvironmentVariable("UPDATE_RELEASE_NOTES_FILE");
        var notes = string.IsNullOrWhiteSpace(notesPath) ? $"Password Phrase Producer {args[1]}" : await File.ReadAllTextAsync(notesPath);
        var manifest = new UpdateManifest { Version = args[1], BuildNumber = long.Parse(args[2]),
            ReleaseTag = Environment.GetEnvironmentVariable("UPDATE_RELEASE_TAG") ?? "v" + args[1],
            Notes = notes,
            Artifacts = artifacts.ToArray() };
        ReleaseVerifier.ValidateManifest(manifest);
        var bytes = JsonSerializer.SerializeToUtf8Bytes(manifest, ReleaseVerifier.JsonOptions);
        await File.WriteAllBytesAsync(Path.Combine(directory, UpdateIdentity.ManifestName), bytes);
        await File.WriteAllBytesAsync(Path.Combine(directory, UpdateIdentity.SignatureName),
            key.SignData(bytes, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
        Console.WriteLine("Release manifest signed.");
        break;
    }
    case "verify":
    {
        var directory = Path.GetFullPath(args[1]);
        var verifier = new ReleaseVerifier(File.ReadAllText(args[2]));
        var signed = verifier.Verify(File.ReadAllBytes(Path.Combine(directory, UpdateIdentity.ManifestName)),
            File.ReadAllBytes(Path.Combine(directory, UpdateIdentity.SignatureName)));
        foreach (var artifact in signed.Manifest.Artifacts)
            await ReleaseVerifier.VerifyPackageAsync(Path.Combine(directory, artifact.FileName), artifact, default);
        Console.WriteLine($"Verified release {signed.Manifest.Version}, build {signed.Manifest.BuildNumber}.");
        break;
    }
    case "provision":
    {
        // Windows-only, explicit one-time operation. Re-running reuses the encrypted backup.
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        var publicPath = Path.GetFullPath(args[1]);
        var backupDirectory = Path.GetFullPath(args[2]);
        Directory.CreateDirectory(backupDirectory);
        await Run("icacls.exe", [backupDirectory, "/inheritance:r", "/grant:r", $"{Environment.UserDomainName}\\{Environment.UserName}:(OI)(CI)F"]);
        var backupPath = Path.Combine(backupDirectory, "release-secrets.dpapi");
        Dictionary<string, string> secrets;
        if (File.Exists(backupPath))
        {
            var decoded = ProtectedData.Unprotect(File.ReadAllBytes(backupPath), null, DataProtectionScope.CurrentUser);
            try { secrets = JsonSerializer.Deserialize<Dictionary<string, string>>(decoded)!; }
            finally { CryptographicOperations.ZeroMemory(decoded); }
        }
        else
        {
            if (File.Exists(publicPath)) throw new InvalidOperationException("A public key already exists. Recover its private-key backup instead of rotating keys.");
            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var password = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
            var keystore = Path.Combine(backupDirectory, "android-release.keystore");
            if (File.Exists(keystore)) throw new InvalidOperationException("An existing keystore must not be overwritten.");
            await Run(args[3], ["-genkeypair", "-keystore", keystore, "-storetype", "PKCS12", "-alias", "ppp-release",
                "-keyalg", "RSA", "-keysize", "3072", "-sigalg", "SHA256withRSA", "-validity", "36500",
                "-dname", "CN=Password Phrase Producer", "-storepass:env", "PPP_SIGNING_PASSWORD", "-keypass:env", "PPP_SIGNING_PASSWORD"],
                environment: new() { ["PPP_SIGNING_PASSWORD"] = password });
            secrets = new()
            {
                ["ANDROID_KEYSTORE_BASE64"] = Convert.ToBase64String(File.ReadAllBytes(keystore)),
                ["ANDROID_KEYSTORE_PASSWORD"] = password,
                ["ANDROID_KEY_ALIAS"] = "ppp-release",
                ["ANDROID_KEY_PASSWORD"] = password,
                ["UPDATE_SIGNING_PRIVATE_KEY"] = key.ExportPkcs8PrivateKeyPem()
            };
            var clear = JsonSerializer.SerializeToUtf8Bytes(secrets);
            try { File.WriteAllBytes(backupPath, ProtectedData.Protect(clear, null, DataProtectionScope.CurrentUser)); }
            finally { CryptographicOperations.ZeroMemory(clear); }
            File.WriteAllText(Path.Combine(backupDirectory, "update-private-key.encrypted.pem"),
                key.ExportEncryptedPkcs8PrivateKeyPem(password, new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 600000)));
            Directory.CreateDirectory(Path.GetDirectoryName(publicPath)!);
            File.WriteAllText(publicPath, key.ExportSubjectPublicKeyInfoPem());
        }
        using (var key = ECDsa.Create())
        {
            key.ImportFromPem(secrets["UPDATE_SIGNING_PRIVATE_KEY"]);
            if (!File.Exists(publicPath)) File.WriteAllText(publicPath, key.ExportSubjectPublicKeyInfoPem());
            using var pinned = ECDsa.Create();
            pinned.ImportFromPem(File.ReadAllText(publicPath));
            if (!pinned.ExportSubjectPublicKeyInfo().SequenceEqual(key.ExportSubjectPublicKeyInfo()))
                throw new InvalidOperationException("Backup does not match the pinned public key.");
        }
        using (var certificate = System.Security.Cryptography.X509Certificates.X509CertificateLoader.LoadPkcs12(
            Convert.FromBase64String(secrets["ANDROID_KEYSTORE_BASE64"]), secrets["ANDROID_KEYSTORE_PASSWORD"],
            System.Security.Cryptography.X509Certificates.X509KeyStorageFlags.EphemeralKeySet))
        {
            var fingerprintPath = Path.Combine(Path.GetDirectoryName(publicPath)!, "AndroidSigningCertificate.sha256");
            var fingerprint = Convert.ToHexString(SHA256.HashData(certificate.RawData));
            if (File.Exists(fingerprintPath) && File.ReadAllText(fingerprintPath).Trim() != fingerprint)
                throw new InvalidOperationException("The Android signing certificate has changed.");
            File.WriteAllText(fingerprintPath, fingerprint + Environment.NewLine);
        }
        foreach (var secret in secrets)
            await Run("gh", ["secret", "set", secret.Key, "--repo", UpdateIdentity.Repository], secret.Value);
        Console.WriteLine("Signing secrets configured. Encrypted recovery material: " + backupDirectory);
        break;
    }
    default: throw new ArgumentException("Unknown command.");
}

static async Task Run(string executable, string[] arguments, string? input = null, Dictionary<string, string>? environment = null)
{
    var info = new ProcessStartInfo(executable) { UseShellExecute = false, CreateNoWindow = true,
        RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true };
    foreach (var argument in arguments) info.ArgumentList.Add(argument);
    if (environment is not null) foreach (var entry in environment) info.Environment[entry.Key] = entry.Value;
    using var process = Process.Start(info) ?? throw new InvalidOperationException("Cannot start required tool.");
    var stdout = process.StandardOutput.ReadToEndAsync();
    var stderr = process.StandardError.ReadToEndAsync();
    if (input is not null) await process.StandardInput.WriteAsync(input);
    process.StandardInput.Close();
    await process.WaitForExitAsync();
    await Task.WhenAll(stdout, stderr);
    // Secret input and environment variables must never appear in diagnostic output.
    if (process.ExitCode != 0) throw new InvalidOperationException($"{Path.GetFileName(executable)} failed (exit {process.ExitCode}).");
}
