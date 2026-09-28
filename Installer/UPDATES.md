# Update delivery and recovery

## User behavior

Windows x64 uses a per-user Velopack Setup. Android uses an APK and the system PackageInstaller.
The app checks stable releases when opened/resumed, at most once every six hours automatically.
Automatic downloads wait for an unmetered connection. Manual downloads also work on metered connections.
Downloaded updates never install on startup or exit: installation requires the user's button click.
Android additionally requires permission to install from this source and its system confirmation.
An installation attempt is recorded before handing control to the native installer. The next launch confirms
success from the actual installed version; an interrupted attempt remains available for an explicit retry.
No background service checks for updates while the app is closed.

## First transition

Existing Windows ZIP/PowerShell installations reuse the same MAUI data and settings paths. Close the old app,
then install Setup. Historical MSIX users must export/import once because their package storage is separate.

Older Android releases did not use a persistent release keystore. Installed APKs may have been signed with a
runner's temporary debug key. If Android rejects the first new APK's signature, export all data from the old app,
uninstall it once, install the signed baseline, and import the export. For the owner this backup already exists.
After that transition every APK must keep the same package ID and signing certificate. Never advise uninstalling
as a routine update fix. A signature mismatch in subsequent releases is a release error.

## Release inputs

- The SDK stays on .NET 9; `global.json` selects 9.0.308. MAUI libraries are pinned to 9.0.111.
- Velopack NuGet and `.config/dotnet-tools.json` both pin 1.2.158.
- `ANDROID_KEYSTORE_BASE64`, `ANDROID_KEYSTORE_PASSWORD`, `ANDROID_KEY_ALIAS`, `ANDROID_KEY_PASSWORD`
  contain the permanent Android key. `AndroidKeyStore=true` is mandatory.
- `UPDATE_SIGNING_PRIVATE_KEY` contains the ECDSA P-256 PKCS#8 PEM private key.
- `Resources/UpdateSigningPublicKey.pem` pins its public key; `Resources/AndroidSigningCertificate.sha256`
  pins the Android release certificate. Both public files are safe to commit. Private material is not.

`ReleaseTools provision <public-key-path> <private-backup-directory> <keytool-path>` is an explicit Windows-only
bootstrap/recovery command. It creates keys only if no key exists, protects the directory with the current user's
ACL, saves an encrypted recovery bundle, and uploads secrets over stdin to this repository using authenticated `gh`.
Rerunning with the same backup reuses the keys. It refuses to replace an existing public key with a new private key.

For this workspace the encrypted recovery directory is `%LOCALAPPDATA%\PasswordPhraseProducerSigning`.
It contains an encrypted Android PKCS#12 keystore, an encrypted ECDSA PKCS#8 file and `release-secrets.dpapi`.
**The DPAPI bundle requires the original Windows account/profile.** Preserve that profile or recover the passwords
on that account and save them separately in your password manager before replacing the computer. Copy the encrypted
key files to your own offline backup. Do not put them or recovered passwords into Git, logs, issues or chat.

Changing either release key breaks existing update trust. A future key rotation needs an explicit transition
release signed with the old key; generating a new key on every build is prohibited.

## Publication

**A push never publishes or packages a version.** Only publishing a normal GitHub release, or promoting a release
to stable, starts the packaging workflow. Drafts and prereleases are excluded. Pull requests run unit tests only.

1. Commit and push the desired source changes to `main`, including the updated workflows before the first release.
2. Open GitHub Releases, choose **Draft a new release**, and create your own version tag, for example `v2.6.0`.
   Select the commit you want to ship and enter your title and release notes. Do not mark it as a prerelease.
3. Click **Publish release**. Merely saving a draft does not start GitHub Actions
   ([GitHub release-event documentation](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#release)).
4. Wait for **Build Android and Windows Packages** to finish. It builds the exact tagged commit, runs the tests,
   signs both platforms, verifies the APK identity/version/certificate and signs the manifest. The release notes
   you entered are included in the signed manifest (up to 16,000 characters); your title/body stay unchanged.
5. The workflow attaches the packages to this same release. Download `*-Setup.exe` or `*_android_signed.apk`.
   Existing update-capable apps will find the release on their next check; a manual check can be run immediately.

The tag must be `MAJOR.MINOR.PATCH`, optionally preceded by `v`. Both `2.6.0` and `v2.6.0` produce app version
`2.6.0`; they represent the same version and cannot both be published as separate versions. Versions must increase.
Android's internal versionCode is derived solely from this chosen version:
`MAJOR * 1,000,000 + MINOR * 1,000 + PATCH` (`v2.6.0` => `2006000`). It does not depend on a workflow run counter.
The supported ranges are major 0..2099 and minor/patch 0..999, excluding 0.0.0. This keeps versionCode monotonic
and within Android's limit, including the transition from the old run-number-based builds.

The release page and GitHub's automatic source-code archives can already be visible while the build runs.
Application packages are uploaded only after both builds and all local checks succeed. The workflow downloads
those remote assets again and verifies their actual bytes. It uploads **`update-manifest.sig` last**, making the
complete release eligible for in-app updates. No ready signature is added after a failed build/upload/verification.

If a run fails, fix build infrastructure/secrets and use **Re-run failed jobs** in Actions. Incomplete assets from
that attempt can be replaced; unrelated attachments are preserved. A release with a ready signature is sealed by
the workflow and cannot be overwritten by retries or duplicate events. If source changes are needed, create a new
tag/version instead of moving an existing tag. Previously published legacy releases cannot be rebuilt in place.
GitHub's optional release immutability must remain disabled for this workflow because it attaches assets after
the user publishes the release; an immutable release is rejected before building.

`UPDATE_RELEASE_NOTES_FILE` supplies notes to local `ReleaseTools manifest` runs. `UPDATE_RELEASE_TAG` supplies
the exact selected tag; when omitted for a local run, the tool defaults to `v` plus the supplied app version.

`update-manifest.json` schema 1 uses UTF-8 and camelCase fields: `schemaVersion`, `version`, `buildNumber`,
`releaseTag`, `notes`, `artifacts`. Exactly three artifacts are required: windows/x64/full, windows/x64/installer,
android/universal/apk. Each has `platform`, `architecture`, `kind`, `fileName`, `size`, `sha256`.
`update-manifest.sig` is a detached 64-byte IEEE P1363 ECDSA P-256/SHA-256 signature over the exact manifest bytes.
Reserializing the manifest invalidates its signature. APK/NUPKG/EXE hashes cover the final published files.

The client lists GitHub's public releases (bounded to 500 entries), sorts stable versions numerically and chooses
the highest complete release. A pending newer release does not hide the previous complete release, and missing or
still-uploading assets are ignored without an update error. Both metadata files and all three packages must be
fully uploaded with the expected sizes. The manifest signature is then verified. Downloads use only the verified
release tag in this fixed repository. No GitHub token is shipped in the app. Windows uses a
custom Velopack source that exposes only the selected verified full package. Delta packages and portable ZIPs are
not distributed. Signatures and file hashes are checked again before installation, including cached files.

Release and app versions are entirely selected by the maintainer; nothing increments on a push or retry.

## Validation

See [VALIDATION.md](VALIDATION.md) for the implementation's completed checks and outstanding device acceptance.

Run `dotnet test PasswordPhraseProducer.Updates.Tests/PasswordPhraseProducer.Updates.Tests.csproj -c Release`.
Run `python -m unittest discover -s Installer/tests -v` to test release sequencing, retries and tag-based versioning.
For platform builds, use `-p:PppTargetFramework=net9.0-android` or
`-p:PppTargetFramework=net9.0-windows10.0.19041.0`, together with the same `-f` value. Android requires JDK 17 and SDK 35.

Automated tests exercise real app-lock/file encryption with a stand-in secure store, update signatures, tampering,
network policy, disk space, cancellation, throttling, restart recovery, concurrent requests and the data-operation barrier.
They do **not** replace operating-system installation tests or prove Android Keystore/Windows Hello persistence.

Before production rollout, use disposable test profiles/devices and an isolated release feed:

1. Populate both vaults, TOTP, app/vault passwords, biometrics, preferences and a sync connection in the baseline.
2. Install two successive signed updates and a skipped-version update; verify every original password and entry.
3. On Windows 10/11, test initial ZIP migration, non-admin Setup, pending updates across restart and Setup repair.
4. On Android API 21, API 26 and a current device, test unknown-source permission, refusal, cancellation, process
   replacement and mismatching signatures. Check persisted sync URI permissions and biometric access.
5. Interrupt download, remove network access, switch to metered access, exhaust disk space and simulate failed writes.
   Installation must not proceed after a failed or timed-out data operation. Existing user data must remain intact.

The startup guard blocks fresh setup when existing encrypted files have missing/corrupt app-key metadata. It never
deletes files or resets keys. Before applying an update, the operation barrier blocks new writes and drains existing
vault/security/sync operations for up to 30 seconds. File writes use temporary files and replacement without changing
the encryption format. Automatic rollback of a broken application version is not claimed; Setup can repair program
files while preserving user data.
