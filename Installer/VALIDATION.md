# Update feature validation — 2026-09-28

Initial local candidate: **2.5.8 / Android versionCode 158**. These original test packages predate the follow-up
change to manually versioned release events; publish a new tag to obtain that updated implementation.
No GitHub release has been published by this implementation task.

| Check | Result |
| --- | --- |
| .NET SDK | 9.0.308, installed in a separate local build directory; no framework migration |
| Update/core automated tests | 49 passed, 0 failed, 0 skipped |
| Release orchestration tests | 14 passed, covering manual versions, retry safety, duplicate events, withdrawal and final-signature publication |
| Manual-version platform builds | Windows and Android Release builds passed with version 2.6.0 and internal build 2006000; Android manifest values inspected |
| Windows Release publish | Passed, win-x64, .NET and Windows App SDK self-contained |
| Velopack packaging | Passed with 1.2.158; Setup EXE and full NUPKG produced |
| Android Release publish | Passed with JDK 17 and Android SDK 35 |
| APK inspection | Package ID, version name/code, non-debuggable configuration and permanent signing certificate verified using aapt/apksigner |
| Complete manifest | P-256/SHA-256 signature verified; all three final package sizes and SHA-256 hashes verified |
| Release workflow | actionlint passed |
| Repository checks | git diff --check passed; no private key or keystore files included |

The local distributable files are in `artifacts/ready-release-2.5.8/` (ignored by Git). That directory contains only
Setup, the full update package, the signed APK, the manifest and its detached signature. It contains no portable ZIP.

The automated suite covers signature/platform/version rejection, interrupted or tampered downloads, low storage,
metered network changes, six-hour throttling, concurrent calls, cached/offline installs, cancellation, post-restart
installation confirmation and the data-operation barrier. It includes nested-operation failures and expired async
contexts. It also runs the production app-lock/file encryption with a simulated secure store across replacement
service instances and checks unchanged data fixtures across consecutive and skipped versions.

The release-event revision additionally tests an incomplete newer release alongside an older complete release,
upload states, missing metadata/package assets, metadata CDN 404s, pagination, numeric release ordering and invalid
signatures. The publication tests use a simulated GitHub API and verify that remote package validation happens
before the signature upload. No test release was created in the real repository.

These tests do not prove OS-keystore, biometric or native installer persistence. The Windows 10/11 installation,
repair and two-update scenarios, Android API 21/26/current-device scenarios and a physical Android device remain
required before production acceptance. Follow the checklist in [UPDATES.md](UPDATES.md#validation).

An isolated Android API 37 / 16 KB AVD was created without using the existing personal AVD. The installed emulator
36.5.11 did not reach an online/boot-completed state during the smoke-test attempt, so no runtime result is claimed.
The pre-existing SkiaSharp.NativeAssets.Android 2.88.8 dependency also emits XA0141 for 16 KB page alignment during
Android publish. Validation on 16 KB devices, and any necessary graphics dependency upgrade, remains open.

Permanent signing secrets are configured in GitHub. Encrypted local recovery material is outside the repository
at `%LOCALAPPDATA%\PasswordPhraseProducerSigning`; protect an independent offline backup and retain recovery
passwords as described in [UPDATES.md](UPDATES.md#release-inputs).
