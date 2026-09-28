param(
    [Parameter(Mandatory)][string]$Apk,
    [Parameter(Mandatory)][string]$Version,
    [Parameter(Mandatory)][long]$BuildNumber,
    [Parameter(Mandatory)][string]$FingerprintFile,
    [Parameter(Mandatory)][string]$BuildTools
)
$ErrorActionPreference = 'Stop'
$signer = Join-Path $BuildTools 'apksigner.bat'
$aapt = Join-Path $BuildTools 'aapt.exe'
Write-Output "Verifying APK using Android Build Tools $(Split-Path -Leaf $BuildTools)."
$signatureOutput = (& $signer verify --verbose --print-certs $Apk) -join "`n"
if ($LASTEXITCODE -ne 0) { throw 'APK signature verification failed.' }
& (Join-Path $PSScriptRoot 'Assert-AndroidSigningCertificate.ps1') -SignatureOutput $signatureOutput `
    -ExpectedFingerprint (Get-Content -LiteralPath $FingerprintFile -Raw)
$badging = (& $aapt dump badging $Apk) -join "`n"
if ($LASTEXITCODE -ne 0) { throw 'Cannot inspect APK.' }
$package = [regex]::Match($badging, "package: name='([^']+)' versionCode='([^']+)' versionName='([^']+)'")
if (-not $package.Success -or $package.Groups[1].Value -ne 'com.companyname.passwordphraseproducer' -or
    [long]$package.Groups[2].Value -ne $BuildNumber -or $package.Groups[3].Value -ne $Version -or
    $badging.Contains('application-debuggable')) { throw 'APK identity, version or release configuration is invalid.' }
Write-Output 'Android release identity and signature verified.'
