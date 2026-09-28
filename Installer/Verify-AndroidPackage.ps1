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
$signatureOutput = (& $signer verify --verbose --print-certs $Apk) -join "`n"
if ($LASTEXITCODE -ne 0) { throw 'APK signature verification failed.' }
$certificateMatches = [regex]::Matches($signatureOutput, 'Signer #\d+ certificate SHA-256 digest: ([a-fA-F0-9]+)')
if ($certificateMatches.Count -ne 1 -or $certificateMatches[0].Groups[1].Value -ne (Get-Content -LiteralPath $FingerprintFile -Raw).Trim()) {
    throw 'APK is not signed with the permanent release certificate.'
}
$badging = (& $aapt dump badging $Apk) -join "`n"
if ($LASTEXITCODE -ne 0) { throw 'Cannot inspect APK.' }
$package = [regex]::Match($badging, "package: name='([^']+)' versionCode='([^']+)' versionName='([^']+)'")
if (-not $package.Success -or $package.Groups[1].Value -ne 'com.companyname.passwordphraseproducer' -or
    [long]$package.Groups[2].Value -ne $BuildNumber -or $package.Groups[3].Value -ne $Version -or
    $badging.Contains('application-debuggable')) { throw 'APK identity, version or release configuration is invalid.' }
Write-Output 'Android release identity and signature verified.'
