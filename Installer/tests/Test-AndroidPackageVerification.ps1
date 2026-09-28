$ErrorActionPreference = 'Stop'
$verifyCertificate = Join-Path (Split-Path -Parent $PSScriptRoot) 'Assert-AndroidSigningCertificate.ps1'
$expected = '0123456789abcdef' * 4
$foreign = 'fedcba9876543210' * 4

# Representative --verbose --print-certs output from Build Tools 35/36 and 37.
$legacy = "Verifies`nNumber of signers: 1`nSigner #1 certificate SHA-256 digest: $expected`n"
$modern = "Verifies`nNumber of signers: 1`nV3.0 Signer: certificate SHA-256 digest: $expected`n"
$cases = @(
    @{ Name = 'Build Tools 35/36'; Output = $legacy },
    @{ Name = 'Build Tools 37'; Output = $modern },
    @{ Name = 'Windows CRLF and uppercase pinned hash'; Output = $modern.Replace("`n", "`r`n"); Pin = $expected.ToUpperInvariant() + "`r`n" },
    @{ Name = 'Same certificate in multiple schemes'; Output = $modern + "V3.1 Signer: certificate SHA-256 digest: $expected`n" },
    @{ Name = 'Foreign certificate in legacy format'; Output = $legacy.Replace($expected, $foreign); Error = 'permanent release certificate' },
    @{ Name = 'Foreign certificate in modern format'; Output = $modern.Replace($expected, $foreign); Error = 'permanent release certificate' },
    @{ Name = 'Different certificate in another scheme'; Output = $modern + "V3.1 Signer: certificate SHA-256 digest: $foreign`n"; Error = 'permanent release certificate' },
    @{ Name = 'Multiple signers'; Output = $legacy.Replace('signers: 1', 'signers: 2') + "Signer #2 certificate SHA-256 digest: $foreign`n"; Error = 'exactly one' },
    @{ Name = 'Unexpected additional signer'; Output = $legacy + "Signer #2 certificate SHA-256 digest: $expected`n"; Error = 'Unsupported or malformed' },
    @{ Name = 'Missing signer count'; Output = $legacy.Replace("Number of signers: 1`n", ''); Error = 'exactly one' },
    @{ Name = 'Duplicate signer counts'; Output = $modern + "Number of signers: 1`n"; Error = 'exactly one' },
    @{ Name = 'Missing certificate'; Output = "Verifies`nNumber of signers: 1`n"; Error = 'No APK signing certificate' },
    @{ Name = 'Public key hash is not a certificate hash'; Output = $modern.Replace('certificate SHA-256', 'public key SHA-256'); Error = 'No APK signing certificate' },
    @{ Name = 'Source stamp is not the APK signer'; Output = $modern.Replace('V3.0 Signer:', 'Source Stamp Signer:'); Error = 'Unsupported or malformed' },
    @{ Name = 'Malformed certificate hash'; Output = $modern.Replace($expected, 'abc'); Error = 'Unsupported or malformed' },
    @{ Name = 'Unknown signer format'; Output = $modern.Replace('V3.0 Signer:', 'Unknown Signer:'); Error = 'Unsupported or malformed' },
    @{ Name = 'Invalid pinned hash'; Output = $modern; Pin = 'abc'; Error = 'pinned Android signing certificate' },
    @{ Name = 'Empty verification output'; Output = ''; Error = 'exactly one' }
)

foreach ($case in $cases) {
    $pin = if ($case.ContainsKey('Pin')) { $case.Pin } else { $expected }
    $failure = $null
    try { & $verifyCertificate -SignatureOutput $case.Output -ExpectedFingerprint $pin }
    catch { $failure = $_.Exception.Message }
    if ($case.ContainsKey('Error')) {
        if (-not $failure -or -not $failure.Contains($case.Error)) {
            throw "$($case.Name): expected rejection containing '$($case.Error)', received '$failure'."
        }
    } elseif ($failure) {
        throw "$($case.Name): unexpectedly rejected: $failure"
    }
    Write-Output "PASS: $($case.Name)"
}
Write-Output "$($cases.Count) APK certificate verification tests passed."
