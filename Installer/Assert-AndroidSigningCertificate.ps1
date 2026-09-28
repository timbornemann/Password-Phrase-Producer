param(
    [Parameter(Mandatory)][AllowEmptyString()][string]$SignatureOutput,
    [Parameter(Mandatory)][AllowEmptyString()][string]$ExpectedFingerprint
)
$ErrorActionPreference = 'Stop'
$expected = $ExpectedFingerprint.Trim()
if ($expected -notmatch '\A[a-fA-F0-9]{64}\z') {
    throw 'The pinned Android signing certificate must be a SHA-256 fingerprint (64 hexadecimal characters).'
}

$signerCounts = [regex]::Matches($SignatureOutput, '(?m)^Number of signers: ([0-9]+)[ \t]*\r?$')
if ($signerCounts.Count -ne 1 -or $signerCounts[0].Groups[1].Value -ne '1') {
    throw 'APK must have exactly one signing certificate; apksigner did not report a single signer.'
}

# Build Tools 35/36 print "Signer #1"; 37 prints scheme labels such as "V3.0 Signer:".
# Check every certificate line so an additional or unrecognised signer cannot be ignored.
$certificateLines = [regex]::Matches($SignatureOutput, '(?m)^[^\r\n]* certificate SHA-256 digest:[^\r\n]*\r?$')
if ($certificateLines.Count -eq 0) {
    throw 'No APK signing certificate SHA-256 fingerprint was found in apksigner output.'
}
$certificatePattern = '\A(?:Signer #1|V[1-4](?:\.[0-9]+)? Signer(?: #1)?):? certificate SHA-256 digest: ([a-fA-F0-9]{64})[ \t]*\r?\z'
foreach ($line in $certificateLines) {
    $certificate = [regex]::Match($line.Value, $certificatePattern)
    if (-not $certificate.Success) {
        throw 'Unsupported or malformed APK signing certificate output from apksigner.'
    }
    $actual = $certificate.Groups[1].Value
    if (-not [string]::Equals($actual, $expected, [StringComparison]::OrdinalIgnoreCase)) {
        throw "APK is not signed with the permanent release certificate. Expected SHA-256: $expected; actual: $actual."
    }
}
