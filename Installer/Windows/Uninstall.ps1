$ErrorActionPreference = 'Stop'

$appName = 'Password Phrase Producer'
$installDir = Join-Path $env:LOCALAPPDATA 'PasswordPhraseProducer'
$startMenuDir = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs'
$shortcutPath = Join-Path $startMenuDir "$appName.lnk"

if (Test-Path $shortcutPath) {
  Remove-Item -Path $shortcutPath -Force
  Write-Host "Removed Start Menu shortcut."
}

if (Test-Path $installDir) {
  Remove-Item -Path $installDir -Recurse -Force
  Write-Host "Removed install directory at $installDir."
} else {
  Write-Host "Install directory not found at $installDir."
}
