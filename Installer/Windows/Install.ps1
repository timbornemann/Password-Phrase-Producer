$ErrorActionPreference = 'Stop'

$appName = 'Password Phrase Producer'
$installDir = Join-Path $env:LOCALAPPDATA 'PasswordPhraseProducer'
$startMenuDir = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs'
$shortcutPath = Join-Path $startMenuDir "$appName.lnk"
$payloadDir = Join-Path $PSScriptRoot 'app'
$exePath = Join-Path $installDir 'Password Phrase Producer.exe'

if (-not (Test-Path $payloadDir)) {
  throw "Install payload not found at $payloadDir. Please unzip the package before running the installer."
}

New-Item -ItemType Directory -Force -Path $installDir | Out-Null
Copy-Item -Path (Join-Path $payloadDir '*') -Destination $installDir -Recurse -Force

$wshShell = New-Object -ComObject WScript.Shell
$shortcut = $wshShell.CreateShortcut($shortcutPath)
$shortcut.TargetPath = $exePath
$shortcut.WorkingDirectory = $installDir
$shortcut.IconLocation = $exePath
$shortcut.Save()

Write-Host "Installed $appName to $installDir"
Write-Host "Start Menu shortcut created at $shortcutPath"
Write-Host "Launching $appName..."
Start-Process -FilePath $exePath
