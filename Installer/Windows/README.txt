Password Phrase Producer - Windows Schnell-Installer
=================================================

Dieses Paket enthält eine portable Windows-Version plus einen einfachen Installations-Wrapper.
Der Installer kopiert die App in dein Benutzerprofil und legt eine Startmenü-Verknüpfung an.

Installation (empfohlen)
------------------------
1) ZIP entpacken.
2) PowerShell öffnen.
3) Im entpackten Ordner ausführen:

   PowerShell -ExecutionPolicy Bypass -File .\Install.ps1

Deinstallation
--------------
1) PowerShell öffnen.
2) Im entpackten Ordner ausführen:

   PowerShell -ExecutionPolicy Bypass -File .\Uninstall.ps1

Hinweise
--------
- Die App wird unter %LOCALAPPDATA%\PasswordPhraseProducer installiert.
- Für Updates zuerst deinstallieren oder den Installer erneut ausführen.

English quick guide
-------------------
Install:
  PowerShell -ExecutionPolicy Bypass -File .\Install.ps1

Uninstall:
  PowerShell -ExecutionPolicy Bypass -File .\Uninstall.ps1
