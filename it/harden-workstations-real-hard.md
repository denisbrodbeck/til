---
title: "Harden Windows 10 workstations real hard with AppLocker and MS Security Baseline"
date: 2019-11-26T17:43:44+01:00
tags: ["os", "it", "security"]
---

## Requirements

* Windows 10 Enterprise (provides AppLocker)
* Users shall not have adminstrative permissions on workstations

## Scenario

* All workstations have Windows 10 Enterprise >= Version 1903 installed
* All users will work with normal (_non-admin_) privileges
* Active Directory is _not_ available (think small shop with < 10 Employees)
* No local MS Office package installed: users use modern browsers with O365 / G Suite

> There are additional _security baslines_ available for local installations of Office 365. Please _do_ apply them, they'll enhance your protection against legacy file types and macro malware.

## Setup

### Install Windows 10 Enterprise

Install Windows 10 Enterprise the usual way and create your first local (admin) user via the onboarding wizard.

> Install and configure all the software the user needs (Office / LibreOffice / Printer Software / Chrome / Firefox / MS Teams / Remote Desktop Tool/ PDF Viewer / etc.)

Download the following items:

* [Windows 10 Version 1909 Security Baseline + LGPO.zip](https://www.microsoft.com/en-us/download/details.aspx?id=55319)
* [Microsoft/AaronLocker](https://github.com/microsoft/AaronLocker/archive/master.zip)

```powershell
cd $env:USERPROFILE\Downloads
$oldProgressPreference = $progressPreference;
$progressPreference = 'SilentlyContinue';
Invoke-WebRequest -Uri https://github.com/microsoft/AaronLocker/archive/master.zip -OutFile Aaronlocker.zip
$progressPreference = $oldProgressPreference
Expand-Archive -Path ".\AaronLocker.zip" -DestinationPath .\aaronlocker -Force
Expand-Archive -Path ".\*Security Baseline*.zip" -DestinationPath ".\security-baseline" -Force
Expand-Archive -Path .\LGPO.zip -DestinationPath ".\security-baseline\Scripts\Tools\" -Force
```

Run an administrative `powershell` (`win+x` --> `Windows PowerShell (Administrator)`):

```powershell
# (optional) rename host and restart
Rename-Computer -NewName 'desktop-001' -Restart -Force
```

### Setup Security Baseline

After _reboot_ start a new administrative powershell session:

```powershell
# bypass execution policy for this session only
Set-ExecutionPolicy Bypass -Scope Process

# create new local admin user
New-LocalUser "admin" -FullName "Admin User" -Description "Local admin user" -AccountNeverExpires -PasswordNeverExpires
# SID of local group `users` is S-1-5-32-545 (OS language independent)
Add-LocalGroupMember -SID "S-1-5-32-545" -Member "$env:USERNAME"
# SID of local group `administrators` is S-1-5-32-544 (OS language independent)
Add-LocalGroupMember -SID "S-1-5-32-544" -Member "admin"
Remove-LocalGroupMember -SID "S-1-5-32-544" -Member "$env:USERNAME"
cd $env:USERPROFILE\Downloads
# apply security baseline
.\security-baseline\Scripts\Baseline-LocalInstall.ps1 -Win10NonDomainJoined

# (optional) modify/override applied settings via local group policies
# e.g. set 'User Account Control: Behavior of the elevation prompt for standard users' to 'Prompt for credentials on the secure desktop', though this reduces security (because of caching of admin credentials on user workstations - see mimikatz and pass-the-ticket attacks https://www.varonis.com/blog/what-is-mimikatz/)
# e.g. requiring bitlocker encryption of external devices (usb-stick) might be too much
gpedit.msc
```

### Setup AppLocker

```powershell
cd "$env:USERPROFILE\Downloads\aaronlocker\AaronLocker\AaronLocker"
.\Support\DownloadAccesschk.ps1
.\Create-Policies.ps1
# (optional) Modify policies (example):
# allow AnyDesk publisher
# Invoke-WebRequest -Uri https://download.anydesk.com/AnyDesk.exe -OutFile $env:ProgramFiles\AnyDesk.exe
# add to `CustomizationInputs\TrustedSigners.ps1`
# @{
#   label = "Trust the publisher of AnyDesk.exe";
#   exemplar = "$env:ProgramFiles\AnyDesk.exe";
# }

# update policies after modifying the rules
.\Create-Policies.ps1
# configure workstation for AppLocker
.\LocalConfiguration\ConfigureForAppLocker.ps1
# enforce AppLocker rules
.\LocalConfiguration\ApplyPolicyToLocalGPO.ps1
# use it
Restart-Computer -Force
```

## Links

* [Microsoft Security Baselines Blog](https://techcommunity.microsoft.com/t5/Microsoft-Security-Baselines/bg-p/Microsoft-Security-Baselines)
* [Security baseline for Office 365 ProPlus (v1908, Sept 2019)](https://techcommunity.microsoft.com/t5/Microsoft-Security-Baselines/Security-baseline-for-Office-365-ProPlus-v1908-Sept-2019-FINAL/ba-p/873084)
* [Security baseline (Sept2019Update) for Windows 10 v1909 and Windows Server](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-final-for-windows-10-v1909-and-windows-server/ba-p/1023093)
* [Microsoft Security Compliance Toolkit](https://www.microsoft.com/en-us/download/details.aspx?id=55319)
