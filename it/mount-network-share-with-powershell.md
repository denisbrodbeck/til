# Mount network shares with powershell

**WARN** Using hard credentials is very insecure - the share should be mounted using the current user's windows credentials.

```ps1
# UNC path to shared drive
$UNC = '\\8.8.8.8\share'
$Description = "Shared Office Drive"
# Credentials for UNC path
$User = "userXYZ"
$Pass = "secrethouseparty"
# Log everything into user's temp folder (windows/user cleans up this up)
$LogFile = "$($env:TEMP)\it_shared_drive.log"  # --> C:\Users\UserA\AppData\Local\Temp\it_shared_drive.log

function LogError {
    param([string]$message)

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    Write-Error ($timestamp + " | " + $message)
    ($timestamp + " | ERROR | " + $message) >> $LogFile;
}

try {
    # create PSCredential
    $creds = New-Object System.Management.Automation.PSCredential -ArgumentList $User, ($Pass | ConvertTo-SecureString -AsPlainText -Force)
    # `New-PSDrive` needs the flag `-Scope Global` when running from a script
    # Provide `-ErrorAction Stop` in order to catch the error
    New-PSDrive -Name "N" -PSProvider "FileSystem" -Root "$UNC" -Description "$Description" -Credential $creds -Scope Global -Persist -ErrorAction Stop
} catch {
    # Access the last error message with `$_`
    LogError ("Failed to mount network drive: " + $_)
}
```
