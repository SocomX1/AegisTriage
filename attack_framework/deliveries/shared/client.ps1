# deliveries/shared/client.ps1
#
# Simple PowerShell wrapper for connecting to a bind shell using Windows ncat.
#
# Intended for:
#   - bind_shell/powershell_auto.conf
#   - bind_shell/powershell_manual.conf
#
# Environment variables:
#
#   TARGET_HOST
#   LPORT
#   NCAT_PATH
#   AUTOMATED
#   COMMANDS_FILE
#
# Defaults:
#
#   LPORT = 4444
#
# Notes:
#
#   - In automated mode, commands from COMMANDS_FILE are piped into ncat.
#   - In manual mode, the operator interacts directly with the shell.
#   - This is intended only for local lab environments.

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

$TARGET_HOST = $env:TARGET_HOST
$LPORT = if ($env:LPORT) { $env:LPORT } else { "4444" }

if (-not $TARGET_HOST) {
    Fail "TARGET_HOST environment variable must be set"
}

$DefaultNcat = "C:\Program Files (x86)\Nmap\ncat.exe"

$NCAT_PATH = if ($env:NCAT_PATH) {
    $env:NCAT_PATH
} else {
    $DefaultNcat
}

if (-not (Test-Path $NCAT_PATH)) {
    Fail "ncat.exe not found: $NCAT_PATH"
}

$AUTOMATED = if ($env:AUTOMATED) {
    $env:AUTOMATED.ToLower()
} else {
    "false"
}

$COMMANDS_FILE = $env:COMMANDS_FILE

Log "Starting bind-shell client"
Log "Target: $TARGET_HOST"
Log "Port: $LPORT"
Log "Automated: $AUTOMATED"

if ($AUTOMATED -eq "true") {

    if (-not $COMMANDS_FILE) {
        Fail "COMMANDS_FILE must be set in automated mode"
    }

    if (-not (Test-Path $COMMANDS_FILE)) {
        Fail "Commands file not found: $COMMANDS_FILE"
    }

    $TranscriptFile = "C:/Windows/Temp/aegis_shell_transcript_$($env:RUN_ID).log"

    Log "Using commands file: $COMMANDS_FILE"
    Log "Transcript file env: $env:TRANSCRIPT_FILE"
    Log "Resolved transcript file: $TranscriptFile"
    Log "Writing transcript to: $TranscriptFile"

    $Content = Get-Content -Raw $COMMANDS_FILE
    $Content = $Content -replace "`r`n", "`n"
    $Content = $Content -replace "`r", "`n"
    $Content = $Content + "`necho __AEGIS_DONE__`nexit`n"

    $Output = $Content | & $NCAT_PATH $TARGET_HOST $LPORT 2>&1

    if (-not $Output) {
        $Output = "[no stdout captured from bind shell]"
    }

    $Output | Out-File -FilePath $TranscriptFile -Encoding utf8
    $Output
} else {

    Log "Manual interaction mode active"

    & $NCAT_PATH $TARGET_HOST $LPORT
}

Log "Client complete"
