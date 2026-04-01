param(
    [Parameter(Mandatory = $true)]
    [string]$FilePath,

    [Parameter(Mandatory = $true)]
    [string]$WorkingDirectory,

    [Parameter(Mandatory = $true)]
    [string]$StdOut,

    [Parameter(Mandatory = $true)]
    [string]$StdErr,

    [string]$PidFile = "",

    [string[]]$ArgumentList = @(),

    [string[]]$EnvVar = @()
)

$ErrorActionPreference = 'Stop'

New-Item -ItemType File -Path $StdOut -Force | Out-Null
New-Item -ItemType File -Path $StdErr -Force | Out-Null

$envPairs = @()
foreach ($entry in $EnvVar) {
    if (-not $entry) {
        continue
    }
    if ($entry.Contains(';')) {
        $envPairs += $entry -split ';'
    } else {
        $envPairs += $entry
    }
}

foreach ($pair in $envPairs) {
    $name, $value = $pair -split '=', 2
    if ($name) {
        [Environment]::SetEnvironmentVariable($name, $value, 'Process')
    }
}

$startParams = @{
    FilePath               = $FilePath
    WorkingDirectory       = $WorkingDirectory
    RedirectStandardOutput = $StdOut
    RedirectStandardError  = $StdErr
    WindowStyle            = 'Hidden'
    PassThru               = $true
}

if ($ArgumentList.Count -gt 0) {
    $startParams.ArgumentList = $ArgumentList
}

$process = Start-Process @startParams
if ($PidFile) {
    Set-Content -Path $PidFile -Value $process.Id -NoNewline -Encoding Ascii
} else {
    $process.Id
}
