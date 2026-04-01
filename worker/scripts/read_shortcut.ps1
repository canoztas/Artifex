param(
    [Parameter(Mandatory = $true)]
    [string]$ShortcutPath
)

$ErrorActionPreference = 'Stop'

$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut($ShortcutPath)

[ordered]@{
    target_path = $shortcut.TargetPath
    arguments = $shortcut.Arguments
    working_directory = $shortcut.WorkingDirectory
    description = $shortcut.Description
    hotkey = $shortcut.Hotkey
    icon_location = $shortcut.IconLocation
    window_style = $shortcut.WindowStyle
} | ConvertTo-Json -Compress -Depth 3
