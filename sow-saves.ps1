<#
.SYNOPSIS
    Inspect, decrypt, encrypt and transfer Middle-earth: Shadow of War PC save files
    between user IDs.

.DESCRIPTION
    Shadow of War encrypts every save with a key derived from the ID of the user who
    created it. Renaming or copying a save for another user does not work: the game
    cannot decrypt it and starts a new campaign. This script re-encrypts saves for a
    different user ID.

    Commands:
      info      Show the header of a save and find which user ID it is encrypted for.
      decrypt   Decrypt a save to a plain binary file.
      encrypt   Encrypt a plain binary file into a save for a given user ID.
      convert   Re-encrypt a single save for another user ID.
      transfer  Re-encrypt a whole save set (main save + 5 backups) from one file name
                prefix to another, backing up any files it overwrites.

    User IDs are hexadecimal, as in the 8-digit prefix of the save file names
    (for example 0a1b2c3d). A "0x" prefix is accepted.

.EXAMPLE
    .\sow-saves.ps1 info "$env:LOCALAPPDATA\WB Games\Shadow of War\0a1b2c3d_ShadowOfWar.sav"

.EXAMPLE
    .\sow-saves.ps1 transfer -From 0a1b2c3d -To $env:COMPUTERNAME

.EXAMPLE
    .\sow-saves.ps1 convert .\0a1b2c3d_ShadowOfWar.sav -ToId 0 -Out .\MYPC_ShadowOfWar.sav

.LINK
    https://github.com/MarcelloCuoghi/shadowofwar-save-tools
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('info', 'decrypt', 'encrypt', 'convert', 'transfer', 'help')]
    [string]$Command = 'help',

    # Input file (info, decrypt, encrypt, convert).
    [Parameter(Position = 1)]
    [string]$Path,

    # Output file (decrypt, encrypt, convert).
    [string]$Out,

    # User ID of the input save (decrypt, convert, transfer). Detected when omitted.
    [string]$FromId,

    # User ID to encrypt for (encrypt, convert, transfer).
    [string]$ToId,

    # Extra user IDs to try when detecting the ID of a save (info, decrypt, convert, transfer).
    [string[]]$Candidates = @(),

    # File name prefix of the save set to read (transfer), e.g. 0a1b2c3d.
    [string]$From,

    # File name prefix of the save set to write (transfer), e.g. your computer name.
    [string]$To,

    # Save folder (transfer). Defaults to %LOCALAPPDATA%\WB Games\Shadow of War.
    [string]$Folder = (Join-Path $env:LOCALAPPDATA 'WB Games\Shadow of War'),

    # Overwrite existing output files (decrypt, encrypt, convert) / run while the game is open.
    [switch]$Force
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# File format
# ---------------------------------------------------------------------------
#   offset  size  field
#   0       4     magic "SOM3"
#   4       4     CRC-32 of the plaintext (little endian)
#   8       4     ciphertext length
#   12      4     plaintext length
#   16      n     AES-256-CBC(PKCS#7) ciphertext
#
#   IV  = "yuwgb@oftv@gx$t3"
#   Key = "ad@210766@vac94Cd_?dVt5$alivjz$e" with 8 bytes replaced by the bytes of
#         the plaintext CRC-32 and of the 32-bit user ID (see Get-SowKey).
#   The plaintext starts with the ASCII magic "SAVE".

$script:KeyBase = 'ad@210766@vac94Cd_?dVt5$alivjz$e'
$script:IV = 'yuwgb@oftv@gx$t3'
$script:Magic = 0x334D4F53 # "SOM3"
$script:SaveSuffix = '_ShadowOfWar.sav'

if (-not ('SowCrc32' -as [type])) {
    Add-Type -TypeDefinition @'
public static class SowCrc32 {
    static readonly uint[] Table = BuildTable();
    static uint[] BuildTable() {
        uint[] t = new uint[256];
        for (uint i = 0; i < 256; i++) {
            uint c = i;
            for (int k = 0; k < 8; k++) c = (c & 1) != 0 ? 0xEDB88320u ^ (c >> 1) : c >> 1;
            t[i] = c;
        }
        return t;
    }
    public static uint Compute(byte[] data, int offset, int count) {
        uint crc = 0xFFFFFFFFu;
        for (int i = offset; i < offset + count; i++) crc = Table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
        return crc ^ 0xFFFFFFFFu;
    }
}
'@
}

function ConvertTo-SowId {
    param([Parameter(Mandatory)][string]$Value)
    $v = $Value.Trim()
    if ($v -match '^(0x)?([0-9a-fA-F]{1,8})$') {
        return [uint32]::Parse($Matches[2], [Globalization.NumberStyles]::HexNumber)
    }
    throw "Invalid user ID '$Value'. Use up to 8 hexadecimal digits, e.g. 0a1b2c3d or 0."
}

function Format-SowId([uint32]$Id) { '{0:x8}' -f $Id }

function Get-SowKey {
    param([uint32]$Crc, [uint32]$Id)
    $k = [Text.Encoding]::ASCII.GetBytes($script:KeyBase)
    $k[11] = [byte](($Crc -shr 8) -band 0xFF)
    $k[17] = [byte](($Crc -shr 24) -band 0xFF)
    $k[18] = [byte](($Crc -shr 16) -band 0xFF)
    $k[26] = [byte]($Crc -band 0xFF)
    $k[2] = [byte](($Id -shr 24) -band 0xFF)
    $k[10] = [byte]($Id -band 0xFF)
    $k[22] = [byte](($Id -shr 16) -band 0xFF)
    $k[30] = [byte](($Id -shr 8) -band 0xFF)
    , $k
}

function New-SowAes {
    param([byte[]]$Key)
    $aes = [Security.Cryptography.Aes]::Create()
    $aes.Mode = [Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [Security.Cryptography.PaddingMode]::PKCS7
    $aes.Key = $Key
    $aes.IV = [Text.Encoding]::ASCII.GetBytes($script:IV)
    $aes
}

function Read-SowHeader {
    param([byte[]]$Bytes)
    if ($Bytes.Length -lt 32 -or [BitConverter]::ToUInt32($Bytes, 0) -ne $script:Magic) {
        throw 'Not a Shadow of War save (missing SOM3 header).'
    }
    $h = [pscustomobject]@{
        Crc             = [BitConverter]::ToUInt32($Bytes, 4)
        CipherLength    = [BitConverter]::ToInt32($Bytes, 8)
        PlaintextLength = [BitConverter]::ToInt32($Bytes, 12)
    }
    if ($h.CipherLength -le 0 -or $h.CipherLength % 16 -ne 0 -or 16 + $h.CipherLength -gt $Bytes.Length) {
        throw "Corrupted header: ciphertext length $($h.CipherLength), file size $($Bytes.Length)."
    }
    $h
}

# Returns the plaintext, or $null if the save is not encrypted for this ID.
function Unprotect-SowSave {
    param([byte[]]$Bytes, [uint32]$Id)
    $h = Read-SowHeader $Bytes
    $aes = New-SowAes (Get-SowKey $h.Crc $Id)
    try {
        $plain = $aes.CreateDecryptor().TransformFinalBlock($Bytes, 16, $h.CipherLength)
    }
    catch [Security.Cryptography.CryptographicException] {
        return $null # wrong key -> invalid padding
    }
    finally { $aes.Dispose() }
    if ($plain.Length -ne $h.PlaintextLength) { return $null }
    if ([SowCrc32]::Compute($plain, 0, $plain.Length) -ne $h.Crc) { return $null }
    , $plain
}

function Protect-SowSave {
    param([byte[]]$Plaintext, [uint32]$Id)
    $crc = [SowCrc32]::Compute($Plaintext, 0, $Plaintext.Length)
    $aes = New-SowAes (Get-SowKey $crc $Id)
    try { $cipher = $aes.CreateEncryptor().TransformFinalBlock($Plaintext, 0, $Plaintext.Length) }
    finally { $aes.Dispose() }
    $out = New-Object byte[] (16 + $cipher.Length)
    [BitConverter]::GetBytes([uint32]$script:Magic).CopyTo($out, 0)
    [BitConverter]::GetBytes([uint32]$crc).CopyTo($out, 4)
    [BitConverter]::GetBytes([int]$cipher.Length).CopyTo($out, 8)
    [BitConverter]::GetBytes([int]$Plaintext.Length).CopyTo($out, 12)
    $cipher.CopyTo($out, 16)
    , $out
}

# IDs worth trying for a file: its 8-hex-digit name prefix, 0, and user candidates.
function Get-SowIdCandidates {
    param([string]$FileName, [string[]]$Extra = @())
    $ids = New-Object System.Collections.Generic.List[uint32]
    if ($FileName -match '^([0-9a-fA-F]{8})_') { $ids.Add((ConvertTo-SowId $Matches[1])) }
    $ids.Add([uint32]0)
    foreach ($c in $Extra) { $ids.Add((ConvertTo-SowId $c)) }
    , @($ids | Select-Object -Unique)
}

# Finds the ID a save is encrypted for. Returns @{ Id; Plaintext } or $null.
function Find-SowId {
    param([byte[]]$Bytes, [string]$FileName, [string[]]$Extra = @(), [string]$Forced)
    $ids = if ($Forced) { @(ConvertTo-SowId $Forced) } else { Get-SowIdCandidates $FileName $Extra }
    foreach ($id in $ids) {
        $plain = Unprotect-SowSave $Bytes $id
        if ($null -ne $plain) { return [pscustomobject]@{ Id = [uint32]$id; Plaintext = $plain } }
    }
    $null
}

function Resolve-InputFile {
    param([string]$Value)
    if (-not $Value) { throw "Command '$Command' needs an input file." }
    (Resolve-Path -LiteralPath $Value).ProviderPath
}

function Assert-CanWrite {
    param([string]$File)
    if (-not $File) { throw "Command '$Command' needs -Out <file>." }
    if ((Test-Path -LiteralPath $File) -and -not $Force) {
        throw "'$File' already exists. Use -Force to overwrite it."
    }
}

function Write-AllBytes {
    param([string]$File, [byte[]]$Bytes)
    $full = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($File)
    [IO.File]::WriteAllBytes($full, $Bytes)
    $full
}

function Get-IdNotFoundMessage {
    param([string]$FileName)
    "Could not find the user ID of '$FileName'. Tried: " +
    ((Get-SowIdCandidates $FileName $Candidates | ForEach-Object { Format-SowId $_ }) -join ', ') +
    '. Pass the right one with -FromId (or more guesses with -Candidates).'
}

function Assert-GameClosed {
    if ($Force) { return }
    if (Get-Process -Name 'ShadowOfWar' -ErrorAction SilentlyContinue) {
        throw 'Shadow of War is running. Close the game first (or use -Force).'
    }
}

# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

function Invoke-Info {
    $file = Resolve-InputFile $Path
    $bytes = [IO.File]::ReadAllBytes($file)
    $h = Read-SowHeader $bytes
    $name = Split-Path $file -Leaf
    "File:             $file"
    "Size:             $($bytes.Length) bytes"
    "Plaintext CRC-32: {0:x8}" -f $h.Crc
    "Ciphertext:       $($h.CipherLength) bytes"
    "Plaintext:        $($h.PlaintextLength) bytes"
    $found = Find-SowId $bytes $name $Candidates $FromId
    if ($found) {
        "User ID:          $(Format-SowId $found.Id)  (decrypts and CRC matches)"
    }
    else {
        "User ID:          unknown"
        Write-Warning (Get-IdNotFoundMessage $name)
    }
}

function Invoke-Decrypt {
    $file = Resolve-InputFile $Path
    if (-not $Out) { $Out = "$file.bin" }
    Assert-CanWrite $Out
    $found = Find-SowId ([IO.File]::ReadAllBytes($file)) (Split-Path $file -Leaf) $Candidates $FromId
    if (-not $found) { throw (Get-IdNotFoundMessage (Split-Path $file -Leaf)) }
    $written = Write-AllBytes $Out $found.Plaintext
    "Decrypted with user ID $(Format-SowId $found.Id) -> $written"
}

function Invoke-Encrypt {
    $file = Resolve-InputFile $Path
    if (-not $ToId) { throw 'encrypt needs -ToId <id>.' }
    Assert-CanWrite $Out
    $plain = [IO.File]::ReadAllBytes($file)
    if ($plain.Length -lt 4 -or [Text.Encoding]::ASCII.GetString($plain, 0, 4) -ne 'SAVE') {
        Write-Warning 'The input does not start with "SAVE"; it may not be a decrypted save.'
    }
    $id = ConvertTo-SowId $ToId
    $written = Write-AllBytes $Out (Protect-SowSave $plain $id)
    "Encrypted for user ID $(Format-SowId $id) -> $written"
}

function Invoke-Convert {
    $file = Resolve-InputFile $Path
    if ($null -eq $ToId -or $ToId -eq '') { throw 'convert needs -ToId <id>.' }
    Assert-CanWrite $Out
    $found = Find-SowId ([IO.File]::ReadAllBytes($file)) (Split-Path $file -Leaf) $Candidates $FromId
    if (-not $found) { throw (Get-IdNotFoundMessage (Split-Path $file -Leaf)) }
    $id = ConvertTo-SowId $ToId
    $new = Protect-SowSave $found.Plaintext $id
    if ($null -eq (Unprotect-SowSave $new $id)) { throw 'Verification of the converted save failed.' }
    $written = Write-AllBytes $Out $new
    (Get-Item -LiteralPath $written).LastWriteTime = (Get-Item -LiteralPath $file).LastWriteTime
    "Converted $(Format-SowId $found.Id) -> $(Format-SowId $id): $written"
}

function Invoke-Transfer {
    if (-not $From -or -not $To) { throw 'transfer needs -From <prefix> and -To <prefix>.' }
    if ($From -eq $To) { throw '-From and -To must be different.' }
    if (-not (Test-Path -LiteralPath $Folder -PathType Container)) { throw "Save folder not found: $Folder" }
    $Folder = (Resolve-Path -LiteralPath $Folder).ProviderPath
    Assert-GameClosed

    # Destination ID: explicit, else the prefix when it is an 8-digit hex ID, else 0.
    if ($ToId) { $targetId = ConvertTo-SowId $ToId }
    elseif ($To -match '^[0-9a-fA-F]{8}$') { $targetId = ConvertTo-SowId $To }
    else { $targetId = [uint32]0 }

    $suffixes = @('') + (1..5 | ForEach-Object { "_$_" })
    $jobs = foreach ($s in $suffixes) {
        $src = Join-Path $Folder "$From$s$script:SaveSuffix"
        if (Test-Path -LiteralPath $src) {
            [pscustomobject]@{ Source = $src; Target = (Join-Path $Folder "$To$s$script:SaveSuffix") }
        }
    }
    if (-not $jobs) { throw "No '$From*$script:SaveSuffix' files found in $Folder." }

    # Convert everything in memory first: nothing is written if any file fails.
    $results = foreach ($j in @($jobs)) {
        $name = Split-Path $j.Source -Leaf
        $found = Find-SowId ([IO.File]::ReadAllBytes($j.Source)) $name $Candidates $FromId
        if (-not $found) { throw (Get-IdNotFoundMessage $name) }
        $new = Protect-SowSave $found.Plaintext $targetId
        if ($null -eq (Unprotect-SowSave $new $targetId)) { throw "Verification failed for $name." }
        [pscustomobject]@{ Job = $j; FromId = $found.Id; Bytes = $new }
    }

    $existing = @(Get-ChildItem -LiteralPath $Folder -File |
        Where-Object { $_.Name -like "$To*$script:SaveSuffix" -and $_.Name -match ('^' + [regex]::Escape($To) + '(_\d)?' + [regex]::Escape($script:SaveSuffix) + '$') })
    if ($existing.Count -gt 0) {
        $backup = Join-Path $Folder ("backup-$To-" + (Get-Date -Format 'yyyyMMdd-HHmmss'))
        New-Item -ItemType Directory -Path $backup | Out-Null
        $existing | Copy-Item -Destination $backup
        "Backed up $($existing.Count) existing '$To' file(s) to $backup"
        # Remove stale backups of the destination so the game cannot pick up old ones.
        $existing | Remove-Item
    }

    foreach ($r in $results) {
        [IO.File]::WriteAllBytes($r.Job.Target, $r.Bytes)
        (Get-Item -LiteralPath $r.Job.Target).LastWriteTime = (Get-Item -LiteralPath $r.Job.Source).LastWriteTime
        '{0} ({1}) -> {2} ({3})' -f (Split-Path $r.Job.Source -Leaf), (Format-SowId $r.FromId),
            (Split-Path $r.Job.Target -Leaf), (Format-SowId $targetId)
    }
    'Done. The original files were not modified.'
}

switch ($Command) {
    'info' { Invoke-Info }
    'decrypt' { Invoke-Decrypt }
    'encrypt' { Invoke-Encrypt }
    'convert' { Invoke-Convert }
    'transfer' { Invoke-Transfer }
    'help' { Get-Help $PSCommandPath -Detailed }
}
