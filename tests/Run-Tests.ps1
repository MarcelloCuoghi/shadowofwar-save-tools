# Self-contained tests for sow-saves.ps1. Run with:
#   powershell -ExecutionPolicy Bypass -File .\tests\Run-Tests.ps1
#   pwsh -File .\tests\Run-Tests.ps1
$ErrorActionPreference = 'Stop'
$script = Join-Path $PSScriptRoot '..\sow-saves.ps1'
$work = Join-Path ([IO.Path]::GetTempPath()) ('sow-tests-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null
$failures = 0

function Check([string]$Name, [bool]$Condition) {
    if ($Condition) { Write-Host "PASS  $Name" -ForegroundColor Green }
    else { Write-Host "FAIL  $Name" -ForegroundColor Red; $script:failures++ }
}
function Bytes([string]$File) { , [IO.File]::ReadAllBytes($File) }
function Same([byte[]]$A, [byte[]]$B) { [Linq.Enumerable]::SequenceEqual($A, $B) }

try {
    # A fake plaintext that looks like a decrypted save.
    $rng = New-Object Random 1234
    $plain = New-Object byte[] 100003
    $rng.NextBytes($plain)
    [Text.Encoding]::ASCII.GetBytes('SAVE').CopyTo($plain, 0)
    $plainFile = Join-Path $work 'plain.bin'
    [IO.File]::WriteAllBytes($plainFile, $plain)

    # encrypt -> decrypt round trip, ID taken from the file name prefix.
    $sav = Join-Path $work '0a1b2c3d_ShadowOfWar.sav'
    & $script encrypt $plainFile -ToId 0a1b2c3d -Out $sav | Out-Null
    $enc = Bytes $sav
    Check 'header magic' ([Text.Encoding]::ASCII.GetString($enc, 0, 4) -eq 'SOM3')
    Check 'header lengths' (([BitConverter]::ToInt32($enc, 12) -eq $plain.Length) -and ([BitConverter]::ToInt32($enc, 8) -eq $enc.Length - 16))
    & $script decrypt $sav -Out (Join-Path $work 'dec.bin') | Out-Null
    Check 'decrypt with ID from file name' (Same (Bytes (Join-Path $work 'dec.bin')) $plain)

    # Encryption is deterministic: re-encrypting gives identical bytes.
    & $script encrypt (Join-Path $work 'dec.bin') -ToId 0x0a1b2c3d -Out (Join-Path $work 'again.sav') | Out-Null
    Check 'deterministic encryption' (Same (Bytes (Join-Path $work 'again.sav')) $enc)

    # A wrong ID is rejected.
    $failed = $false
    try { & $script decrypt $sav -FromId 0a1b2c3e -Out (Join-Path $work 'x.bin') | Out-Null } catch { $failed = $true }
    Check 'wrong ID rejected' $failed

    # convert to ID 0 under a computer-name style file name.
    $conv = Join-Path $work 'MYPC_ShadowOfWar.sav'
    & $script convert $sav -ToId 0 -Out $conv | Out-Null
    & $script decrypt $conv -Out (Join-Path $work 'conv.bin') | Out-Null
    Check 'convert to ID 0' (Same (Bytes (Join-Path $work 'conv.bin')) $plain)
    $info = (& $script info $conv) -join "`n"
    Check 'info detects ID 0' ($info -match 'User ID:\s+00000000')

    # transfer a full set, with an existing destination set that must be backed up.
    $set = Join-Path $work 'set'
    New-Item -ItemType Directory -Path $set | Out-Null
    foreach ($s in @('') + (1..5 | ForEach-Object { "_$_" })) {
        Copy-Item $sav (Join-Path $set "0a1b2c3d${s}_ShadowOfWar.sav")
    }
    [IO.File]::WriteAllBytes((Join-Path $set 'MYPC_ShadowOfWar.sav'), [byte[]](1, 2, 3))
    & $script transfer -Folder $set -From 0a1b2c3d -To MYPC -Force | Out-Null
    $targets = @(Get-ChildItem $set -Filter 'MYPC*_ShadowOfWar.sav')
    Check 'transfer writes 6 files' ($targets.Count -eq 6)
    $ok = $true
    foreach ($t in $targets) {
        & $script decrypt $t.FullName -FromId 0 -Out (Join-Path $work 't.bin') -Force | Out-Null
        if (-not (Same (Bytes (Join-Path $work 't.bin')) $plain)) { $ok = $false }
    }
    Check 'transferred files decrypt with ID 0' $ok
    $bk = @(Get-ChildItem $set -Directory -Filter 'backup-MYPC-*')
    Check 'existing destination backed up' ($bk.Count -eq 1 -and (Test-Path (Join-Path $bk[0].FullName 'MYPC_ShadowOfWar.sav')))

    # Known vector: the first block of a real save written by the game for user ID 0.
    $hex = '534f4d33bccdbb8a80be13007dbe1300a47b89a1316b83068850780d998d56be'
    $vec = [byte[]]::new(32)
    for ($i = 0; $i -lt 32; $i++) { $vec[$i] = [Convert]::ToByte($hex.Substring($i * 2, 2), 16) }
    $k = [Text.Encoding]::ASCII.GetBytes('ad@210766@vac94Cd_?dVt5$alivjz$e')
    $crc = [BitConverter]::ToUInt32($vec, 4)
    $k[11] = ($crc -shr 8) -band 0xFF; $k[17] = ($crc -shr 24) -band 0xFF
    $k[18] = ($crc -shr 16) -band 0xFF; $k[26] = $crc -band 0xFF
    $k[2] = 0; $k[10] = 0; $k[22] = 0; $k[30] = 0
    $aes = [Security.Cryptography.Aes]::Create()
    $aes.Mode = 'CBC'; $aes.Padding = 'None'; $aes.Key = $k
    $aes.IV = [Text.Encoding]::ASCII.GetBytes('yuwgb@oftv@gx$t3')
    $block = $aes.CreateDecryptor().TransformFinalBlock($vec, 16, 16)
    Check 'real save first block decrypts to SAVE' ([Text.Encoding]::ASCII.GetString($block, 0, 4) -eq 'SAVE')
}
finally {
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}

if ($failures) { Write-Host "$failures test(s) failed" -ForegroundColor Red; exit 1 }
Write-Host 'All tests passed' -ForegroundColor Green
