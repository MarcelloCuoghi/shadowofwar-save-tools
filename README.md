# shadowofwar-save-tools

A small PowerShell tool to **inspect, decrypt, encrypt and transfer Middle-earth:
Shadow of War PC saves** between user IDs.

Use it when the game does not see your existing saves and offers a new campaign,
for example after:

- moving from one store version of the game to another (e.g. Steam to GOG),
- switching to a different Steam account,
- upgrading to the Definitive Edition on a different store,
- renaming your PC (when the save files are named after the computer).

## Why copying or renaming saves does not work

Saves live in

```
%LOCALAPPDATA%\WB Games\Shadow of War\
├── <user>_ShadowOfWar.sav        main save
├── <user>_1_ShadowOfWar.sav      backups, newest first
├── ...
└── <user>_5_ShadowOfWar.sav
```

`<user>` is either an 8-digit hexadecimal user ID (for example `0a1b2c3d`) or,
depending on the version and launcher, your Windows computer name.

Each file is encrypted with a key that depends on the **user ID**. When the game
starts with a different ID, it looks for files with the new prefix. If you copy or
rename the old files, it finds them but cannot decrypt them, so it starts a new
campaign and resets your settings (settings are stored inside the save too).

This tool decrypts the old saves and encrypts them again for the new ID.

| File name prefix | User ID used for encryption |
|---|---|
| 8 hex digits, e.g. `0a1b2c3d` | the prefix itself (`0a1b2c3d`) |
| your computer name, e.g. `DESKTOP-ABC123` | `0` |

If you are not sure, `info` tells you which ID a file uses.

## Requirements

Windows with PowerShell 5.1 (included in Windows 10/11) or PowerShell 7+.
Nothing to install.

## Download

Download [`sow-saves.ps1`](sow-saves.ps1) (or clone the repository):

```powershell
git clone https://github.com/MarcelloCuoghi/shadowofwar-save-tools
cd shadowofwar-save-tools
```

Files downloaded from the internet are blocked by Windows. Either unblock the
script once:

```powershell
Unblock-File .\sow-saves.ps1
```

or run it with `powershell -ExecutionPolicy Bypass -File .\sow-saves.ps1 ...`.

## Quick start: move your saves to the new user

1. **Turn off cloud sync** for the game (Steam Cloud / GOG Galaxy cloud saves),
   otherwise the launcher may replace your files with its own copy.
2. **Start the game once** with the new setup, reach the main menu (or start a
   new campaign and let it save), then quit. This shows you the new file prefix.
3. **Back up** the folder `%LOCALAPPDATA%\WB Games\Shadow of War`.
4. Look at the file names in that folder. You now have two sets, for example:

   ```
   0a1b2c3d_ShadowOfWar.sav ... 0a1b2c3d_5_ShadowOfWar.sav    <- old saves
   DESKTOP-ABC123_ShadowOfWar.sav ...                         <- new, empty campaign
   ```

5. **Transfer** the old set to the new prefix:

   ```powershell
   .\sow-saves.ps1 transfer -From 0a1b2c3d -To DESKTOP-ABC123
   ```

   The tool:
   - detects the ID of each old file and checks it decrypts correctly,
   - picks the new ID from the new prefix (8 hex digits = that ID, a computer
     name = `0`; override with `-ToId`),
   - moves the existing files of the new prefix into a
     `backup-<prefix>-<timestamp>` subfolder,
   - writes the converted main save and backups,
   - never modifies the old files.

6. Start the game: your campaign and settings are back.

Example output:

```
Backed up 2 existing 'DESKTOP-ABC123' file(s) to ...\backup-DESKTOP-ABC123-20261102-221830
0a1b2c3d_ShadowOfWar.sav (0a1b2c3d) -> DESKTOP-ABC123_ShadowOfWar.sav (00000000)
0a1b2c3d_1_ShadowOfWar.sav (0a1b2c3d) -> DESKTOP-ABC123_1_ShadowOfWar.sav (00000000)
...
Done. The original files were not modified.
```

## Commands

```powershell
.\sow-saves.ps1 <command> [file] [options]
```

| Command | What it does |
|---|---|
| `info FILE` | Shows the header and finds the user ID the file is encrypted for. |
| `transfer -From PREFIX -To PREFIX [-Folder DIR] [-FromId ID] [-ToId ID]` | Converts a whole save set (main + `_1`..`_5`) to another prefix and ID, backing up what it replaces. `-Folder` defaults to `%LOCALAPPDATA%\WB Games\Shadow of War`. |
| `convert FILE -ToId ID -Out FILE [-FromId ID]` | Converts a single save to another ID. |
| `decrypt FILE [-FromId ID] [-Out FILE]` | Writes the decrypted save (default: `FILE.bin`). |
| `encrypt FILE -ToId ID -Out FILE` | Encrypts a decrypted (possibly edited) save for an ID. The checksum is recomputed. |
| `help` | Shows the built-in help. |

Common options:

- IDs are hexadecimal like in the file names: `0a1b2c3d`, `0x0a1b2c3d` and `0`
  are all valid.
- The source ID is detected automatically by trying the file name prefix and `0`.
  If neither works, pass `-FromId`, or extra guesses with `-Candidates id1,id2`.
- `-Force` overwrites existing output files (`convert`, `decrypt`, `encrypt`) and
  lets `transfer` run while the game is open (not recommended: the game may
  overwrite the files when it exits).

## File format

All integers are little endian.

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | magic `SOM3` |
| 4 | 4 | CRC-32 (IEEE, as in zip) of the plaintext |
| 8 | 4 | ciphertext length |
| 12 | 4 | plaintext length |
| 16 | n | AES-256-CBC ciphertext, PKCS#7 padding |

- IV: the ASCII string `yuwgb@oftv@gx$t3`
- Key: the ASCII string `ad@210766@vac94Cd_?dVt5$alivjz$e` with these bytes
  replaced (`crc` = plaintext CRC-32, `id` = 32-bit user ID, byte 0 = least
  significant):

  | Key index | 2 | 10 | 11 | 17 | 18 | 22 | 26 | 30 |
  |---|---|---|---|---|---|---|---|---|
  | Value | `id[3]` | `id[0]` | `crc[1]` | `crc[3]` | `crc[2]` | `id[2]` | `crc[0]` | `id[1]` |

- The plaintext starts with the ASCII magic `SAVE`.

Because the key depends on both the user ID and the content, a file decrypts only
with the right ID, and the CRC-32 check confirms it.

## Tests

```powershell
powershell -ExecutionPolicy Bypass -File .\tests\Run-Tests.ps1
pwsh -File .\tests\Run-Tests.ps1
```

## Disclaimer

This is an unofficial tool, not affiliated with or endorsed by Warner Bros.
Games or Monolith Productions. It only works with save files on your own PC.
Always keep a backup of your saves.

## License

[MIT](LICENSE)
