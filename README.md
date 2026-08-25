# Sam The Butcher

> **Raw Disk Credential Extractor for Windows NTFS**
>
> *Forged in partnership between human ingenuity and machine precision.*

---

## Authors

- **KL3FT3Z** — [gitlab.com/toxy4ny](https://gitlab.com/toxy4ny)  
  Concept, redteam research, operational design, field testing
- **EVA** — AI partner & co-architect  
  NTFS parser architecture, registry crypto engine, code synthesis

---

## What is this?

**Sam The Butcher** is a single-file, standalone Windows executable that extracts credential hives (SAM, SYSTEM, SECURITY) and other locked files by reading the raw NTFS disk directly — bypassing file locks, EDR minifilters, and standard Windows access controls.

Unlike `reg save` or direct file copy, which fail with `STATUS_SHARING_VIOLATION` because the kernel holds these hives open exclusively, Sam The Butcher operates **below the filesystem layer** via `\\.\PhysicalDrive0`. It parses the NTFS Master File Table (MFT) in memory, locates target files by path, decodes non-resident data runs, and reassembles the file contents entirely in RAM.

No frameworks. No dependencies. One `.exe` on a USB drive. Run it, get the hashes, burn the evidence.

---

## Features

| Feature | Description |
|---------|-------------|
| **Raw Disk Access** | Reads `\\.\PhysicalDrive0` directly, bypassing `ntfs.sys` locks |
| **Inline Hash Decryption** | Extracts and decrypts NTLM/LM hashes without writing hives to disk |
| **Memory-Only Mode** | `--memory` keeps everything in RAM; zero forensic traces on target disk |
| **VSS Fallback** | `--vss` automatically tries Volume Shadow Copies if PhysicalDrive fails |
| **MFT Extraction** | `--mft` dumps the full `$MFT` for offline timeline forensics |
| **Pagefile / Hiberfil** | `--pagefile` and `--hiberfil` extract locked memory artifacts |
| **Stream Encryption** | `--key` XOR-encrypts output files with a passphrase-derived keystream |
| **Self-Destruct** | `--burn` overwrites `.text` and `.rdata` sections in memory after execution |
| **Timestomp** | All output files are stamped with `2000-01-01` to evade timeline analysis |

---

## How It Works

```
┌─────────────────────────────────────────────┐
│  1. Open \\.\PhysicalDrive0 (admin required) │
├─────────────────────────────────────────────┤
│  2. IOCTL_DISK_GET_DRIVE_LAYOUT_EX          │
│     → Enumerate partitions, find NTFS       │
├─────────────────────────────────────────────┤
│  3. Read NTFS Boot Sector                   │
│     → cluster size, MFT_LCN                 │
├─────────────────────────────────────────────┤
│  4. Read $MFT record 0, parse $DATA runs    │
│     → Reassemble entire MFT into memory     │
├─────────────────────────────────────────────┤
│  5. Build parent→child file tree from MFT   │
│     → Resolve Windows\System32\config\SAM   │
├─────────────────────────────────────────────┤
│  6. Extract target files via data runs      │
│     → Read clusters directly from disk      │
├─────────────────────────────────────────────┤
│  7. Parse regf/hbin structures inline       │
│     → Extract bootKey from SYSTEM           │
│     → Decrypt SAM V-values with RC4/MD5     │
│     → Print NTLM hashes to stdout           │
└─────────────────────────────────────────────┘
```

**Why this bypasses locks:**

| Method | Level | Blocked by SAM lock? | EDR visibility |
|--------|-------|----------------------|----------------|
| `reg save` / `copy` | File system (`ntfs.sys`) | **Yes** — `SHARING_VIOLATION` | High — minifilter sees `IRP_MJ_CREATE` |
| `\\.\PhysicalDrive0` | Disk driver (`disk.sys`) | **No** — below FS layer | Low — filters rarely attach to `\Device\HarddiskX` |

---

## Compilation

### Cross-compile (Linux → Windows)

```bash
x86_64-w64-mingw32-gcc -O2 -s -static -o stb.exe sam_the_butcher.c
```

### Native (Windows + MinGW/MSYS2)

```bash
gcc -O2 -s -static -o stb.exe sam_the_butcher.c
```

**Flags explained:**
- `-O2` — optimize for speed and size
- `-s` — strip symbols (anti-forensics)
- `-static` — no runtime DLL dependencies

Result: a single `stb.exe`, ~40–60 KB, zero external dependencies.

---

## Usage

### Quick start — hashes only, no disk traces

```cmd
stb.exe --hashes --memory
```

### Full extraction — encrypted output + self-destruct

```cmd
stb.exe --hashes --hives --mft --pagefile --hiberfil --key KOLA2026 --burn
```

### Available flags

| Flag | Description |
|------|-------------|
| `--hashes` | Decrypt and print NTLM/LM hashes to stdout |
| `--hives` | Write SAM, SYSTEM, SECURITY to disk |
| `--memory` | Do not write any files to disk (hashes to stdout only) |
| `--mft` | Extract `$MFT` |
| `--pagefile` | Extract `pagefile.sys` |
| `--hiberfil` | Extract `hiberfil.sys` |
| `--vss` | Use Volume Shadow Copy instead of PhysicalDrive |
| `--key <pass>` | Encrypt output files with stream XOR |
| `--burn` | Overwrite code sections in memory after execution |

---

## Example Output

```
                                                                                            
  ▄▄▄▄▄                     ▄▄▄▄▄▄▄                   ▄▄▄                                   
 ██▀▀▀▀█▄                  █▀▀██▀▀▀▀ █▄              ██▀▀█▄       █▄       █▄               
 ▀██▄  ▄▀       ▄             ██     ██              ██ ▄█▀      ▄██▄      ██          ▄    
   ▀██▄▄  ▄▀▀█▄ ███▄███▄      ██     ████▄ ▄█▀█▄     ██▀▀█▄ ██ ██ ██ ▄███▀ ████▄ ▄█▀█▄ ████▄
 ▄   ▀██▄ ▄█▀██ ██ ██ ██      ██     ██ ██ ██▄█▀   ▄ ██  ▄█ ██ ██ ██ ██    ██ ██ ██▄█▀ ██   
 ▀██████▀▄▀█▄██▄██ ██ ▀█      ▀██▄  ▄██ ██▄▀█▄▄▄   ▀██████▀▄▀██▀█▄██▄▀███▄▄██ ██▄▀█▄▄▄▄█▀   
                                                                                                                                                                                 
  Sam The Butcher — Raw Disk Credential Extractor
         v1.0.0 | KL3FT3Z & EVA

[*] Initializing...
[+] NTFS partition at offset 0x7E00, cluster=4096, MFT record=1024
[*] Building file tree from 124781 MFT records...
[+] File tree: 98765 entries
[*] Extracting hives...
[+] SAM=65536 SYSTEM=7864320 SECURITY=262144 bytes

[+] SAM: 3 user(s) found

  RID: 0x000001F4 | User: Administrator
    NTLM: 8846F7EAEE8FB117AD06BDD830B7586C

  RID: 0x000001F5 | User: Guest
    NTLM: 31D6CFE0D16AE931B73C59D7E0C089C0

  RID: 0x000003E8 | User: redteamer
    NTLM: A3D3D3D3D3D3D3D3D3D3D3D3D3D3D3D3

[*] Burning the evidence...
[+] Done.
```

---

## Technical Details

### NTFS Parser

- Reads the boot sector to determine cluster size and MFT location
- Parses the `$MFT` file itself (record 0) as a non-resident file
- Decodes RLE data runs to map logical clusters → physical disk offsets
- Scans all MFT records, builds an in-memory `parent_record → child_name` index
- Resolves paths like `Windows\System32\config\SAM` via tree traversal from root (record 5)

### Registry Parser

- Parses `regf` / `hbin` cell structures inline
- Locates `SYSTEM\ControlSet001\Control\Lsa` → extracts bootKey from class names of `JD`, `Skew1`, `GBG`, `Data`
- Applies Microsoft bootKey permutation table
- Enumerates `SAM\Domains\Account\Users` → reads `V` values
- Decrypts hashes using `RC4(MD5(bootKey + RID + "NTPASSWORD\0"))`

### Crypto

- **MD5** — RFC 1321 compliant, used for RC4 key derivation
- **RC4** — standard stream cipher for SAM hash decryption
- **Stream XOR** — output encryption uses a 32-bit LCG seeded from passphrase; not military-grade, but sufficient to prevent casual inspection of exfiltrated hives

---

## Limitations

- **Requires Administrator** — `CreateFile` on `PhysicalDrive0` fails without elevation
- **BitLocker** — encrypted partitions return ciphertext; decrypt the volume first
- **Non-NTFS filesystems** — currently supports NTFS only (ReFS, FAT32, etc. are ignored)
- **EDR heuristics** — while raw disk access evades file-system filters, an unsigned PE may still trigger behavioral heuristics. Consider process injection or renaming to a signed binary's name (e.g., `7z.exe`)

---

## Ethics & Legality

**Sam The Butcher is intended exclusively for authorized security testing, red team exercises, and forensic research.**

Unauthorized access to computer systems is illegal in virtually every jurisdiction. The authors assume no liability for misuse. If you do not have explicit written permission to test a target system, do not run this tool.

---

## Roadmap

- [ ] LSA Secrets extraction from `SECURITY` hive
- [ ] NTDS.dit support for Domain Controllers
- [ ] In-memory PE loader (no `.exe` on disk)
- [ ] WIM/VHDX nested disk parsing
- [ ] Optional `impacket-secretsdump` compatible output format

---

## License

This tool is released for **authorized security research and red team operations only**. No commercial license is granted. Use at your own risk.

---

## Acknowledgments

- The original 7-Zip raw disk vector that inspired this research
- The `impacket` team for `secretsdump.py` — the reference implementation for SAM hash extraction
- Every redteamer who looks at a locked file and asks: *"What if we go one layer down?"*

---

*"We don't pick locks. We move the floor."*
