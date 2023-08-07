#ifndef PE_H
#define PE_H

#include <cstdint>
#include <memory>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <Windows.h>
#include <winnt.h>

#define PE_SIGNATURE_ADDRESS_OFFSET 0x3c
#define PE_SIGNATURE "PE\0" // {'P', 'E', '\0', '\0'}
#define PE_SIGNATURE_SIZE (sizeof PE_SIGNATURE)
#define SECTION_FIELD_NAME_SIZE 8

typedef struct pe
{
  int16_t type;
  uint16_t number_of_sections;
  FILE *file;
  char* pe_file_buffer;
  struct pe_coff_header *coff_header;
  void *optional_header;
  struct pe_section_header *section_header[];
} pe_t;

typedef struct pe32
{
  int16_t type;
  uint16_t number_of_sections;
  FILE *file;
  char* pe_file_buffer;
  struct pe_coff_header *coff_header;
  struct pe32_optional_header *optional_header;
  struct pe_section_header *section_header[];
} pe32_t;

typedef struct pe64
{
  int16_t type;
  uint16_t number_of_sections;
  FILE *file;
  char* pe_file_buffer;
  struct pe_coff_header *coff_header;
  struct pe64_optional_header *optional_header;
  struct pe_section_header *section_header[];
} pe64_t;

typedef struct pe_data_directory
{
  int32_t virtual_address;
  int32_t size;
} pe_data_directory_t;

typedef struct pe_coff_header
{
  uint16_t machine;
  uint16_t number_of_sections;
  uint32_t time_date_stamp;
  uint32_t pointer_to_symbol_table;
  uint32_t number_of_symbols;
  uint16_t size_of_optional_header;
  uint16_t characteristics;
} pe_coff_header_t;

#define PE_OPTIONAL_HEADER_STANDARD_FIELDS \
  uint16_t magic;                          \
  uint8_t major_linker_version;            \
  uint8_t minor_linker_version;            \
  uint32_t size_of_code;                   \
  uint32_t size_of_initialized_data;       \
  uint32_t size_of_unitialized_data;       \
  uint32_t entry_point;                    \
  uint32_t base_of_code

#define PE_OPTIONAL_HEADER_WINDOWS_FIELDS(field_type) \
  field_type image_base;                              \
  uint32_t section_alignment;                         \
  uint32_t file_alignment;                            \
  uint16_t major_os_version;                          \
  uint16_t minor_os_version;                          \
  uint16_t major_image_version;                       \
  uint16_t minor_image_version;                       \
  uint16_t major_subsystem_version;                   \
  uint16_t minor_subsystem_version;                   \
  uint32_t win32_version_value;                       \
  uint32_t size_of_image;                             \
  uint32_t size_of_headers;                           \
  uint32_t checksum;                                  \
  uint16_t subsystem;                                 \
  uint16_t dll_characteristics;                       \
  field_type size_of_stack_reserve;                   \
  field_type size_of_stack_commit;                    \
  field_type size_of_head_reserve;                    \
  field_type size_of_head_commit;                     \
  uint32_t loader_flags;                              \
  uint32_t number_of_rva_and_sizes

#define PE_OPTIONAL_HEADER_DATA_DIRECTORIES    \
  pe_data_directory_t export_table;            \
  pe_data_directory_t import_table;            \
  pe_data_directory_t resource_table;          \
  pe_data_directory_t exception_table;         \
  pe_data_directory_t certificate_table;       \
  pe_data_directory_t base_relocation_table;   \
  pe_data_directory_t debug;                   \
  pe_data_directory_t architecture;            \
  pe_data_directory_t global_ptr;              \
  pe_data_directory_t tls_table;               \
  pe_data_directory_t load_config_table;       \
  pe_data_directory_t bound_import;            \
  pe_data_directory_t iat;                     \
  pe_data_directory_t delay_import_descriptor; \
  pe_data_directory_t clr_runtime_header;      \
  pe_data_directory_t reserved

typedef struct pe32_optional_header
{
  PE_OPTIONAL_HEADER_STANDARD_FIELDS;
  int32_t base_of_data;
  PE_OPTIONAL_HEADER_WINDOWS_FIELDS(uint32_t);
  PE_OPTIONAL_HEADER_DATA_DIRECTORIES;
} pe32_optional_header_t;

typedef struct pe64_optional_header
{
  PE_OPTIONAL_HEADER_STANDARD_FIELDS;
  PE_OPTIONAL_HEADER_WINDOWS_FIELDS(uint64_t);
  PE_OPTIONAL_HEADER_DATA_DIRECTORIES;
} pe64_optional_header_t;

typedef struct pe_section_header
{
  char name[SECTION_FIELD_NAME_SIZE];
  uint32_t virtual_size;
  uint32_t virtual_address;
  uint32_t size_of_raw_data;
  uint32_t pointer_to_raw_data;
  uint32_t pointer_to_relocations;
  uint32_t pointer_to_line_numbers;
  uint16_t number_of_relocations;
  uint16_t number_of_line_numbers;
  uint32_t characteristics;
} pe_section_header_t;

enum pe_section_flags
{
  TYPE_NO_PAD = 0x00000008,
  CNT_CODE = 0x00000020,
  CNT_INITIALIZED_DATA = 0x00000040,
  CNT_UNINITIALIZED_DATA = 0x00000080,
  LNK_OTHER = 0x00000100,
  LNK_INFO = 0x00000200,
  LNK_REMOVE = 0x00000800,
  LNK_COMDAT = 0x00001000,
  GPREL = 0x00008000,
  MEM_PURGEABLE = 0x00020000,
  MEM_16BIT = 0x00020000,
  MEM_LOCKED = 0x00040000,
  MEM_PRELOAD = 0x00080000,
  ALIGN_1BYTES = 0x00100000,
  ALIGN_2BYTES = 0x00200000,
  ALIGN_4BYTES = 0x00300000,
  ALIGN_8BYTES = 0x00400000,
  ALIGN_16BYTES = 0x00500000,
  ALIGN_32BYTES = 0x00600000,
  ALIGN_64BYTES = 0x00700000,
  ALIGN_128BYTES = 0x00800000,
  ALIGN_256BYTES = 0x00900000,
  ALIGN_512BYTES = 0x00A00000,
  ALIGN_1024BYTES = 0x00B00000,
  ALIGN_2048BYTES = 0x00C00000,
  ALIGN_4096BYTES = 0x00D00000,
  ALIGN_8192BYTES = 0x00E00000,
  LNK_NRELOC_OVFL = 0x01000000,
  MEM_DISCARDABLE = 0x02000000,
  MEM_NOT_CACHED = 0x04000000,
  MEM_NOT_PAGED = 0x08000000,
  MEM_SHARED = 0x10000000,
  MEM_EXECUTE = 0x20000000,
  MEM_READ = 0x40000000,
  MEM_WRITE = INT_MIN, // Workaround to get 0x80000000 value
};

enum pe_machine_type
{
  MACHINE_UNKNOWN = 0x0,
  AM33 = 0x1d3,
  AMD64 = 0x8664,
  ARM = 0x1c0,
  ARM64 = 0xaa64,
  ARMNT = 0x1c4,
  EBC = 0xebc,
  I386 = 0x14c,
  IA64 = 0x200,
  M32R = 0x9041,
  MIPS16 = 0x266,
  MIPSFPU = 0x366,
  MIPSFPU16 = 0x466,
  POWERPC = 0x1f0,
  POWERPCFP = 0x1f1,
  R4000 = 0x166,
  RISCV32 = 0x5032,
  RISCV64 = 0x5064,
  RISCV128 = 0x5128,
  SH3 = 0x1a2,
  SH3DSP = 0x1a3,
  SH4 = 0x1a6,
  SH5 = 0x1a8,
  THUMB = 0x1c2,
  WCEMIPSV2 = 0x169,
};

enum pe32_characteristics
{
  RELOCS_STRIPPED = 0x0001,
  EXECUTABLE_IMAGE = 0x0002,
  LINE_NUMS_STRIPPED = 0x0004,
  LOCAL_SYMS_STRIPPED = 0x0008,
  AGGRESSIVE_WS_TRIM = 0x0010,
  LARGE_ADDRESS_AWARE = 0x0020,
  BYTES_REVERSED_LO = 0x0080,
  BIT32_MACHINE = 0x0100,
  DEBUG_STRIPPED = 0x0200,
  REMOVABLE_RUN_FROM_SWAP = 0x0400,
  NET_RUN_FROM_SWAP = 0x0800,
  SYSTEM = 0x1000,
  UP_SYSTEM_ONLY = 0x4000,
  BYTES_REVERSED_HI = 0x8000,
};

enum pe_magic_number
{
  MAGIC_ROM = 0x107,
  MAGIC_32BIT = 0x10b,
  MAGIC_64BIT = 0x20b,
};

enum pe_subsystem
{
  SUBSYSTEM_UNKNOWN = 0,
  NATIVE = 1,
  WINDOWS_GUI = 2,
  WINDOWS_CUI = 3,
  OS2_CUI = 5,
  POSIX_CUI = 7,
  NATIVE_WINDOWS = 8,
  WINDOWS_CE_GUI = 9,
  EFI_APPLICATION = 10,
  EFI_BOOT_SERVICE_DRIVER = 11,
  EFI_RUNTIME_DRIVER = 12,
  EFI_ROM = 13,
  XBOX = 14,
  WINDOWS_BOOT_APPLICATION = 16,
};

enum pe_dll_characteristic
{
  HIGH_ENTROPY_VA = 0x0020,
  DYNAMIC_BASE = 0x0040,
  FORCE_INTEGRITY = 0x0080,
  NX_COMPAT = 0x0100,
  NO_ISOLATION = 0x0200,
  NO_SEH = 0x0400,
  NO_BIND = 0x0800,
  APPCONTAINER = 0x1000,
  WDM_DRIVER = 0x2000,
  GUARD_CF = 0x4000,
  TERMINAL_SERVER_AWARE = 0x8000,
};

typedef struct pe_export_table {
    int32_t   Characteristics;
    int32_t   TimeDateStamp;
    int16_t    MajorVersion;
    int16_t    MinorVersion;
    int32_t   Name;
    int32_t   Base;
    int32_t   NumberOfFunctions;
    int32_t   NumberOfNames;
    int32_t   AddressOfFunctions;     // RVA from base of image
    int32_t   AddressOfNames;         // RVA from base of image
    int32_t   AddressOfNameOrdinals;  // RVA from base of image
} pe_export_table_t;

typedef struct _MYIMAGE_IMPORT_DESCRIPTOR {
    union {
        uint32_t Characteristics;
        uint32_t OriginalFirstThunk;
    };
    uint32_t TimeDateStamp;
    uint32_t ForwarderChain;
    uint32_t Name;
    uint32_t FirstThunk;
} MYIMAGE_IMPORT_DESCRIPTOR, *PMYIMAGE_IMPORT_DESCRIPTOR;

typedef struct _IMAGE_DELAY_IMPORT_DESCRIPTOR
{
    uint32_t grAttrs;
    uint32_t DLLName;
    uint32_t Hmod;
    uint32_t IAT;
    uint32_t INT;
    uint32_t BoundIAT;
    uint32_t UnloadIAT;
    uint32_t TimeDateStamp;
}IMAGE_DELAY_IMPORT_DESCRIPTOR, *PIMAGE_DELAY_IMPORT_DESCRIPTOR;

typedef struct _UNICODE_STR
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR pBuffer;
} UNICODE_STR, * PUNICODE_STR;

typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STR FullDllName;
    UNICODE_STR BaseDllName;
    ULONG Flags;
    SHORT LoadCount;
    SHORT TlsIndex;
    LIST_ENTRY HashTableEntry;
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;
typedef struct _PEB_LDR_DATA //, 7 elements, 0x28 bytes
{
    DWORD dwLength;
    DWORD dwInitialized;
    LPVOID lpSsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    LPVOID lpEntryInProgress;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _PEB_FREE_BLOCK // 2 elements, 0x8 bytes
{
    struct _PEB_FREE_BLOCK* pNext;
    DWORD dwSize;
} PEB_FREE_BLOCK, * PPEB_FREE_BLOCK;

typedef struct __MYPEB // 65 elements, 0x210 bytes
{
    BYTE bInheritedAddressSpace;
    BYTE bReadImageFileExecOptions;
    BYTE bBeingDebugged;
    BYTE bSpareBool;
    LPVOID lpMutant;
    LPVOID lpImageBaseAddress;
    PPEB_LDR_DATA pLdr;
} _MYPEB, * _PMYPEB;

// #ifndef PE_NEW_H
// #define PE_NEW_H

// #include <memory>
// #include <string>
// #include <unordered_map>
// #include <fstream>

// namespace pe_lib
// {
// class PE_OPT
// {
// public:
//     template <typename T>
//     T getValueFrom32Member(const std::string& sMemName, PIMAGE_OPTIONAL_HEADER32 pOpt32) {
//         static std::unordered_map<std::string, T IMAGE_OPTIONAL_HEADER32::*> memberMap = {
//             {"Magic", &IMAGE_OPTIONAL_HEADER32::Magic},
//             {"MajorLinkerVersion", &IMAGE_OPTIONAL_HEADER32::MajorLinkerVersion},
//             {"MinorLinkerVersion", &IMAGE_OPTIONAL_HEADER32::MinorLinkerVersion},
//             {"SizeOfCode", &IMAGE_OPTIONAL_HEADER32::SizeOfCode},
//             {"SizeOfInitializedData", &IMAGE_OPTIONAL_HEADER32::SizeOfInitializedData},
//             {"SizeOfUninitializedData", &IMAGE_OPTIONAL_HEADER32::SizeOfUninitializedData},
//             {"AddressOfEntryPoint", &IMAGE_OPTIONAL_HEADER32::AddressOfEntryPoint},
//             {"BaseOfCode", &IMAGE_OPTIONAL_HEADER32::BaseOfCode},
//             {"BaseOfData", &IMAGE_OPTIONAL_HEADER32::BaseOfData},
//             {"ImageBase", &IMAGE_OPTIONAL_HEADER32::ImageBase},
//             {"SectionAlignment", &IMAGE_OPTIONAL_HEADER32::SectionAlignment},
//             {"FileAlignment", &IMAGE_OPTIONAL_HEADER32::FileAlignment},
//             {"MajorOperatingSystemVersion", &IMAGE_OPTIONAL_HEADER32::MajorOperatingSystemVersion},
//             {"MinorOperatingSystemVersion", &IMAGE_OPTIONAL_HEADER32::MinorOperatingSystemVersion},
//             {"MajorImageVersion", &IMAGE_OPTIONAL_HEADER32::MajorImageVersion},
//             {"MinorImageVersion", &IMAGE_OPTIONAL_HEADER32::MinorImageVersion},
//             {"MajorSubsystemVersion", &IMAGE_OPTIONAL_HEADER32::MajorSubsystemVersion},
//             {"MinorSubsystemVersion", &IMAGE_OPTIONAL_HEADER32::MinorSubsystemVersion},
//             {"Win32VersionValue", &IMAGE_OPTIONAL_HEADER32::Win32VersionValue},
//             {"SizeOfImage", &IMAGE_OPTIONAL_HEADER32::SizeOfImage},
//             {"SizeOfHeaders", &IMAGE_OPTIONAL_HEADER32::SizeOfHeaders},
//             {"CheckSum", &IMAGE_OPTIONAL_HEADER32::CheckSum},
//             {"Subsystem", &IMAGE_OPTIONAL_HEADER32::Subsystem},
//             {"DllCharacteristics", &IMAGE_OPTIONAL_HEADER32::DllCharacteristics},
//             {"SizeOfStackReserve", &IMAGE_OPTIONAL_HEADER32::SizeOfStackReserve},
//             {"SizeOfStackCommit", &IMAGE_OPTIONAL_HEADER32::SizeOfStackCommit},
//             {"SizeOfHeapReserve", &IMAGE_OPTIONAL_HEADER32::SizeOfHeapReserve},
//             {"SizeOfHeapCommit", &IMAGE_OPTIONAL_HEADER32::SizeOfHeapCommit},
//             {"LoaderFlags", &IMAGE_OPTIONAL_HEADER32::LoaderFlags},
//             {"NumberOfRvaAndSizes", &IMAGE_OPTIONAL_HEADER32::NumberOfRvaAndSizes},
//             {"DataDirectory", &IMAGE_OPTIONAL_HEADER32::DataDirectory},
//         };

//         auto it = memberMap.find(sMemName);
//         if (it != memberMap.end()) {
//             return pOpt32->*(it->second);
//         }
//         return T();
//     }

//     template <typename T>
//     T getValueFrom64Member(const std::string& sMemName, PIMAGE_OPTIONAL_HEADER64 pOpt64) {
//         static std::unordered_map<std::string, T IMAGE_OPTIONAL_HEADER64::*> memberMap = {
//             {"Magic", &IMAGE_OPTIONAL_HEADER64::Magic},
//             {"MajorLinkerVersion", &IMAGE_OPTIONAL_HEADER64::MajorLinkerVersion},
//             {"MinorLinkerVersion", &IMAGE_OPTIONAL_HEADER64::MinorLinkerVersion},
//             {"SizeOfCode", &IMAGE_OPTIONAL_HEADER64::SizeOfCode},
//             {"SizeOfInitializedData", &IMAGE_OPTIONAL_HEADER64::SizeOfInitializedData},
//             {"SizeOfUninitializedData", &IMAGE_OPTIONAL_HEADER64::SizeOfUninitializedData},
//             {"AddressOfEntryPoint", &IMAGE_OPTIONAL_HEADER64::AddressOfEntryPoint},
//             {"BaseOfCode", &IMAGE_OPTIONAL_HEADER64::BaseOfCode},
//             {"ImageBase", &IMAGE_OPTIONAL_HEADER64::ImageBase},
//             {"SectionAlignment", &IMAGE_OPTIONAL_HEADER64::SectionAlignment},
//             {"FileAlignment", &IMAGE_OPTIONAL_HEADER64::FileAlignment},
//             {"MajorOperatingSystemVersion", &IMAGE_OPTIONAL_HEADER64::MajorOperatingSystemVersion},
//             {"MinorOperatingSystemVersion", &IMAGE_OPTIONAL_HEADER64::MinorOperatingSystemVersion},
//             {"MajorImageVersion", &IMAGE_OPTIONAL_HEADER64::MajorImageVersion},
//             {"MinorImageVersion", &IMAGE_OPTIONAL_HEADER64::MinorImageVersion},
//             {"MajorSubsystemVersion", &IMAGE_OPTIONAL_HEADER64::MajorSubsystemVersion},
//             {"MinorSubsystemVersion", &IMAGE_OPTIONAL_HEADER64::MinorSubsystemVersion},
//             {"Win32VersionValue", &IMAGE_OPTIONAL_HEADER64::Win32VersionValue},
//             {"SizeOfImage", &IMAGE_OPTIONAL_HEADER64::SizeOfImage},
//             {"SizeOfHeaders", &IMAGE_OPTIONAL_HEADER64::SizeOfHeaders},
//             {"CheckSum", &IMAGE_OPTIONAL_HEADER64::CheckSum},
//             {"Subsystem", &IMAGE_OPTIONAL_HEADER64::Subsystem},
//             {"DllCharacteristics", &IMAGE_OPTIONAL_HEADER64::DllCharacteristics},
//             {"SizeOfStackReserve", &IMAGE_OPTIONAL_HEADER64::SizeOfStackReserve},
//             {"SizeOfStackCommit", &IMAGE_OPTIONAL_HEADER64::SizeOfStackCommit},
//             {"SizeOfHeapReserve", &IMAGE_OPTIONAL_HEADER64::SizeOfHeapReserve},
//             {"SizeOfHeapCommit", &IMAGE_OPTIONAL_HEADER64::SizeOfHeapCommit},
//             {"LoaderFlags", &IMAGE_OPTIONAL_HEADER64::LoaderFlags},
//             {"NumberOfRvaAndSizes", &IMAGE_OPTIONAL_HEADER64::NumberOfRvaAndSizes},
//             {"DataDirectory", &IMAGE_OPTIONAL_HEADER64::DataDirectory},
//         };

//         auto it = memberMap.find(sMemName);
//         if (it != memberMap.end()) {
//             return pOpt64->*(it->second);
//         }
//         return T();
//     }

//     template <typename T>
//     T operator[](std::string key) const {
//         return mOptHdr32 ? getValueFrom32Member<T>(key, mOptHdr32) : getValueFrom64Member<T>(key, mOptHdr64);
//     }

//     void set_opt32(PIMAGE_OPTIONAL_HEADER32 opt32)
//     {
//         mOptHdr32 = opt32;
//     }

//     void set_opt64(PIMAGE_OPTIONAL_HEADER64 opt64)
//     {
//         mOptHdr64 = opt64;
//     }

// private:
//     PIMAGE_OPTIONAL_HEADER32 mOptHdr32;
//     PIMAGE_OPTIONAL_HEADER64 mOptHdr64;
// };

// enum my_pe_machine_type
// {
//     MACHINE_UNKNOWN = 0x0,
//     AM33 = 0x1d3,
//     AMD64 = 0x8664,
//     ARM = 0x1c0,
//     ARM64 = 0xaa64,
//     ARMNT = 0x1c4,
//     EBC = 0xebc,
//     I386 = 0x14c,
//     IA64 = 0x200,
//     M32R = 0x9041,
//     MIPS16 = 0x266,
//     MIPSFPU = 0x366,
//     MIPSFPU16 = 0x466,
//     POWERPC = 0x1f0,
//     POWERPCFP = 0x1f1,
//     R4000 = 0x166,
//     RISCV32 = 0x5032,
//     RISCV64 = 0x5064,
//     RISCV128 = 0x5128,
//     SH3 = 0x1a2,
//     SH3DSP = 0x1a3,
//     SH4 = 0x1a6,
//     SH5 = 0x1a8,
//     THUMB = 0x1c2,
//     WCEMIPSV2 = 0x169,
// };

// class PE
// {
// public:

//     PE() = default;
//     ~PE() = default;

//     template <typename T>
//     T load_from_file(std::string path, bool file)
//     {
//         std::ofstream fil(path, std::ios::binary);
//         if (!fil.is_open()) {
//             return -1;
//         }
//         file ? fil.write(mFileBuf.data(), mFileBuf.size())
//              : fil.write(mImageBuf.data(), mImageBuf.size());
//         fil.close();
//         int typ = 0;
//         file ? typ = parse_pe(mFileBuf, mFileBuf.size(), true)
//              : typ = parse_pe(mImageBuf, mImageBuf.size(), false);
        
//         if(typ == 0) // exe
//         {
//             PE_EXE exe(1);
//             return T(exe);
//         }
        
//         return T(-1);
//     }
//     bool load_from_buf(char* buf, size_t size, bool file);

// private:
    
//     int parse_pe(std::vector<char> buf, size_t size, bool file)
//     {
//         int typ = 0;
//         mDosHdr = reinterpret_cast<PIMAGE_DOS_HEADER>(mFileBuf.data());
//         mFileHdr = reinterpret_cast<PIMAGE_FILE_HEADER>(reinterpret_cast<char*>(mFileBuf.data()) + mDosHdr->e_lfanew);
//         if(mFileHdr->Machine == my_pe_machine_type::I386)
//         {
//             PIMAGE_OPTIONAL_HEADER32 opt32 = reinterpret_cast<PIMAGE_OPTIONAL_HEADER32>(reinterpret_cast<char*>(mFileHdr) + sizeof(IMAGE_FILE_HEADER));
//             mOptHdr.set_opt32(opt32);
//         }
//         else if(mFileHdr->Machine == my_pe_machine_type::AMD64)
//         {
//             PIMAGE_OPTIONAL_HEADER64 opt64 = reinterpret_cast<PIMAGE_OPTIONAL_HEADER64>(reinterpret_cast<char*>(mFileHdr) + sizeof(IMAGE_FILE_HEADER));
//             mOptHdr.set_opt64(opt64);
//         }
//         return typ;
//     }

//     PIMAGE_DOS_HEADER    mDosHdr;
//     PIMAGE_FILE_HEADER   mFileHdr;
//     PE_OPT               mOptHdr;

//     FILE                 mFile;

//     std::vector<char> mFileBuf;
//     std::vector<char> mImageBuf;
// };
// }

// #endif

#endif