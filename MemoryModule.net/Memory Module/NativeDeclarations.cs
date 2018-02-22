/*                                                               
 * Memory Module.net 0.2
 * 
 * Loading a native Dll from memory, a C#/.net port of Memory Module
 * 
 * (c) 2012-2018 by Andreas Kanzler (andi_kanzler(at)gmx.de)
 * 
 * Memory Module is original developed by Joachim Bauch (mail(at)joachim-bauch.de)  
 * https://github.com/fancycode/MemoryModule
 * http://www.joachim-bauch.de/tutorials/loading-a-dll-from-memory/                
 *                                                                                
 * 
 * The contents of this file are subject to the Mozilla Public License Version
 * 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is MemoryModule.c
 *
 * The Initial Developer of the Original Code is Joachim Bauch.
 *
 * Portions created by Andreas Kanzler are Copyright (c)2012
 * Andreas Kanzler. All Rights Reserved.
 * 
 */


using System;
using System.Runtime.InteropServices;

namespace Scavanger.MemoryModule
{
    #region structs
    [StructLayout(LayoutKind.Sequential)]
    public unsafe struct IMAGE_DOS_HEADER32
    {
        public ushort e_magic;       // Magic number
        public ushort e_cblp;    // Bytes on last page of file
        public ushort e_cp;      // Pages in file
        public ushort e_crlc;    // Relocations
        public ushort e_cparhdr;     // Size of header in paragraphs
        public ushort e_minalloc;    // Minimum extra paragraphs needed
        public ushort e_maxalloc;    // Maximum extra paragraphs needed
        public ushort e_ss;      // Initial (relative) SS value
        public ushort e_sp;      // Initial SP value
        public ushort e_csum;    // Checksum
        public ushort e_ip;      // Initial IP value
        public ushort e_cs;      // Initial (relative) CS value
        public ushort e_lfarlc;      // File address of relocation table
        public ushort e_ovno;    // Overlay number
        public fixed ushort e_res1[4];    // Reserved words
        public ushort e_oemid;       // OEM identifier (for e_oeminfo)
        public ushort e_oeminfo;     // OEM information; e_oemid specific
        public fixed ushort e_res2[10];    // Reserved words
        public int e_lfanew;      // File address of new exe header
    }

    [StructLayout(LayoutKind.Sequential)]
    public unsafe struct IMAGE_NT_HEADERS32
    {
        public uint Signature;
        public IMAGE_FILE_HEADER FileHeader;
        public IMAGE_OPTIONAL_HEADER32 OptionalHeader;
    }

    [StructLayout(LayoutKind.Sequential)]
    public unsafe struct IMAGE_FILE_HEADER
    {
        public ushort Machine;
        public ushort NumberOfSections;
        public uint TimeDateStamp;
        public uint PointerToSymbolTable;
        public uint NumberOfSymbols;
        public ushort SizeOfOptionalHeader;
        public ushort Characteristics;
    }

    [StructLayout(LayoutKind.Sequential)]
    public unsafe struct IMAGE_OPTIONAL_HEADER32
    {
        public MagicType Magic;
        public byte MajorLinkerVersion;
        public byte MinorLinkerVersion;
        public uint SizeOfCode;
        public uint SizeOfInitializedData;
        public uint SizeOfUninitializedData;
        public uint AddressOfEntryPoint;
        public uint BaseOfCode;
        // PE32 contains this additional field
        public uint BaseOfData;
        public uint ImageBase;
        public uint SectionAlignment;
        public uint FileAlignment;
        public ushort MajorOperatingSystemVersion;
        public ushort MinorOperatingSystemVersion;
        public ushort MajorImageVersion;
        public ushort MinorImageVersion;
        public ushort MajorSubsystemVersion;
        public ushort MinorSubsystemVersion;
        public uint Win32VersionValue;
        public uint SizeOfImage;
        public uint SizeOfHeaders;
        public uint CheckSum;
        public SubSystemType Subsystem;
        public DllCharacteristicsType DllCharacteristics;
        public uint SizeOfStackReserve;
        public uint SizeOfStackCommit;
        public uint SizeOfHeapReserve;
        public uint SizeOfHeapCommit;
        public uint LoaderFlags;
        public uint NumberOfRvaAndSizes;
        public IMAGE_DATA_DIRECTORY ExportTable;
        public IMAGE_DATA_DIRECTORY ImportTable;
        public IMAGE_DATA_DIRECTORY ResourceTable;
        public IMAGE_DATA_DIRECTORY ExceptionTable;
        public IMAGE_DATA_DIRECTORY CertificateTable;
        public IMAGE_DATA_DIRECTORY BaseRelocationTable;
        public IMAGE_DATA_DIRECTORY Debug;
        public IMAGE_DATA_DIRECTORY Architecture;
        public IMAGE_DATA_DIRECTORY GlobalPtr;
        public IMAGE_DATA_DIRECTORY TLSTable;
        public IMAGE_DATA_DIRECTORY LoadConfigTable;
        public IMAGE_DATA_DIRECTORY BoundImport;
        public IMAGE_DATA_DIRECTORY IAT;
        public IMAGE_DATA_DIRECTORY DelayImportDescriptor;
        public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
        public IMAGE_DATA_DIRECTORY Reserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    public unsafe struct IMAGE_DATA_DIRECTORY
    {
        public uint VirtualAddress;
        public uint Size;
    }

    [StructLayout(LayoutKind.Sequential)]
    public unsafe struct IMAGE_SECTION_HEADER
    {
        public fixed byte Name[8];
        public uint PhysicalAddress;
        public uint VirtualAddress;
        public uint SizeOfRawData;
        public uint PointerToRawData;
        public uint PointerToRelocations;
        public uint PointerToLinenumbers;
        public ushort NumberOfRelocations;
        public ushort NumberOfLinenumbers;
        public uint Characteristics;
    }

    [StructLayout(LayoutKind.Sequential)]
    public unsafe struct IMAGE_BASE_RELOCATION
    {
        public uint VirtualAdress;
        public uint SizeOfBlock;
    }

    [StructLayout(LayoutKind.Sequential)]
    public unsafe struct IMAGE_IMPORT_DESCRIPTOR
    {
        public uint OriginalFirstThunk;
        public uint TimeDateStamp;
        public uint ForwarderChain;
        public uint Name;
        public uint FirstThunk;
    }

    [StructLayout(LayoutKind.Sequential)]
    public unsafe struct IMAGE_EXPORT_DIRECTORY
    {
        public uint Characteristics;
        public uint TimeDateStamp;
        public ushort MajorVersion;
        public ushort MinorVersion;
        public uint Name;
        public uint Base;
        public uint NumberOfFunctions;
        public uint NumberOfNames;
        public uint AddressOfFunctions;     // RVA from base of image
        public uint AddressOfNames;         // RVA from base of image
        public uint AddressOfNameOrdinals;  // RVA from base of image
    }

    [StructLayout(LayoutKind.Sequential)]
    public unsafe struct IMAGE_IMPORT_BY_NAME
    {
        public ushort Hint;
        public fixed byte Name[1];
    }

    [StructLayout(LayoutKind.Sequential)]
    public unsafe struct SYSTEM_INFO
    {
        public ushort wProcessorArchitecture;
        public ushort wReserved;
        public uint dwPageSize;
        public void* lpMinimumApplicationAddress;
        public void* lpMaximumApplicationAddress;
        public void* dwActiveProcessorMask;
        public uint dwNumberOfProcessors;
        public uint dwProcessorType;
        public uint dwAllocationGranularity;
        public ushort wProcessorLevel;
        public ushort wProcessorRevision;
    };

    [StructLayout(LayoutKind.Sequential)]
    public unsafe struct IMAGE_TLS_DIRECTORY
    {
        public uint StartAddressOfRawData;
        public uint EndAddressOfRawData;
        public uint AddressOfIndex;             // PDWORD
        public uint AddressOfCallBacks;         // PIMAGE_TLS_CALLBACK *
        public uint SizeOfZeroFill;
        public uint Characteristics;
        // union not defined, we don't use it
    }
    #endregion

    #region enums
    public enum MagicType : ushort
    {
        IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b,
        IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b
    }

    public enum SubSystemType : ushort
    {
        IMAGE_SUBSYSTEM_UNKNOWN = 0,
        IMAGE_SUBSYSTEM_NATIVE = 1,
        IMAGE_SUBSYSTEM_WINDOWS_GUI = 2,
        IMAGE_SUBSYSTEM_WINDOWS_CUI = 3,
        IMAGE_SUBSYSTEM_POSIX_CUI = 7,
        IMAGE_SUBSYSTEM_WINDOWS_CE_GUI = 9,
        IMAGE_SUBSYSTEM_EFI_APPLICATION = 10,
        IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 11,
        IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER = 12,
        IMAGE_SUBSYSTEM_EFI_ROM = 13,
        IMAGE_SUBSYSTEM_XBOX = 14

    }

    public enum DllCharacteristicsType : ushort
    {
        RES_0 = 0x0001,
        RES_1 = 0x0002,
        RES_2 = 0x0004,
        RES_3 = 0x0008,
        IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE = 0x0040,
        IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY = 0x0080,
        IMAGE_DLL_CHARACTERISTICS_NX_COMPAT = 0x0100,
        IMAGE_DLLCHARACTERISTICS_NO_ISOLATION = 0x0200,
        IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400,
        IMAGE_DLLCHARACTERISTICS_NO_BIND = 0x0800,
        RES_4 = 0x1000,
        IMAGE_DLLCHARACTERISTICS_WDM_DRIVER = 0x2000,
        IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000
    }

    enum BasedRelocationType
    {
        IMAGE_REL_BASED_ABSOLUTE = 0,
        IMAGE_REL_BASED_HIGH = 1,
        IMAGE_REL_BASED_LOW = 2,
        IMAGE_REL_BASED_HIGHLOW = 3,
        IMAGE_REL_BASED_HIGHADJ = 4,
        IMAGE_REL_BASED_MIPS_JMPADDR = 5,
        IMAGE_REL_BASED_MIPS_JMPADDR16 = 9,
        IMAGE_REL_BASED_IA64_IMM64 = 9,
        IMAGE_REL_BASED_DIR64 = 10
    }

    [Flags()]
    public enum AllocationType : uint
    {
        COMMIT = 0x1000,
        RESERVE = 0x2000,
        RESET = 0x80000,
        LARGE_PAGES = 0x20000000,
        PHYSICAL = 0x400000,
        TOP_DOWN = 0x100000,
        WRITE_WATCH = 0x200000,
        DECOMMIT = 0x4000,
        RELEASE = 0x8000
    }

    [Flags()]
    public enum MemoryProtection : uint
    {
        EXECUTE = 0x10,
        EXECUTE_READ = 0x20,
        EXECUTE_READWRITE = 0x40,
        EXECUTE_WRITECOPY = 0x80,
        NOACCESS = 0x01,
        READONLY = 0x02,
        READWRITE = 0x04,
        WRITECOPY = 0x08,
        GUARD_Modifierflag = 0x100,
        NOCACHE_Modifierflag = 0x200,
        WRITECOMBINE_Modifierflag = 0x400
    }

    [Flags()]
    public enum PageProtection
    {
        NOACCESS = 0x01,
        READONLY = 0x02,
        READWRITE = 0x04,
        WRITECOPY = 0x08,
        EXECUTE = 0x10,
        EXECUTE_READ = 0x20,
        EXECUTE_READWRITE = 0x40,
        EXECUTE_WRITECOPY = 0x80,
        GUARD = 0x100,
        NOCACHE = 0x200,
        WRITECOMBINE = 0x400,
    }

    public enum ImageSectionFlags : uint
    {
        IMAGE_SCN_LNK_NRELOC_OVFL = 0x01000000,  // Section contains extended relocations.
        IMAGE_SCN_MEM_DISCARDABLE = 0x02000000,  // Section can be discarded.
        IMAGE_SCN_MEM_NOT_CACHED = 0x04000000,  // Section is not cachable.
        IMAGE_SCN_MEM_NOT_PAGED = 0x08000000, // Section is not pageable.
        IMAGE_SCN_MEM_SHARED = 0x10000000,  // Section is shareable.
        IMAGE_SCN_MEM_EXECUTE = 0x20000000, // Section is executable.
        IMAGE_SCN_MEM_READ = 0x40000000, // Section is readable.
        IMAGE_SCN_MEM_WRITE = 0x80000000  // Section is writeable.
    }

    public enum ImageSectionContains : uint
    {
        CODE = 0x00000020,  // Section contains code.
        INITIALIZED_DATA = 0x00000040,  // Section contains initialized data.
        UNINITIALIZED_DATA = 0x00000080  // Section contains uninitialized data.
    }

    public enum DllReason : uint
    {
        DLL_PROCESS_ATTACH = 1,
        DLL_THREAD_ATTACH = 2,
        DLL_THREAD_DETACH = 3,
        DLL_PROCESS_DETACH = 0
    }
    #endregion

    unsafe class NativeDeclarations
    {
        public const ushort IMAGE_DOS_SIGNATURE = 0x5A4D;
        public const uint IMAGE_NT_SIGNATURE = 0x00004550;
        public const uint IMAGE_FILE_MACHINE_I386 = 0x014c;
        public const uint IMAGE_FILE_MACHINE_AMD64 = 0x8664;
        public const uint PAGE_NOCACHE = 0x200;
        public const uint IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040;
        public const uint IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080;
        public const uint IMAGE_SCN_MEM_DISCARDABLE = 0x02000000;
        public const uint IMAGE_SCN_MEM_NOT_CACHED = 0x04000000;
        public const uint IMAGE_FILE_DLL = 0x2000;

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern void* VirtualAlloc(void* lpAddress, uint dwSize, AllocationType flAllocationType, MemoryProtection flProtect);

        [DllImport("msvcrt.dll", EntryPoint = "memset", CallingConvention = CallingConvention.Cdecl, SetLastError = false)]
        public static extern void* MemSet(void* dest, int c, void* count);

        [DllImport("kernel32.dll")]
        public static extern bool IsBadReadPtr(void* lp, uint ucb);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern void* LoadLibrary(string lpFileName);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        public static extern void* GetProcAddress(void* hModule, string procName);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool VirtualFree(void* lpAddress, uint dwSize, AllocationType dwFreeType);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool VirtualProtect(void* lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool FreeLibrary(void* hModule);

        [DllImport("kernel32.dll")]
        public static extern void GetNativeSystemInfo(SYSTEM_INFO* lpSystemInfo);

        /// <summary>
        /// Equivalent to the IMAGE_FIRST_SECTION macro
        /// </summary>
        /// <param name="ntheader">Pointer to to ntheader</param>
        /// <returns>Pointer to the first section</returns>
        public static IMAGE_SECTION_HEADER* IMAGE_FIRST_SECTION(IMAGE_NT_HEADERS32* ntheader)
        {
            return ((IMAGE_SECTION_HEADER*)((int)ntheader +
                 (int)Marshal.OffsetOf(typeof(IMAGE_NT_HEADERS32), "OptionalHeader") +
                 ntheader->FileHeader.SizeOfOptionalHeader));
        }

        /// <summary>
        /// Equivalent to the IMAGE_ORDINAL32 macro
        /// </summary>
        public static uint IMAGE_ORDINAL32(uint ordinal)
        {
            return ordinal & 0xffff;
        }

        /// <summary>
        /// Equivalent to the IMAGE_SNAP_BY_ORDINAL32 macro
        /// </summary>
        public static bool IMAGE_SNAP_BY_ORDINAL32(uint ordinal)
        {
            return ((ordinal & 0x80000000) != 0);
        }
    }
}
