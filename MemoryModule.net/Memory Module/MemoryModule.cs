/*                                                               
 * Memory Module.net 0.2
 * 
 * Loading a native Dll from memory, a C#/.net port of Memory Module
 * 
 * (c) 2012 - 2018 by Andreas Kanzler (andi_kanzler(at)gmx.de)
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
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.ComponentModel;
using System.Linq;

namespace Scavanger.MemoryModule
{
    unsafe class MemoryModule : IDisposable
    {
        public bool Disposed { get; private set; }
        public bool IsRelocated { get; private set; }
        public bool IsDll { get; private set; }

        private GCHandle _dataHandle;
        private IMAGE_NT_HEADERS32* _headers;
        private byte* _codeBase;
        private List<IntPtr> _modules;
        private bool _initialized;
        private uint _pageSize;
        private DllEntryDelegate _dllEntry;
        private ExeEntryDelegate _exeEntry;

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        private delegate bool DllEntryDelegate(void* hinstDLL, DllReason fdwReason, void* lpReserved);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        private delegate int ExeEntryDelegate();

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate void ImageTlsDelegate(void* dllHandle, DllReason reason, void* reserved);



        /// <summary>
        /// Loads a unmanged (native) DLL in the memory.
        /// </summary>
        /// <param name="data">Dll as a byte array</param>
        public MemoryModule(byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException("data");

            _headers = null;
            _codeBase = null;
            _pageSize = 0;
            _modules = new List<IntPtr>();
            _initialized = false;
            _exeEntry = null;
            _dllEntry = null;

            Disposed = false;
            IsRelocated = false;

            MemoryLoadLibrary(data);
        }

        ~MemoryModule()
        {
            Dispose();
        }

        /// <summary>
        /// Returns a delegate for a function inside the DLL.
        /// </summary>
        /// <param name="funcName">The Name of the function to be searched.</param>
        /// <param name="t">The type of the delegate to be returned.</param>
        /// <returns>A delegate instance that can be cast to the appropriate delegate type.</returns>
        public Delegate GetDelegateFromFuncName(string funcName, Type t)
        {
            if (Disposed)
                throw new InvalidOperationException("Object disposed");

            if (!IsDll)
                throw new InvalidOperationException("Loaded Module is not a DLL");

            if (string.IsNullOrEmpty(funcName))
                throw new ArgumentException("funcName");

            if (t == null)
                throw new ArgumentNullException("t");

            if (Disposed)
                throw new ObjectDisposedException("MemoryModule");

            if (!_initialized)
                throw new InvalidOperationException("Dll is not initialized.");

            funcName = funcName.ToLower(); //Ignore case

            //Todo:
            // Add support for stdcall: _funcname@

            int idx = -1;
            uint* nameRef;
            ushort* ordinal;
            IMAGE_EXPORT_DIRECTORY* exports;
            void* funcPtr;
            Dictionary<string, int> exportEntrys = new Dictionary<string, int>();

            IMAGE_DATA_DIRECTORY* directory = &_headers->OptionalHeader.ExportTable;
            if (directory->Size == 0)
                throw new NativeDllLoadException("Dll has no export table.");

            exports = (IMAGE_EXPORT_DIRECTORY*)(_codeBase + directory->VirtualAddress);
            if (exports->NumberOfFunctions == 0 || exports->NumberOfNames == 0)
                throw new NativeDllLoadException("Dll exports no functions.");

            nameRef = (uint*)(_codeBase + exports->AddressOfNames);
            ordinal = (ushort*)(_codeBase + exports->AddressOfNameOrdinals);
            for (int i = 0; i < exports->NumberOfNames; i++, nameRef++, ordinal++)
            {
                string curFuncName = Marshal.PtrToStringAnsi((IntPtr)(_codeBase + *nameRef));
                exportEntrys.Add(curFuncName.ToLower(), *ordinal);
            }

            if (!exportEntrys.Keys.Contains(funcName))
                throw new NativeDllLoadException("Dll exports no function named " + funcName);

            idx = exportEntrys[funcName];

            if (idx > exports->NumberOfFunctions)
                throw new NativeDllLoadException("IDX don't match number of funtions.");

            funcPtr = _codeBase + (*(uint*)(_codeBase + exports->AddressOfFunctions + (idx * 4)));
            return Marshal.GetDelegateForFunctionPointer((IntPtr)funcPtr, t);
        }

        /// <summary>
        /// Call entry point of executable.
        /// </summary>
        /// <returns>Exitcode of executable</returns>
        public int MemoryCallEntryPoint()
        {
            if (Disposed)
                throw new InvalidOperationException("Object disposed");

            if (IsDll || _exeEntry == null || !IsRelocated)
                throw new NativeDllLoadException("Unable to call entry point. Is loaded module a dll?");

            return _exeEntry();
        }

        private void MemoryLoadLibrary(byte[] data)
        {
            IMAGE_DOS_HEADER32* dosHeader;
            IMAGE_NT_HEADERS32* oldHeader;
            IMAGE_SECTION_HEADER* section;
            SYSTEM_INFO systemInfo;
            void* dllEntryPtr;
            void* exeEntryPtr;
            byte* headers, dataPtr, code;
            uint optionalSectionSize;
            uint lastSectionEnd = 0;
            uint alignedImageSize;
            uint locationDelta;

            _dataHandle = GCHandle.Alloc(data, GCHandleType.Pinned);
            if (!_dataHandle.IsAllocated)
                throw new NativeDllLoadException("Can't allocate memory.");

            dataPtr = (byte*)_dataHandle.AddrOfPinnedObject().ToPointer();

            dosHeader = (IMAGE_DOS_HEADER32*)dataPtr;
            if (dosHeader->e_magic != NativeDeclarations.IMAGE_DOS_SIGNATURE)
                throw new BadImageFormatException("Not a valid executable file.");

            oldHeader = (IMAGE_NT_HEADERS32*)(dataPtr + dosHeader->e_lfanew);
            if (oldHeader->Signature != NativeDeclarations.IMAGE_NT_SIGNATURE)
                throw new BadImageFormatException("Not a valid PE file.");

            if (oldHeader->FileHeader.Machine != GetMachineType())
                throw new BadImageFormatException("Machine type doesn't fit. (i386 vs. AMD64)");

            if ((oldHeader->OptionalHeader.SectionAlignment & 1) > 0)
                throw new BadImageFormatException("Wrong section alignment");

            section = NativeDeclarations.IMAGE_FIRST_SECTION(oldHeader);
            optionalSectionSize = oldHeader->OptionalHeader.SectionAlignment;
            for (int i = 0; i < oldHeader->FileHeader.NumberOfSections; i++, section++)
            {
                uint endOfSection;
                if (section->SizeOfRawData == 0) // Section without data in the DLL           
                    endOfSection = section->VirtualAddress + optionalSectionSize;
                else
                    endOfSection = section->VirtualAddress + section->SizeOfRawData;

                if (endOfSection > lastSectionEnd)
                    lastSectionEnd = endOfSection;
            }

            NativeDeclarations.GetNativeSystemInfo(&systemInfo);
            alignedImageSize = AlignValueUp(oldHeader->OptionalHeader.SizeOfImage, systemInfo.dwPageSize);
            if (alignedImageSize != AlignValueUp(lastSectionEnd, systemInfo.dwPageSize))
                throw new BadImageFormatException("Wrong section alignment.");

            code = (byte*)NativeDeclarations.VirtualAlloc(
                (void*)(oldHeader->OptionalHeader.ImageBase),
                oldHeader->OptionalHeader.SizeOfImage,
                AllocationType.RESERVE,
                MemoryProtection.READWRITE);

            if (code == null)
            {
                code = (byte*)NativeDeclarations.VirtualAlloc(
                null,
                oldHeader->OptionalHeader.SizeOfImage,
                AllocationType.RESERVE,
                MemoryProtection.READWRITE);
            }

            if (code == null)
                throw new NativeDllLoadException("Out of Memory");

            //NativeDeclarations.VirtualAlloc(
            //    new IntPtr(code),
            //    ntHeader->OptionalHeader.SizeOfImage,
            //    AllocationType.COMMIT,
            //    MemoryProtection.READWRITE);

            _pageSize = systemInfo.dwPageSize;
            _codeBase = code;
            IsDll = (oldHeader->FileHeader.Characteristics & NativeDeclarations.IMAGE_FILE_DLL) != 0;

            headers = (byte*)NativeDeclarations.VirtualAlloc(
                code,
                oldHeader->OptionalHeader.SizeOfHeaders,
                AllocationType.COMMIT,
                MemoryProtection.READWRITE);

            if (headers == null)
                throw new Win32Exception();

            Marshal.Copy(data, 0, new IntPtr(headers), (int)(dosHeader->e_lfanew + oldHeader->OptionalHeader.SizeOfHeaders));
            _headers = (IMAGE_NT_HEADERS32*)&((headers))[dosHeader->e_lfanew];

            _headers->OptionalHeader.ImageBase = (uint)code;

            CopySections(data, oldHeader);

            locationDelta = _headers->OptionalHeader.ImageBase - oldHeader->OptionalHeader.ImageBase;
            if (locationDelta != 0)
                IsRelocated = PerformBaseRelocation(locationDelta);
            else
                IsRelocated = false;

            BuildImportTable();
            FinalizeSections();
            ExecuteTLS();

            if (_headers->OptionalHeader.AddressOfEntryPoint == 0)
                throw new NativeDllLoadException("DLL has no entry point");

            if (IsDll)
            {
                dllEntryPtr = code + _headers->OptionalHeader.AddressOfEntryPoint;
                _dllEntry = (DllEntryDelegate)Marshal.GetDelegateForFunctionPointer((IntPtr)dllEntryPtr, typeof(DllEntryDelegate));

                if (_dllEntry != null && _dllEntry(code, DllReason.DLL_PROCESS_ATTACH, null))
                    _initialized = true;
                else
                {
                    _initialized = false;
                    throw new NativeDllLoadException("Can't attach DLL to process.");
                }
            }
            else
            {
                exeEntryPtr = code + _headers->OptionalHeader.AddressOfEntryPoint;
                _exeEntry = (ExeEntryDelegate)Marshal.GetDelegateForFunctionPointer((IntPtr)exeEntryPtr, typeof(ExeEntryDelegate));

            }
        }

        private void ExecuteTLS()
        {
            IMAGE_TLS_DIRECTORY* tls;
            byte* callbackPtr;
            ImageTlsDelegate tlsdelegate;

            IMAGE_DATA_DIRECTORY* directory = &_headers->OptionalHeader.TLSTable;
            if (directory->VirtualAddress == 0)
                return;

            tls = (IMAGE_TLS_DIRECTORY*)(_codeBase + directory->VirtualAddress);
            callbackPtr = (byte*)tls->AddressOfCallBacks;
            if (callbackPtr != null)
            {
                while (*callbackPtr > 0)
                {
                    tlsdelegate = (ImageTlsDelegate)Marshal.GetDelegateForFunctionPointer((IntPtr)callbackPtr, typeof(ImageTlsDelegate));
                    tlsdelegate(_codeBase, DllReason.DLL_PROCESS_ATTACH, null);
                    callbackPtr++;
                }
            }

        }

        private readonly PageProtection[,,] ProtectionFlags = new PageProtection[,,]
        {
            {
                { PageProtection.NOACCESS, PageProtection.WRITECOPY },
                { PageProtection.READONLY, PageProtection.READWRITE }
            },
            {
                { PageProtection.EXECUTE, PageProtection.WRITECOPY },
                { PageProtection.EXECUTE_READ, PageProtection.EXECUTE_READWRITE }
            }

        };

        private void FinalizeSections()
        {
            IMAGE_SECTION_HEADER* section = NativeDeclarations.IMAGE_FIRST_SECTION(_headers);

            uint imageOffset = 0;

            SectionFinalizeData sectionData = new SectionFinalizeData();
            sectionData.Address = (void*)(section->PhysicalAddress | imageOffset);
            sectionData.AlignedAddress = AlignAddressDown(sectionData.Address, _pageSize);
            sectionData.Size = GetRealSectionSize(section);
            sectionData.Characteristics = section->Characteristics;
            sectionData.Last = false;
            section++;

            // loop through all sections and change access flags
            for (int i = 1; i < _headers->FileHeader.NumberOfSections; i++, section++)
            {
                void* sectionAddress = (void*)((uint)section->PhysicalAddress | imageOffset);
                void* alignedAddress = AlignAddressDown(sectionAddress, _pageSize);
                uint sectionSize = GetRealSectionSize(section);
                // Combine access flags of all sections that share a page
                // TODO(fancycode): We currently share flags of a trailing large section
                //   with the page of a first small section. This should be optimized.
                if (sectionData.AlignedAddress == alignedAddress || (uint)sectionData.Address + sectionData.Size > (uint)alignedAddress)
                {
                    // Section shares page with previous
                    if ((section->Characteristics & NativeDeclarations.IMAGE_SCN_MEM_DISCARDABLE) == 0 || (sectionData.Characteristics & NativeDeclarations.IMAGE_SCN_MEM_DISCARDABLE) == 0)
                    {
                        sectionData.Characteristics = (sectionData.Characteristics | section->Characteristics) & ~NativeDeclarations.IMAGE_SCN_MEM_DISCARDABLE;
                    }
                    else
                    {
                        sectionData.Characteristics |= section->Characteristics;
                    }
                    sectionData.Size = (((uint)sectionAddress) + (sectionSize)) - (uint)sectionData.Address;
                    continue;
                }

                FinalizeSection(sectionData);

                sectionData.Address = sectionAddress;
                sectionData.AlignedAddress = alignedAddress;
                sectionData.Size = sectionSize;
                sectionData.Characteristics = section->Characteristics;
            }
            sectionData.Last = true;
            FinalizeSection(sectionData);
        }

        private void FinalizeSection(SectionFinalizeData sectionData)
        {
            uint protect, oldProtect;
            int executable;
            int readable;
            int writeable;

            if (sectionData.Size == 0)
                return;

            if ((sectionData.Characteristics & NativeDeclarations.IMAGE_SCN_MEM_DISCARDABLE) > 0)
            {
                // section is not needed any more and can safely be freed
                if (sectionData.Address == sectionData.AlignedAddress &&
                    (sectionData.Last ||
                     _headers->OptionalHeader.SectionAlignment == _pageSize ||
                     (sectionData.Size % _pageSize) == 0)
                   )
                {
                    // Only allowed to decommit whole pages
                    NativeDeclarations.VirtualFree(sectionData.Address, sectionData.Size, AllocationType.DECOMMIT);
                }
                return;
            }

            // determine protection flags based on characteristics
            executable = (sectionData.Characteristics & (uint)ImageSectionFlags.IMAGE_SCN_MEM_EXECUTE) != 0 ? 1 : 0;
            readable = (sectionData.Characteristics & (uint)ImageSectionFlags.IMAGE_SCN_MEM_READ) != 0 ? 1 : 0;
            writeable = (sectionData.Characteristics & (uint)ImageSectionFlags.IMAGE_SCN_MEM_WRITE) != 0 ? 1 : 0;
            protect = (uint)ProtectionFlags[executable, readable, writeable];
            if ((sectionData.Characteristics & NativeDeclarations.IMAGE_SCN_MEM_NOT_CACHED) > 0)
            {
                protect |= NativeDeclarations.PAGE_NOCACHE;
            }

            // change memory access flags
            if (!NativeDeclarations.VirtualProtect(sectionData.Address, sectionData.Size, protect, out oldProtect))
                throw new NativeDllLoadException("Error protecting memory page");
        }


        // Old FinalizeSections
        //private void FinalizeSections()
        //{
        //    int imageOffset = 0;

        //    IMAGE_SECTION_HEADER* section = (IMAGE_SECTION_HEADER*)NativeDeclarations.IMAGE_FIRST_SECTION(_headers);

        //    for (int i = 0; i < _headers->FileHeader.NumberOfSections; i++, section++)
        //    {
        //        uint protect, oldProtect, size;

        //        int executable = (section->Characteristics & (uint)ImageSectionFlags.IMAGE_SCN_MEM_EXECUTE) != 0 ? 1 : 0;
        //        int readable = (section->Characteristics & (uint)ImageSectionFlags.IMAGE_SCN_MEM_READ) != 0 ? 1 : 0;
        //        int writeable = (section->Characteristics & (uint)ImageSectionFlags.IMAGE_SCN_MEM_WRITE) != 0 ? 1 : 0;

        //        if ((section->Characteristics & (int)ImageSectionFlags.IMAGE_SCN_MEM_DISCARDABLE) > 0)
        //        {
        //            NativeDeclarations.VirtualFree((void*)(section->PhysicalAddress | (uint)imageOffset), section->SizeOfRawData, AllocationType.DECOMMIT);
        //            continue;
        //        }
        //        protect = (uint)ProtectionFlags[executable, readable, writeable];
        //        if ((section->Characteristics & (uint)ImageSectionFlags.IMAGE_SCN_MEM_NOT_CACHED) > 0)
        //            protect |= NativeDeclarations.PAGE_NOCACHE;

        //        size = section->SizeOfRawData;
        //        if (size == 0)
        //        {
        //            if ((section->Characteristics & (uint)ImageSectionContains.INITIALIZED_DATA) > 0)
        //                size = _headers->OptionalHeader.SizeOfInitializedData;
        //            else if ((section->Characteristics & (uint)ImageSectionContains.UNINITIALIZED_DATA) > 0)
        //                size = _headers->OptionalHeader.SizeOfUninitializedData;
        //        }

        //        if (size > 0)
        //        {
        //            if (!NativeDeclarations.VirtualProtect((void*)(section->PhysicalAddress | (uint)imageOffset), size, protect, out oldProtect))
        //                throw new Win32Exception("Can't change section access rights");
        //        }
        //    }
        //}

        private void BuildImportTable()
        {
            IMAGE_DATA_DIRECTORY* directory = &_headers->OptionalHeader.ImportTable;
            if (directory->Size == 0)
                throw new NativeDllLoadException("Invalid import table.");


            IMAGE_IMPORT_DESCRIPTOR* importDesc = (IMAGE_IMPORT_DESCRIPTOR*)(_codeBase + directory->VirtualAddress);
            for (; !NativeDeclarations.IsBadReadPtr((importDesc), (uint)Marshal.SizeOf(typeof(IMAGE_IMPORT_DESCRIPTOR))) && importDesc->Name > 0; importDesc++)
            {
                uint* thunkRef;
                int* funcRef;

                string funcName = Marshal.PtrToStringAnsi(new IntPtr(_codeBase + importDesc->Name));
                void* handle = NativeDeclarations.LoadLibrary(funcName);

                if (handle == null)
                {
                    if (_modules.Any())
                        _modules.ForEach(m => NativeDeclarations.FreeLibrary((void*)m));

                    throw new NativeDllLoadException("Can't load libary " + funcName);
                }

                _modules.Add((IntPtr)handle);
                if (importDesc->OriginalFirstThunk > 0)
                {
                    thunkRef = (uint*)(_codeBase + importDesc->OriginalFirstThunk);
                    funcRef = (int*)(_codeBase + importDesc->FirstThunk);
                }
                else
                {
                    // no hint table
                    thunkRef = (uint*)(_codeBase + importDesc->FirstThunk);
                    funcRef = (int*)(_codeBase + importDesc->FirstThunk);
                }
                for (; *thunkRef > 0; thunkRef++, funcRef++)
                {
                    string procName;
                    if (NativeDeclarations.IMAGE_SNAP_BY_ORDINAL32(*thunkRef))
                    {
                        procName = Marshal.PtrToStringAnsi(new IntPtr(NativeDeclarations.IMAGE_ORDINAL32(*thunkRef)));
                        *funcRef = (int)NativeDeclarations.GetProcAddress(handle, procName);
                    }
                    else
                    {
                        IMAGE_IMPORT_BY_NAME* thunkData = (IMAGE_IMPORT_BY_NAME*)(_codeBase + (*thunkRef));
                        procName = Marshal.PtrToStringAnsi(new IntPtr(thunkData->Name));
                        *funcRef = (int)NativeDeclarations.GetProcAddress(handle, procName);
                    }
                    if (*funcRef == 0)
                        throw new NativeDllLoadException("Can't get adress for " + procName);

                }

            }
        }

        private bool PerformBaseRelocation(uint delta)
        {

            int imageSizeOfBaseRelocation = Marshal.SizeOf(typeof(IMAGE_BASE_RELOCATION));
            IMAGE_DATA_DIRECTORY* directory = &_headers->OptionalHeader.BaseRelocationTable;
            if (directory->Size == 0)
                return delta == 0;

            if (directory->Size > 0)
            {
                IMAGE_BASE_RELOCATION* relocation = (IMAGE_BASE_RELOCATION*)(_codeBase + directory->VirtualAddress);
                while (relocation->VirtualAdress > 0)
                {
                    byte* dest = _codeBase + relocation->VirtualAdress;
                    ushort* relInfo = (ushort*)((byte*)relocation + imageSizeOfBaseRelocation);

                    for (int i = 0; i < ((relocation->SizeOfBlock - imageSizeOfBaseRelocation) / 2); i++, relInfo++)
                    {
                        // the upper 4 bits define the type of relocation
                        BasedRelocationType type = (BasedRelocationType)(*relInfo >> 12);
                        // the lower 12 bits define the offset
                        int offset = *relInfo & 0xfff;

                        switch (type)
                        {
                            case BasedRelocationType.IMAGE_REL_BASED_ABSOLUTE:
                                break;
                            case BasedRelocationType.IMAGE_REL_BASED_HIGHLOW:
                                uint* patchAddrHL = (uint*)(dest + offset);
                                *patchAddrHL += delta;
                                break;
                            default:
                                break;
                        }
                    }
                    // advance to next relocation block
                    relocation = (IMAGE_BASE_RELOCATION*)(((byte*)relocation) + relocation->SizeOfBlock);
                }
            }
            return true;
        }

        void CopySections(byte[] data, IMAGE_NT_HEADERS32* oldHeader)
        {
            if (data == null)
                throw new ArgumentNullException("data");

            if (oldHeader->Signature != NativeDeclarations.IMAGE_NT_SIGNATURE)
                throw new BadImageFormatException("Invalid PE-Header");

            uint size;
            byte* dest;

            IMAGE_SECTION_HEADER* section = NativeDeclarations.IMAGE_FIRST_SECTION(_headers);

            for (int i = 0; i < _headers->FileHeader.NumberOfSections; i++, section++)
            {
                if (section->SizeOfRawData == 0)
                {
                    // section doesn't contain data in the dll itself, but may define
                    // uninitialized data
                    size = oldHeader->OptionalHeader.SectionAlignment;
                    if (size > 0)
                    {
                        dest = (byte*)NativeDeclarations.VirtualAlloc(
                            _codeBase + section->VirtualAddress,
                            size,
                            AllocationType.COMMIT,
                            MemoryProtection.READWRITE);

                        if (dest == null)
                            throw new NativeDllLoadException("Unable to allocate memory.");

                        dest = _codeBase + section->VirtualAddress;

                        section->PhysicalAddress = (uint)dest & 0xffffffff;
                        NativeDeclarations.MemSet(dest, 0, (void*)size);
                    }
                    continue;
                }

                dest = (byte*)NativeDeclarations.VirtualAlloc(
                           _codeBase + section->VirtualAddress,
                            section->SizeOfRawData,
                            AllocationType.COMMIT,
                            MemoryProtection.READWRITE);

                if (dest == null)
                    throw new NativeDllLoadException("Out of memory.");

                Marshal.Copy(data, (int)section->PointerToRawData, (IntPtr)dest, (int)section->SizeOfRawData);
                section->PhysicalAddress = (uint)dest & 0xffffffff; ;
            }
        }

        #region Helper

        private uint GetMachineType()
        {
            return Environment.Is64BitProcess ? NativeDeclarations.IMAGE_FILE_MACHINE_AMD64 : NativeDeclarations.IMAGE_FILE_MACHINE_I386;
        }

        private uint AlignValueUp(uint value, uint alignment)
        {
            return (value + alignment - 1) & ~(alignment - 1);
        }

        private static uint AlignValueDown(uint value, uint alignment)
        {
            return value & ~(alignment - 1);
        }

        private static void* AlignAddressDown(void* address, uint alignment)
        {
            return (void*)AlignValueDown((uint)address, alignment);
        }

        private uint GetRealSectionSize(IMAGE_SECTION_HEADER* section)
        {
            uint size = section->SizeOfRawData;
            if (size == 0)
            {
                if ((section->Characteristics & NativeDeclarations.IMAGE_SCN_CNT_INITIALIZED_DATA) > 0)
                {
                    size = _headers->OptionalHeader.SizeOfInitializedData;
                }
                else if ((section->Characteristics & NativeDeclarations.IMAGE_SCN_CNT_UNINITIALIZED_DATA) > 0)
                {
                    size = _headers->OptionalHeader.SizeOfUninitializedData;
                }
            }
            return size;
        }

        private static void* OffsetPointer(void* data, int offset)
        {
            return (void*)((int)data + offset);
        }


        #endregion

        #region IDisposable
        public void Close()
        {
            ((IDisposable)this).Dispose();
        }

        void IDisposable.Dispose()
        {
            Dispose();
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose()
        {
            if (_dataHandle.IsAllocated)
                _dataHandle.Free();

            if (_initialized)
            {
                _dllEntry?.Invoke(_codeBase, DllReason.DLL_PROCESS_DETACH, null);
                _initialized = false;
            }

            if (_modules.Count > 0)
            {
                foreach (IntPtr module in _modules)
                {
                    if (module != (IntPtr)(-1) || module != IntPtr.Zero) // INVALID_HANDLE
                        NativeDeclarations.FreeLibrary((void*)module);
                }
            }

            if (_codeBase != null)
                NativeDeclarations.VirtualFree(_codeBase, 0, AllocationType.RELEASE);

            Disposed = true;

        }
        #endregion

        private class SectionFinalizeData
        {
            public void* Address { get; set; }
            public void* AlignedAddress { get; set; }
            public uint Size { get; set; }
            public uint Characteristics { get; set; }
            public bool Last { get; set; }
        }
    }

}

