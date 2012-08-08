/*                                                               
 * Memory Module.net 0.1
 * 
 * Loading a native Dll from memory, a C#/.net port of Memory Module
 * 
 * (c) 2012 by Andreas Kanzler (andi_kanzler(at)gmx.de)
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

namespace Scavanger.MemoryModule
{
    unsafe class MemoryModule : IDisposable
    {
        public bool Disposed { get; private set; }
        
        private GCHandle dataHandle;
        private IMAGE_NT_HEADERS32* headers;
        private byte* codeBase;
        private List<IntPtr> modules;
        private bool initialized;

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        private delegate bool DllEntryDelegate(IntPtr hinstDLL, DllReason fdwReason, IntPtr lpReserved);

        private DllEntryDelegate dllEntry;

        /// <summary>
        /// Loads a unmanged (native) DLL in the memory.
        /// </summary>
        /// <param name="data">Dll as a byte array</param>
        public MemoryModule(byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException("data");

            this.headers = null;
            this.codeBase = null;
            this.modules = new List<IntPtr>();
            this.initialized = false;
            this.Disposed = false;

            MemoryLoadLibrary(data);
        }

        ~MemoryModule()
        {
            this.Dispose();
        }
        
        /// <summary>
        /// Returns a delegate for a function inside the DLL.
        /// </summary>
        /// <param name="funcName">The Name of the function to be searched.</param>
        /// <param name="t">The type of the delegate to be returned.</param>
        /// <returns>A delegate instance that can be cast to the appropriate delegate type.</returns>
        public Delegate GetDelegateFromFuncName(string funcName, Type t)
        {
            if (string.IsNullOrEmpty(funcName))
                throw new ArgumentException("funcName");

            if (t == null)
                throw new ArgumentNullException("t");

            if (this.Disposed)
                throw new ObjectDisposedException("MemoryModule");

            if (!this.initialized)
                throw new InvalidOperationException("Dll is not initialized.");

            int idx = -1;
            uint* nameRef;
            ushort* ordinal;
            IMAGE_EXPORT_DIRECTORY* exports;
            IntPtr funcPtr;

            IMAGE_DATA_DIRECTORY* directory = &this.headers->OptionalHeader.ExportTable;
            if (directory->Size == 0)
                throw new NativeDllLoadException("Dll has no export table.");

            exports = (IMAGE_EXPORT_DIRECTORY*)(this.codeBase + directory->VirtualAddress);
            if (exports->NumberOfFunctions == 0 || exports->NumberOfNames == 0)
                throw new NativeDllLoadException("Dll exports no functions.");

            nameRef = (uint*)(this.codeBase + exports->AddressOfNames);
            ordinal = (ushort*)(this.codeBase + exports->AddressOfNameOrdinals);
            for (int i = 0; i < exports->NumberOfNames; i++, nameRef++, ordinal++)
            {
                string curFuncName = Marshal.PtrToStringAnsi(new IntPtr(this.codeBase + *nameRef));
                if (curFuncName == funcName)
                {
                    idx = *ordinal;
                    break;
                }
            }

            if (idx == -1)
                throw new NativeDllLoadException("Dll exports no function named " + funcName);

            if (idx > exports->NumberOfFunctions)
                throw new NativeDllLoadException("IDX don't match number of funtions.");

            funcPtr = new IntPtr(this.codeBase + (*(uint*)(this.codeBase + exports->AddressOfFunctions + (idx * 4))));
            return Marshal.GetDelegateForFunctionPointer(funcPtr, t);

        }

        private void MemoryLoadLibrary(byte[] data)
        {
            IMAGE_DOS_HEADER32* dosHeader;
            IMAGE_NT_HEADERS32* ntHeader;
            IntPtr dllEntryPtr;
            byte* code, headers, dataPtr;
            uint locationDelta;

            this.dataHandle = GCHandle.Alloc(data, GCHandleType.Pinned);
            dataPtr = (byte*)this.dataHandle.AddrOfPinnedObject().ToPointer();

            dosHeader = (IMAGE_DOS_HEADER32*)dataPtr;
            if (dosHeader->e_magic != NativeDeclarations.IMAGE_DOS_SIGNATURE)
                throw new BadImageFormatException("Not a valid executable file.");

            ntHeader = (IMAGE_NT_HEADERS32*)(dataPtr + dosHeader->e_lfanew);
            if (ntHeader->Signature != NativeDeclarations.IMAGE_NT_SIGNATURE)
                throw new BadImageFormatException("Not a valid PE file.");

            code = (byte*)NativeDeclarations.VirtualAlloc(
                new IntPtr(ntHeader->OptionalHeader.ImageBase),
                ntHeader->OptionalHeader.SizeOfImage,
                AllocationType.RESERVE,
                MemoryProtection.READWRITE).ToPointer();

            if (code == null)
            {
                code = (byte*)NativeDeclarations.VirtualAlloc(
                IntPtr.Zero,
                ntHeader->OptionalHeader.SizeOfImage,
                AllocationType.RESERVE,
                MemoryProtection.READWRITE).ToPointer();
            }

            if (code == null)
                throw new Win32Exception();

            NativeDeclarations.VirtualAlloc(
                new IntPtr(code),
                ntHeader->OptionalHeader.SizeOfImage,
                AllocationType.COMMIT,
                MemoryProtection.READWRITE);

            this.codeBase = code;

            headers = (byte*)NativeDeclarations.VirtualAlloc(
                new IntPtr(code),
                ntHeader->OptionalHeader.SizeOfHeaders,
                AllocationType.COMMIT,
                MemoryProtection.READWRITE).ToPointer();

            if (headers == null)
                throw new Win32Exception();

            Marshal.Copy(data, 0, new IntPtr(headers), (int)(dosHeader->e_lfanew + ntHeader->OptionalHeader.SizeOfHeaders));
            this.headers = (IMAGE_NT_HEADERS32*)&((byte*)(headers))[dosHeader->e_lfanew];

            this.headers->OptionalHeader.ImageBase = (uint)code;

            this.CopySections(data, ntHeader);

            locationDelta = (uint)(code - ntHeader->OptionalHeader.ImageBase);
            if (locationDelta != 0)
                PerformBaseRelocation(locationDelta);

            this.BuildImportTable();
            this.FinalizeSections();

            if (this.headers->OptionalHeader.AddressOfEntryPoint == 0)
                throw new NativeDllLoadException("DLL has no entry point");

            dllEntryPtr = new IntPtr(code + this.headers->OptionalHeader.AddressOfEntryPoint);
     
            this.dllEntry = (DllEntryDelegate)Marshal.GetDelegateForFunctionPointer(dllEntryPtr, typeof(DllEntryDelegate));

            if (dllEntry(new IntPtr(code), DllReason.DLL_PROCESS_ATTACH, IntPtr.Zero))
                this.initialized = true;
            else
            {
                this.initialized = false;
                throw new NativeDllLoadException("Can't attach DLL to process.");
            }


        }

        private readonly PageProtection[, ,] ProtectionFlags = new PageProtection[,,]    
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
            int imageOffset = 0;

            IMAGE_SECTION_HEADER* section = (IMAGE_SECTION_HEADER*)NativeDeclarations.IMAGE_FIRST_SECTION(this.headers);

            for (int i = 0; i < this.headers->FileHeader.NumberOfSections; i++, section++)
            {
                uint protect, oldProtect, size;

                int executable = (section->Characteristics & (uint)ImageSectionFlags.IMAGE_SCN_MEM_EXECUTE) != 0 ? 1 : 0;
                int readable = (section->Characteristics & (uint)ImageSectionFlags.IMAGE_SCN_MEM_READ) != 0 ? 1 : 0;
                int writeable = (section->Characteristics & (uint)ImageSectionFlags.IMAGE_SCN_MEM_WRITE) != 0 ? 1 : 0;

                if ((section->Characteristics & (int)ImageSectionFlags.IMAGE_SCN_MEM_DISCARDABLE) > 0)
                {
                    NativeDeclarations.VirtualFree(new IntPtr(section->PhysicalAddress | (uint)imageOffset), section->SizeOfRawData, AllocationType.DECOMMIT);
                    continue;
                }
                protect = (uint)ProtectionFlags[executable, readable, writeable];
                if ((section->Characteristics & (uint)ImageSectionFlags.IMAGE_SCN_MEM_NOT_CACHED) > 0)
                    protect |= NativeDeclarations.PAGE_NOCACHE;

                size = section->SizeOfRawData;
                if (size == 0)
                {
                    if ((section->Characteristics & (uint)ImageSectionContains.INITIALIZED_DATA) > 0)
                        size = this.headers->OptionalHeader.SizeOfInitializedData;
                    else if ((section->Characteristics & (uint)ImageSectionContains.UNINITIALIZED_DATA) > 0)
                        size = this.headers->OptionalHeader.SizeOfUninitializedData;
                }

                if (size > 0)
                {
                    if (!NativeDeclarations.VirtualProtect(new IntPtr(section->PhysicalAddress | (uint)imageOffset), size, protect, out oldProtect))
                        throw new Win32Exception("Can't change section access rights");
                }
            }
        }

        private void BuildImportTable()
        {
            IMAGE_DATA_DIRECTORY* directory = &this.headers->OptionalHeader.ImportTable;
            if (directory->Size > 0)
            {
                IMAGE_IMPORT_DESCRIPTOR* importDesc = (IMAGE_IMPORT_DESCRIPTOR*)(this.codeBase + directory->VirtualAddress);
                for (; !NativeDeclarations.IsBadReadPtr(new IntPtr(importDesc), (uint)Marshal.SizeOf(typeof(IMAGE_IMPORT_DESCRIPTOR))) && importDesc->Name > 0; importDesc++)
                {
                    uint* thunkRef;
                    int* funcRef;

                    string funcName = Marshal.PtrToStringAnsi(new IntPtr(this.codeBase + importDesc->Name));
                    IntPtr handle = NativeDeclarations.LoadLibrary(funcName);

                    if (handle == IntPtr.Zero)
                        throw new NativeDllLoadException("Can't load libary " + funcName);

                    this.modules.Add(handle);
                    if (importDesc->OriginalFirstThunk > 0)
                    {
                        thunkRef = (uint*)(codeBase + importDesc->OriginalFirstThunk);
                        funcRef = (int*)(codeBase + importDesc->FirstThunk);
                    }
                    else
                    {
                        // no hint table
                        thunkRef = (uint*)(codeBase + importDesc->FirstThunk);
                        funcRef = (int*)(codeBase + importDesc->FirstThunk);
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
                            IMAGE_IMPORT_BY_NAME* thunkData = (IMAGE_IMPORT_BY_NAME*)(codeBase + (*thunkRef));
                            procName = Marshal.PtrToStringAnsi(new IntPtr(thunkData->Name));
                            *funcRef = (int)NativeDeclarations.GetProcAddress(handle, procName);
                        }
                        if (*funcRef == 0)
                            throw new NativeDllLoadException("Can't get adress for " + procName);

                    }
                }
            }
        }

        private void PerformBaseRelocation(uint delta)
        {
            if (delta == 0)
                return;

            int imageSizeOfBaseRelocation = Marshal.SizeOf(typeof(IMAGE_BASE_RELOCATION));

            IMAGE_DATA_DIRECTORY* directory = &this.headers->OptionalHeader.BaseRelocationTable;
            if (directory->Size > 0)
            {
                IMAGE_BASE_RELOCATION* relocation = (IMAGE_BASE_RELOCATION*)(this.codeBase + directory->VirtualAddress);
                while (relocation->VirtualAdress > 0)
                {
                    byte* dest = this.codeBase + relocation->VirtualAdress;
                    ushort* relInfo = (ushort*)((byte*)relocation + imageSizeOfBaseRelocation);

                    for (int i = 0; i < ((relocation->SizeOfBlock - imageSizeOfBaseRelocation) / 2); i++, relInfo++)
                    {
                        uint* patchAddrHL;
                        BasedRelocationType type;
                        int offset;

                        // the upper 4 bits define the type of relocation
                        type = (BasedRelocationType)(*relInfo >> 12);
                        // the lower 12 bits define the offset
                        offset = *relInfo & 0xfff;

                        switch (type)
                        {
                            case BasedRelocationType.IMAGE_REL_BASED_ABSOLUTE:
                                break;
                            case BasedRelocationType.IMAGE_REL_BASED_HIGHLOW:
                                patchAddrHL = (uint*)(dest + offset);
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

        }

        void CopySections(byte[] data, IMAGE_NT_HEADERS32* ntHeader)
        {
            if (data == null)
                throw new ArgumentNullException("data");

            if (ntHeader->Signature != NativeDeclarations.IMAGE_NT_SIGNATURE)
                throw new BadImageFormatException("Inavlid PE-Header");

            uint size;
            int* dest;

            IMAGE_SECTION_HEADER* section = NativeDeclarations.IMAGE_FIRST_SECTION(this.headers);

            for (int i = 0; i < this.headers->FileHeader.NumberOfSections; i++, section++)
            {
                if (section->SizeOfRawData == 0)
                {
                    // section doesn't contain data in the dll itself, but may define
                    // uninitialized data
                    size = ntHeader->OptionalHeader.SectionAlignment;
                    if (size > 0)
                    {
                        dest = (int*)NativeDeclarations.VirtualAlloc(
                            new IntPtr(this.codeBase + section->VirtualAddress),
                            size,
                            AllocationType.COMMIT,
                            MemoryProtection.READWRITE).ToPointer();

                        section->PhysicalAddress = (uint)dest;
                        NativeDeclarations.MemSet(new IntPtr(dest), 0, new IntPtr(size));
                    }
                    continue;
                }

                dest = (int*)NativeDeclarations.VirtualAlloc(
                            new IntPtr((int)this.codeBase + section->VirtualAddress),
                            section->SizeOfRawData,
                            AllocationType.COMMIT,
                            MemoryProtection.READWRITE).ToPointer();

                Marshal.Copy(data, (int)section->PointerToRawData, new IntPtr(dest), (int)section->SizeOfRawData);
                section->PhysicalAddress = (uint)dest;
            }
        }

        public void Close()
        {
            ((IDisposable)this).Dispose();
        }

        void IDisposable.Dispose()
        {
            this.Dispose();
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose()
        {
            if (dataHandle.IsAllocated)
                dataHandle.Free();

            if (this.initialized)
            {
                this.dllEntry(new IntPtr(this.codeBase), DllReason.DLL_PROCESS_DETACH, IntPtr.Zero);
                this.initialized = false;
            }

            if (this.modules.Count > 0)
            {
                foreach (IntPtr module in this.modules)
                {
                    if (module != new IntPtr(-1) || module != IntPtr.Zero) // INVALID_HANDLE
                        NativeDeclarations.FreeLibrary(module);
                }
            }

            if (this.codeBase != null)
                NativeDeclarations.VirtualFree(new IntPtr(this.codeBase), 0, AllocationType.RELEASE);

            this.Disposed = true;

        }

    }
}
