using System;
using System.Runtime.InteropServices;
using System.IO;
using System.Threading;

namespace Scavanger.MemoryModule
{
    unsafe class Program
    {
        [StructLayout(LayoutKind.Sequential)]
        struct Foo
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)]
            public int[] bar;
        }

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int QuxDelegate(IntPtr strPtr);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int AddNumbersDelegate(int a, int b);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        private delegate int TlsDelegate();

        static void Main(string[] args)
        {


#if DEBUG
            
#if WIN64
            string dllPath = @"..\..\..\..\x64\Debug\SampleDll.dll";
#elif WIN32
            string dllPath = @"..\..\..\Debug\SampleDll.dll";
#endif
#else
#if WIN64
            //string dllPath = @"..\..\..\..\X64\Release\SampleDll.dll";
            string dllPath = "SampleDll.dll";
#elif WIN32
            string dllPath = @"..\..\..\Release\SampleDll.dll";
#endif
#endif
            if (File.Exists(dllPath))
            {
                try
                {
                    using (MemoryModule memModule = new MemoryModule(File.ReadAllBytes(dllPath)))
                    {
                        // Normal fucnction call
                        AddNumbersDelegate AddNumbers = (AddNumbersDelegate)memModule.GetDelegateFromFuncName("AddNumbers", typeof(AddNumbersDelegate));
                        Console.WriteLine("The Answer: {0:G}", AddNumbers(40, 2));

                        // Normal fucnction call, with generics
                        AddNumbersDelegate AddNumbers2 = memModule.GetDelegateFromFuncName<AddNumbersDelegate>("AddNumbers");
                        Console.WriteLine("The Answer: {0:G}", AddNumbers(38, 4));


                        // Working with stucts
                        QuxDelegate qux = (QuxDelegate)memModule.GetDelegateFromFuncName("Qux", typeof(QuxDelegate));
                        Foo foo = new Foo
                        {
                            bar = new int[] { 23, 5, 42 }
                        };

                        IntPtr fooPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(Foo)));
                        Marshal.StructureToPtr(foo, fooPtr, true);
                        Console.WriteLine("Still the answer: {0:D}", qux(fooPtr));

                        Marshal.FreeHGlobal(fooPtr);
                    }

                }
                catch (Exception ex)
                {
                    Console.WriteLine("Error: " + ex.Message);
                }
            }
            else
                Console.WriteLine("Error: Dll not found!");

            Console.ReadKey(true);
        }
    }
}
    
