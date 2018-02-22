using System;
using System.Runtime.InteropServices;
using System.IO;

namespace Scavanger.MemoryModule
{
    class Program
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

        static void Main(string[] args)
        {

#if DEBUG
            string dllPath = @"..\..\..\Debug\SampleDll.dll";
#else
            string dllPath = @"..\..\..\Release\SampleDll.dll";
#endif

            if (File.Exists(dllPath))
            {
                try
                {
                    using (MemoryModule memModule = new MemoryModule(File.ReadAllBytes(dllPath)))
                    {
                        AddNumbersDelegate AddNumbers = (AddNumbersDelegate)memModule.GetDelegateFromFuncName("AddNumbers", typeof(AddNumbersDelegate));
                        if (AddNumbers != null)
                            Console.WriteLine("The Answer: {0:G}", AddNumbers(40, 2));

                        QuxDelegate qux = (QuxDelegate)memModule.GetDelegateFromFuncName("Qux", typeof(QuxDelegate));

                        Foo foo = new Foo
                        {
                            bar = new int[] { 23, 5, 42 }
                        };

                        IntPtr fooPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(Foo)));
                        Marshal.StructureToPtr(foo, fooPtr, true);

                        if (qux != null)
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

        static void LoadAndExecuteFromMemory(byte[] dll)
        {

        }
    }
}
