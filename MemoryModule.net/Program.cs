using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;
using System.IO;

namespace MemoryModule.net
{
    class Program
    {
        [StructLayout(LayoutKind.Sequential)]
        struct Test
        {
            public int a;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)]
            public int[] b;
        }

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int StructTestDelegate(IntPtr strPtr);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int AddNumbersDelegate(int a, int b);

        static void Main(string[] args)
        {
            //byte[] dll = Properties.Resources.SampleDLL;
            byte[] dll = File.ReadAllBytes(@"..\..\..\Debug\SampleDLL.dll");
            try
            {
                using (MemoryModule memModule = new MemoryModule(dll))
                {
                    AddNumbersDelegate AddNumbers = (AddNumbersDelegate)memModule.GetDelegateFromFuncName("AddNumbers", typeof(AddNumbersDelegate));
                    if (AddNumbers != null)
                        Console.WriteLine(AddNumbers(40, 2));

                    StructTestDelegate StructTest = (StructTestDelegate)memModule.GetDelegateFromFuncName("StructTest", typeof(StructTestDelegate));

                    Test test = new Test();
                    test.a = 2;
                    test.b = new int[] {3, 4, 5};

                    IntPtr testPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(Test)));
                    Marshal.StructureToPtr(test, testPtr, true);

                    int j = 0;

                    if (StructTest != null)
                        j = StructTest(testPtr);


                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: " + ex.Message);
            }

            Console.ReadKey(true);
        }
    }
}
