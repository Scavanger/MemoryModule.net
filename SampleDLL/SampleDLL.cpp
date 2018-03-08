#include "SampleDLL.h"

// TLS
static int v1 = 0;
static int v2 = 0;

VOID WINAPI tls_callback1(
	PVOID DllHandle,
	DWORD Reason,
	PVOID Reserved)
{
	if (Reason == DLL_PROCESS_ATTACH)
		v1 = 1;
}
VOID WINAPI tls_callback2(
	PVOID DllHandle,
	DWORD Reason,
	PVOID Reserved)
{
	if (Reason == DLL_PROCESS_ATTACH)
		v2 = 2;
}


// ------------------------------------------------------------------------ -
// TLS 32/64 bits example by Elias Bachaalany <lallousz-x86@yahoo.com>
#ifdef _M_AMD64
#pragma comment (linker, "/INCLUDE:_tls_used")
#pragma comment (linker, "/INCLUDE:p_tls_callback1")
#pragma const_seg(push)
#pragma const_seg(".CRT$XLAAA")
EXTERN_C const PIMAGE_TLS_CALLBACK p_tls_callback1 = tls_callback1;
#pragma const_seg(".CRT$XLAAB")
EXTERN_C const PIMAGE_TLS_CALLBACK p_tls_callback2 = tls_callback2;
#pragma const_seg(pop)
#endif
#ifdef _M_IX86
#pragma comment (linker, "/INCLUDE:__tls_used")
#pragma comment (linker, "/INCLUDE:_p_tls_callback1")
#pragma data_seg(push)
#pragma data_seg(".CRT$XLAAA")
EXTERN_C PIMAGE_TLS_CALLBACK p_tls_callback1 = tls_callback1;
#pragma data_seg(".CRT$XLAAB")
EXTERN_C PIMAGE_TLS_CALLBACK p_tls_callback2 = tls_callback2;
#pragma data_seg(pop)
#endif

// Test TLS
EXPORT int TLS_Test1()
{
	return v1;
}

EXPORT int TLS_Test2()
{
	return v2;
}

EXPORT int AddNumbers(int a, int b)
{
	return a + b;
}

EXPORT int Qux(PFoo foo)
{
	return foo->bar[2];
}