#include <Windows.h>

#ifndef SAMPLEDLL
#define SAMPLEDLL

#define EXPORT __declspec(dllexport)


typedef struct foo
{
	int bar[3];
} Foo, *PFoo;

#ifdef __cplusplus

extern "C"
{
#endif

EXPORT int AddNumbers(int a, int b);
EXPORT int Qux(PFoo foo);
EXPORT int TLS_Test1();
EXPORT int TLS_Test2();

#ifdef __cplusplus
}

#endif

#endif // SAMPLEDLL