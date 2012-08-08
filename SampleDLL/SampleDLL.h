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

#ifdef __cplusplus
}
#endif

#endif // SAMPLEDLL