#ifndef SAMPLEDLL
#define SAMPLEDLL

#define EXPORT __declspec(dllexport)

typedef struct test
{
	int a;
	int b[2];
} Test, *PTest;

#ifdef __cplusplus
extern "C"
{
#endif

EXPORT int AddNumbers(int a, int b);
EXPORT int StructTest(PTest str);

#ifdef __cplusplus
}
#endif

#endif // SAMPLEDLL