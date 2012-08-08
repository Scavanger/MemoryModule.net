#include "SampleDLL.h"

EXPORT int AddNumbers(int a, int b)
{
	return a + b;
}

EXPORT int Qux(PFoo foo)
{
	return foo->bar[2];
}