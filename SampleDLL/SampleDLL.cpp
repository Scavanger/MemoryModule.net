
#include "SampleDLL.h"


EXPORT int StructTest(PTest str)
{
	return str->b[2];
}

EXPORT int AddNumbers(int a, int b)
{
	return a + b;
}



