//////////////////////////////////////////////////////////////////////////
//for research and learning only
//////////////////////////////////////////////////////////////////////////

#include "pch.h"
#include "stdcpp_override.h"

#pragma function(memset)
void* memset(void* dest, int c, size_t count)
{
	char* bytes = (char*)dest;
	while (count--)
	{
		*bytes++ = (char)c;
	}

	return dest;
}

void ZY_ZeroMemory(void* pDest, SIZE_T size)
{
	ZY_Memset(pDest, 0, size);
}

void ZY_Memset(void* pDest, BYTE n, SIZE_T size)
{
	for (int i = 0; i < size; ++i)
	{
		reinterpret_cast<BYTE*>(pDest)[i] = n;
	}
}
