//////////////////////////////////////////////////////////////////////////
//for research and learning only
//////////////////////////////////////////////////////////////////////////

#include "pch.h"
#include "InternalFunc.h"
#include "stdcpp_override.h"
#include <stddef.h>

EXTERN_C NTSTATUS NTAPI RtlQueryEnvironmentVariable(PVOID Environment, PWSTR Name, size_t NameLength, PWSTR Value, size_t ValueLength, PSIZE_T ReturnLength);
EXTERN_C VOID NTAPI RtlGetNtVersionNumbers(PULONG MajorVersion, PULONG MinorVersion, PULONG BuildNumber);
EXTERN_C NTSTATUS NTAPI LdrGetDllHandle(PWSTR DllPath, PULONG DllCharacteristics, PUNICODE_STRING DllName, PVOID* DllHandle);
EXTERN_C NTSTATUS NTAPI LdrEnumerateLoadedModules(BOOLEAN ReservedFlag, PLDR_ENUM_CALLBACK EnumProc, PVOID Context);
EXTERN_C NTSTATUS NTAPI LdrFindEntryForAddress(PVOID handle, PZYLDR_DATA_TABLE_ENTRY* pEntry);
EXTERN_C NTSTATUS NTAPI NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, SIZE_T* NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection);
EXTERN_C PPEB NTAPI RtlGetCurrentPeb();
EXTERN_C ULONG NTAPI RtlGetProcessHeaps(ULONG count, HANDLE* heaps);

#define GLOBAL_BUF_LEN 0x8000

HANDLE g_processHeaps = INVALID_HANDLE_VALUE;
int g_nVerbose;
static char g_szBuf[GLOBAL_BUF_LEN + 1];
static SIZE_T g_nBufLen;
bool g_bPatchImportsOn = false;
static int g_nRedirectFlag = 0;

void ZY_AnsiStringToUnicodeString(PUNICODE_STRING pDestinationString, PCANSI_STRING pSourceString)
{
	ZY_ZeroMemory(pDestinationString->Buffer, pDestinationString->MaximumLength);
	pDestinationString->Length = 0;

	if (!pSourceString->Buffer)
		return;

	if (pSourceString->MaximumLength == 0)
		return;

	if (pSourceString->Length >= pSourceString->MaximumLength)
		return;

	int nIndex1 = 0;
	int nIndex2 = 0;
	char* pSourceBuf = pSourceString->Buffer;
	while (nIndex1 < pSourceString->Length
		&& 2 * nIndex2 < pDestinationString->MaximumLength - 1
		&& pSourceBuf[nIndex1])
	{
		char c = pSourceBuf[nIndex1];
		wchar_t wc = L'?';
		if (c <= 0x7F)
		{
			wc = c;
			++nIndex1;
		}
		else if (c <= 0xC1)
		{
			++nIndex1;
		}
		else if (c <= 0xDF && nIndex1 + 1 < pSourceString->Length)
		{
			wc = (pSourceBuf[nIndex1 + 1] & 0x3F) | ((c & 0x1F) << 6);
			nIndex1 += 2;
		}
		else if (c <= 0xEF && nIndex1 + 2 < pSourceString->Length)
		{
			wc = (pSourceBuf[nIndex1 + 2] & 0x3F) | ((pSourceBuf[nIndex1 + 1] & 0x3F) << 6) | ((c & 0xF) << 12);
			nIndex1 += 3;
		}
		else if (c <= 0xF4 && nIndex1 + 2 < pSourceString->Length)
		{
			int tmp = (pSourceBuf[nIndex1 + 3] & 0x3F) | ((pSourceBuf[nIndex1 + 2] & 0x3F) << 6) | ((pSourceBuf[nIndex1 + 1] & 0x3F) << 12) | ((c & 0x7) << 18);
			if (tmp >= 0xED800 && tmp <= 0xEDFFF)
				wc = (pSourceBuf[nIndex1 + 3] & 0x3F) | ((pSourceBuf[nIndex1 + 2] & 0x3F) << 6) | ((pSourceBuf[nIndex1 + 1] & 0x3F) << 12);
		}
		pDestinationString->Buffer[nIndex2++] = wc;
	}

	pDestinationString->Length = 2 * nIndex2;
}

void ZY_UnicodeStringToAnsiString(PANSI_STRING pDestinationString, PCUNICODE_STRING pSourceString)
{
    ZY_ZeroMemory(pDestinationString->Buffer, pDestinationString->MaximumLength);
	pDestinationString->Length = 0;

	if (!pSourceString->Buffer)
		return;

	if (pSourceString->MaximumLength == 0)
		return;

    if (pSourceString->Length >= pSourceString->MaximumLength)
        return;

	int nIndex1 = 0;
	int nIndex2 = 0;
	while (2 * nIndex1 < pSourceString->Length
		&& nIndex2 < pDestinationString->MaximumLength - 1
		&& pSourceString->Buffer[nIndex1])
	{
		wchar_t wc = pSourceString->Buffer[nIndex1];
		char c[4] = { 0 };
		int nByte = 0;
		if (wc <= 0x7F)
		{
			c[0] = wc;
			nByte = 1;
		}
		else if (wc <= 0x7FF)
		{
			c[0] = (wc >> 6) | 0xC0;
			c[1] = (wc & 0x3F) | 0x80;
			nByte = 2;
		}
		else if (wc < 0xD800 && wc > 0xDFFF)
		{
			c[0] = (wc >> 12) | 0xE0;
			c[1] = ((wc >> 6) & 0x3F) | 0x80;
			c[2] = (wc & 0x3F) | 0x80;
			nByte = 3;
		}
		else
		{
			int tmp = wc + 0xE0000;
			c[0] = (tmp >> 18) | 0xF0;
			c[1] = ((tmp >> 12) & 0x3F) | 0x80;
			c[2] = ((tmp >> 6) & 0x3F) | 0x80;
			c[3] = (wc & 0x3F) | 0x80;
			nByte = 4;
		}

		if (nByte + nIndex2 < pDestinationString->MaximumLength - 1)
		{
			for (int i = 0; i < nByte; ++i)
			{
				pDestinationString->Buffer[nIndex2++] = c[i];
			}
		}
		++nIndex1;
	}

	pDestinationString->Length = nIndex2;
}

int ZY_GetEnvironmentVariable(const char* lpName, char* lpBuffer, int nSize)
{
	if (!lpBuffer || nSize == 0)
		return 0;

	*lpBuffer = 0;
	ANSI_STRING strAnsi;
	RtlInitAnsiString(&strAnsi, lpName);

	UNICODE_STRING strUnicode;
	WCHAR buf[128] = { 0 };
	strUnicode.Length = 0;
	strUnicode.MaximumLength = 128;
	strUnicode.Buffer = buf;
	ZY_AnsiStringToUnicodeString(&strUnicode, &strAnsi);

	SIZE_T size = 0;
	WCHAR buf2[MAX_BUF_LEN] = { 0 };
	if (!NT_SUCCESS(RtlQueryEnvironmentVariable(nullptr, buf, strUnicode.Length / 2, buf2, MAX_BUF_LEN, &size))
		|| size >= nSize || size >= MAX_BUF_LEN)
		return 0;

	strAnsi.Length = 0;
	strAnsi.MaximumLength = nSize;
	strAnsi.Buffer = lpBuffer;
	strUnicode.Length = 2 * size;
	strUnicode.MaximumLength = 520;
	strUnicode.Buffer = buf2;
	ZY_UnicodeStringToAnsiString(&strAnsi, &strUnicode);
	lpBuffer[nSize - 1] = 0;
	return 1;
}

size_t ZY_GetSysVersion(size_t* pMinorVersion, size_t* pBuildNumber)
{
	ULONG nMajorVersion = 10;
	ULONG nMinorVersion = 0;
	ULONG nBuildNumber = 0;
	RtlGetNtVersionNumbers(&nMajorVersion, &nMinorVersion, &nBuildNumber);
	if (pMinorVersion)
		*pMinorVersion = nMinorVersion;
	if (pBuildNumber)
		*pBuildNumber = nBuildNumber & 0xFFFF;
	return nMajorVersion;
}

void* ZY_GetModelHandle(const char* pModelName)
{
	ANSI_STRING strAnsi;
	RtlInitAnsiString(&strAnsi, pModelName);
	UNICODE_STRING strUnicode;
	WCHAR buf[MAX_BUF_LEN] = { 0 };
	strUnicode.Length = 0;
	strUnicode.MaximumLength = 260;
	strUnicode.Buffer = buf;
	ZY_AnsiStringToUnicodeString(&strUnicode, &strAnsi);
	PVOID handle = nullptr;
	if (NT_SUCCESS(LdrGetDllHandle(nullptr, nullptr, &strUnicode, &handle)))
		return handle;
	return nullptr;
}

void* ZY_GetFuncAddress(void* handle, const char* pFuncName)
{
	ANSI_STRING strAnsi;
	RtlInitAnsiString(&strAnsi, pFuncName);

	ULONG_PTR BasePtr = reinterpret_cast<ULONG_PTR>(handle);
	PIMAGE_EXPORT_DIRECTORY pExportDir = static_cast<PIMAGE_EXPORT_DIRECTORY>(ZY_GetImageDirectionEntry(handle, IMAGE_DIRECTORY_ENTRY_EXPORT));

	if(!pExportDir || pExportDir->AddressOfNames == 0)
		return nullptr;
	PULONG pAddressOfNamesVA = reinterpret_cast<PULONG>(BasePtr + pExportDir->AddressOfNames);
	for (int i = 0; i < pExportDir->NumberOfNames; ++i)
	{
		if (0 == ZY_CompareStr(pFuncName, reinterpret_cast<char*>(BasePtr + pAddressOfNamesVA[i])))
		{
			USHORT nAddrOfName = reinterpret_cast<PUSHORT>(BasePtr + pExportDir->AddressOfNameOrdinals)[i];
			ULONG nAddOfFunc = reinterpret_cast<PULONG>(BasePtr + pExportDir->AddressOfFunctions)[nAddrOfName];
			return reinterpret_cast<PVOID>(BasePtr + nAddOfFunc);
		}
	}
	return nullptr;
}

void* ZY_GetFuncAddress2(void* handle, const char* pModelName, const char* pFuncName, void** ppFunc)
{
	if (ppFunc)
		*ppFunc = nullptr;

	void* handle2 = ZY_GetModelHandle(pModelName);
	if (!handle2)
		return nullptr;

	void* pFunc2 = ZY_GetFuncAddress(handle2, pFuncName);
	if (!pFunc2)
		return nullptr;

	if (ppFunc)
		*ppFunc = pFunc2;

	ULONG_PTR BasePtr = reinterpret_cast<ULONG_PTR>(handle);
	PIMAGE_EXPORT_DIRECTORY pExportDir = static_cast<PIMAGE_EXPORT_DIRECTORY>(ZY_GetImageDirectionEntry(handle, IMAGE_DIRECTORY_ENTRY_IMPORT));
	for (; pExportDir->Characteristics && pExportDir->Name; pExportDir++)
	{
		PVOID* ppFunc1 = reinterpret_cast<PVOID*>(BasePtr + pExportDir->Base);
		for (; *ppFunc1; ++ppFunc1)
		{
			if (*ppFunc1 == pFunc2)
				return ppFunc1;
		}
	}

	return nullptr;
}

void* ZY_GetFuncAddress3(const char* pModelName1, void* handle, const char* pModelName2, const char* pFuncName)
{
	return ZY_GetFuncAddress2(handle, pModelName2, pFuncName, nullptr);
}

void* ZY_GetActProcFunc(const char* pModelName, void* handle, const char* pFuncName)
{
	void* pFunc = ZY_GetFuncAddress(handle, pFuncName);
	if (pFunc)
		return pFunc;

	if (0 == ZY_CompareStr(pFuncName, "_recalloc_base"))
	{
		void* pFunc2 = ZY_GetFuncAddress(handle, "_recalloc");
		pFunc = ZY_GetJmpCallFunc(pFunc2);
	}
	else if (0 == ZY_CompareStr(pFuncName, "_msize_base"))
	{
		void* pFunc2 = ZY_GetFuncAddress(handle, "_msize");
		pFunc = ZY_GetJmpCallFunc(pFunc2);
	}
	else if(0 == ZY_CompareStr(pFuncName, "_expand_base"))
	{
		void* pFunc2 = ZY_GetFuncAddress(handle, "_expand");
		pFunc = ZY_GetJmpCallFunc(pFunc2);
	}
	else
	{
		return nullptr;
	}

	if (!pFunc && !ZY_IsSameStrNoCase(pModelName, "ucrtbased"))
	{
		ZY_Warning("unable to resolve \"%s!%s\" -- enabling MIMALLOC_PATCH_IMPORTS to prevent allocation errors.", pModelName, pFuncName);
		g_bPatchImportsOn = true;
	}

	return pFunc;
}

void* ZY_GetCodeSegment(void* handle, size_t* nSize)
{
	if (nSize)
		*nSize = 0;

	ULONG_PTR BasePtr = reinterpret_cast<ULONG_PTR>(handle);
	PIMAGE_DOS_HEADER pDOSHeader = static_cast<PIMAGE_DOS_HEADER>(handle);
	PIMAGE_NT_HEADERS pNTHeader = ZY_GetImageNTHeaders(pDOSHeader);
	if (!pNTHeader)
		return nullptr;

	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNTHeader);
	for (int i = 0; i < pNTHeader->FileHeader.NumberOfSections; ++i)
	{
		if (0 == ZY_CompareStr2(reinterpret_cast<char*>(pSectionHeader->Name), ".text", 5))
		{
			if (nSize)
				*nSize = pSectionHeader->Misc.VirtualSize;
			return reinterpret_cast<PVOID*>(BasePtr + pSectionHeader->VirtualAddress);
		}
		pSectionHeader++;
	}

	return nullptr;
}

void* ZY_GetJmpCallFunc(void* pFunc)
{
	if (!pFunc)
		return nullptr;

	BYTE* pData = reinterpret_cast<BYTE*>(pFunc);
	if (*pData == 0xEB)	//short jmp
		return pData + pData[1] + 2;
	if (*pData == 0xE9)	//long jmp
		return pData + *reinterpret_cast<PLONG>(pData + 1) + 5;
	if (pData[0] == 0xFF && pData[1] == 0x25 && 0 == *reinterpret_cast<PLONG>(pData + 2))	//jmp
		return *reinterpret_cast<void**>(pData + 6);
	return nullptr;
}

int ZY_CheckInvalidCode(void* addr, int nSize)
{
	for (int i = 0; i < nSize; ++i)
	{
		BYTE b = *(reinterpret_cast<BYTE*>(addr) - 1 - i);
		if (b != 0xCC && b != 0x90)	//invalid|nop
			return i;
	}
	return nSize;
}

bool ZY_CheckInvalidCode2(void* addr, int nSize)
{
	for (int i = 0; i < nSize; ++i)
	{
		BYTE b = reinterpret_cast<BYTE*>(addr)[i];
		if (b != 0xCC)
			return false;
	}
	return true;
}

void ZY_CopyCode(CodeContext* pContext, void* addr, int nSize)
{
	if (nSize == 0 || !pContext || !pContext->pFunc)
		return;

	if (0 != pContext->nCopySize)
		return;

	if (nSize > 16)
	{
		ZY_Error("trying to save beyond the maximum jump size: %zu > %zu", nSize, 16);
		nSize = 16;
	}
	pContext->nCopySize = nSize;
	if (addr)
		pContext->pCopyAddr = addr;
	else
		pContext->pCopyAddr = pContext->pFunc;
	Zy_Memcpy(pContext->szCopyCode, pContext->pCopyAddr, pContext->nCopySize);
}

bool ZY_WriteCode(void* addr, LONG_PTR code)
{
	ULONG OldAccessProtection = PAGE_READWRITE;
	if (ZY_ProtectVirtualMemory(addr, 8, PAGE_EXECUTE_READWRITE, &OldAccessProtection))
	{
		*reinterpret_cast<LONG_PTR*>(addr) = code;
		ZY_ProtectVirtualMemory(addr, 8, OldAccessProtection, &OldAccessProtection);
		return true;
	}

	ZY_Error("unable to get write permission for address store (at %p)", addr);
	return false;
}

void* ZY_WriteCode2(void* addr, SIZE_T size, LONG_PTR code)
{
	const int n = 18;
	if (!addr || size < n)
		return nullptr;

	for (SIZE_T i = 0; i < size - n; ++i)
	{
		LONG_PTR ad = reinterpret_cast<LONG_PTR>(addr);
		if (ZY_CheckInvalidCode2(reinterpret_cast<void*>(ad + i), n)
			&& ZY_WriteCode(reinterpret_cast<void*>(((ad + i + 8) & (~7))), code))
		{
			return reinterpret_cast<void*>(((ad + i + 8) & (~7)));
		}
	}
	return nullptr;
}

bool ZY_WriteCode3(PVOID addr, ULONG_PTR code, ULONG_PTR* oldCode)
{
    ULONG OldAccessProtection = PAGE_READWRITE;
    if (!ZY_ProtectVirtualMemory(addr, 8, PAGE_READWRITE, &OldAccessProtection))
        return false;

    if (oldCode)
        *oldCode = *reinterpret_cast<ULONG_PTR*>(addr);
    *reinterpret_cast<ULONG_PTR*>(addr) = code;

    ZY_ProtectVirtualMemory(addr, 8, OldAccessProtection, &OldAccessProtection);
    return true;
}

void ZY_RedirectFunction(CodeContext* pContext, void* pFunc)
{
	if (!pContext || !pContext->pFunc)
		return;

	LONG_PTR funcAddr = reinterpret_cast<LONG_PTR>(pContext->pFunc);
	LONG_PTR nOffset = reinterpret_cast<LONG_PTR>(pFunc) - funcAddr;
	if (nOffset <= 0x7FFFFFEF && nOffset >= -0x7FFFFFF0)
	{
		int nInv = ZY_CheckInvalidCode(pContext->pFunc, 5);
		if (nInv < 5)
		{
			ZY_CopyCode(pContext, reinterpret_cast<void*>(funcAddr), 5);
			*reinterpret_cast<BYTE*>(funcAddr) = 0xE9;	//jmp
			*reinterpret_cast<LONG*>(funcAddr + 1) = static_cast<LONG>(nOffset) - 5;
		}
		else
		{
			funcAddr -= 5;
			ZY_CopyCode(pContext, reinterpret_cast<void*>(funcAddr), 7);
			*reinterpret_cast<BYTE*>(funcAddr) = 0xE9;	//jmp
			*reinterpret_cast<LONG*>(funcAddr + 1) = nOffset;
			*reinterpret_cast<BYTE*>(funcAddr+5) = 0xEB;	//jmp
			*reinterpret_cast<BYTE*>(funcAddr+6) = -7;
		}

		if(g_nVerbose >= 5)
			ZY_Trace("write entry: %p, %i, 0x%zx, na", funcAddr, nInv, pFunc);
	}
	else 
	{
		int nInv = ZY_CheckInvalidCode(pContext->pFunc, 14);
		if (nInv >= 14)
		{
			funcAddr -= 14;
			ZY_CopyCode(pContext, reinterpret_cast<void*>(funcAddr), 16);
			*reinterpret_cast<BYTE*>(funcAddr) = 0xFF;	//jmp
			*reinterpret_cast<BYTE*>(funcAddr + 1) = 0x25;
			*reinterpret_cast<LONG*>(funcAddr + 2) = 0;
			*reinterpret_cast<ULONG_PTR*>(funcAddr + 6) = reinterpret_cast<LONG_PTR>(pFunc);
			*reinterpret_cast<BYTE*>(funcAddr + 14) = 0xEB;	//jmp
			*reinterpret_cast<BYTE*>(funcAddr + 15) = -16;
		}
		else if(nInv >= 8)
		{
			funcAddr -= 8;
			ZY_CopyCode(pContext, reinterpret_cast<void*>(funcAddr), 14);
			*reinterpret_cast<ULONG_PTR*>(funcAddr) = reinterpret_cast<LONG_PTR>(pFunc);
			*reinterpret_cast<BYTE*>(funcAddr + 8) = 0xFF;	//jmp
			*reinterpret_cast<BYTE*>(funcAddr + 9) = 0x25;
			*reinterpret_cast<LONG*>(funcAddr + 10) = -14;
		}
		else
		{
			if (pContext->nWriteOffset == 0)
			{
				if (pContext->pCode)
				{
					void* pAddr = ZY_WriteCode2(pContext->pCode, pContext->nCodeSize, reinterpret_cast<LONG_PTR>(pFunc));
					if (pAddr)
						pContext->nWriteOffset = reinterpret_cast<LONG_PTR>(pAddr) - funcAddr;
				}
			}
			if (pContext->nWriteOffset != 0)
			{
				ZY_CopyCode(pContext, reinterpret_cast<void*>(funcAddr), 6);
				*reinterpret_cast<BYTE*>(funcAddr) = 0xFF;	//jmp
				*reinterpret_cast<BYTE*>(funcAddr + 1) = 0x25;
				*reinterpret_cast<LONG*>(funcAddr + 2) = static_cast<LONG>(pContext->nWriteOffset) - 6;
			}
			else
			{
				ZY_CopyCode(pContext, reinterpret_cast<void*>(funcAddr), 14);
				*reinterpret_cast<BYTE*>(funcAddr) = 0xFF;	//jmp
				*reinterpret_cast<BYTE*>(funcAddr + 1) = 0x25;
				*reinterpret_cast<LONG*>(funcAddr + 2) = 0;
				*reinterpret_cast<LONG_PTR*>(funcAddr + 6) = reinterpret_cast<LONG_PTR>(pFunc);
			}
		}
		if(g_nVerbose >= 5)
			ZY_Trace("write entry: %p, %i, 0x%zx, %zi", funcAddr, nInv, pFunc, pContext->nWriteOffset);
	}
}

void ZY_RedirectFunction2(CodeContext* pContext, void* pFunc)
{
	if (!pContext || !pContext->pFunc)
		return;

	if (pContext->nFlag == 0)
		ZY_RedirectFunction(pContext, pFunc);
	else
	{
		ZY_CopyCode(pContext, 0, 8);
		*reinterpret_cast<ULONG_PTR*>(pContext->pFunc) = reinterpret_cast<ULONG_PTR>(pFunc);
	}
}

bool ZY_RedirectFunction3(FuncContext* pContext, int nRedirectFlag, int nSeg)
{
	if (nSeg >= 4)
		return false;

	CodeContext* pCodeCtx = pContext->m_c + nSeg;
	if (!pCodeCtx->pFunc)
		return true;
	if (pCodeCtx->nRedirectFlag == nRedirectFlag)
		return true;
	if (nRedirectFlag == 0 && pCodeCtx->nCopySize == 0)
	{
		pCodeCtx->nRedirectFlag = 0;
		return true;
	}

	ULONG OldAccessProtection = PAGE_READWRITE;
	LONG_PTR addr = reinterpret_cast<ULONG_PTR>(pCodeCtx->pFunc) - 16;
	if (!ZY_ProtectVirtualMemory(reinterpret_cast<void*>(addr), 32, PAGE_EXECUTE_READWRITE, &OldAccessProtection))
	{
		ZY_Error("unable to patch %s (%p); unable to get write permission", pContext->pName1, pCodeCtx->pFunc);
		return false;
	}

	if (nRedirectFlag == 0)
	{
		ZY_RollBackCode(pCodeCtx);
	}
	else
	{
		void* pFunc = nRedirectFlag == 1 ? pContext->pFunc4 : pContext->pFunc5;
		if (pFunc)
			ZY_RedirectFunction2(pCodeCtx, pFunc);
	}

	pCodeCtx->nRedirectFlag = nRedirectFlag;
	ZY_ProtectVirtualMemory(reinterpret_cast<void*>(addr), 32, OldAccessProtection, &OldAccessProtection);

	return true;
}

bool ZY_RedirectFunction4(FuncContext* pContext, int nRedirectFlag)
{
	if (!pContext->m_c[0].pFunc)
		return true;

	if (nRedirectFlag == 2 && !pContext->pFunc5)
		nRedirectFlag = 1;

	if (nRedirectFlag != 0)
	{
		for (int i = 0; i < 4; ++i)
		{
			if (!ZY_RedirectFunction3(pContext, nRedirectFlag, i))
				return false;
		}
	}
	else
	{
		bool bRet = true;
		for (int i = 3; i >= 0; --i)
		{
			if (!ZY_RedirectFunction3(pContext, 0, i))
				bRet = false;
		}
		return bRet;
	}

	return true;
}

bool ZY_RedirectFunction5(int nRedirectFlag, FuncContext** ppContexts)
{
	if (g_nRedirectFlag == nRedirectFlag)
		return true;
	g_nRedirectFlag = nRedirectFlag;

	if (nRedirectFlag != 0)
	{
		for (int i = 0; ppContexts[i]; ++i)
		{
			FuncContext* pContexts = ppContexts[i];
			for (int j = 0; pContexts[j].pName1; ++j)
			{
				if (!ZY_RedirectFunction4(pContexts + j, nRedirectFlag))
					return false;
			}
		}
	}
	else
	{
		bool bRet = true;
		int i = 0;
		for (; ppContexts[i]; ++i);

		while (i != 0)
		{
			--i;

			FuncContext* pContexts = ppContexts[i];
			int j = 0;
			for (; pContexts[j].pName1; ++j);

			while (j != 0)
			{
				--j;
				if (!ZY_RedirectFunction4(pContexts + j, 0))
					bRet = false;
			}
		}

		return bRet;
	}

	return true;
}

int ZY_RedirectFunction6(int nRedirectFlag, FuncContext** ppContexts)
{
	bool bRet = ZY_RedirectFunction5(nRedirectFlag, ppContexts);
	if (nRedirectFlag == 0 || bRet || ZY_RedirectFunction5(0, ppContexts))
		return !bRet;

	ZY_Error("unable to roll back partially applied patches!");
	return 2;
}

void ZY_RollBackCode(CodeContext* pContext)
{
	if (!pContext || 0 == pContext->nCopySize || !pContext->pCopyAddr)
		return;
	Zy_Memcpy(pContext->pCopyAddr, pContext->szCopyCode, pContext->nCopySize);
}

bool ZY_IsWin11OrGreater()
{
	size_t buildNum = 0;
	ZY_GetSysVersion(nullptr, &buildNum);
	return buildNum >= 22000;
}

PZYLDR_DATA_TABLE_ENTRY ZY_GetDataTableEntry(void* handle)
{
	PZYLDR_DATA_TABLE_ENTRY pEntry = nullptr;
	if (NT_SUCCESS(LdrFindEntryForAddress(handle, &pEntry)))
		return pEntry;
	return nullptr;
}

bool ZY_IsProcessAttachCalled(void* handle)
{
	PZYLDR_DATA_TABLE_ENTRY pEntry = ZY_GetDataTableEntry(handle);
	return pEntry && (pEntry->Flags & LDRP_PROCESS_ATTACH_CALLED);
}

bool ZY_VoidEnumLoadedModulesCallback(const char*, void*, FuncContext*)
{
	return true;
}

void ZY_PrintNtDllOrder(bool bLoad)
{
	ZY_EnumerateNtLoadedModules(ZY_VoidEnumLoadedModulesCallback, nullptr, bLoad, true);
}

bool ZY_ProtectVirtualMemory(PVOID BaseAddress, SIZE_T NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection)
{
	PVOID BaseAddress_ = BaseAddress;
	SIZE_T NumberOfBytesToProtect_ = NumberOfBytesToProtect;
	ULONG NewAccessProtection_ = NewAccessProtection;
	PULONG OldAccessProtection_ = OldAccessProtection;
	return NT_SUCCESS(NtProtectVirtualMemory(INVALID_HANDLE_VALUE, &BaseAddress, &NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection));
}

HANDLE ZY_GetOneProcessHeaps()
{
	HANDLE handle;
	if (RtlGetProcessHeaps(1, &handle))
		return handle;
	return INVALID_HANDLE_VALUE;
}

bool ZY_IsGlobalProcessHeaps(HANDLE handle)
{
	if (g_processHeaps == INVALID_HANDLE_VALUE)
		g_processHeaps = ZY_GetOneProcessHeaps();
	return handle == g_processHeaps;
}

PIMAGE_NT_HEADERS ZY_GetImageNTHeaders(PIMAGE_DOS_HEADER pDosHeader)
{
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)	//"MZ"
	{
		ZY_Error("DOS header magic number is invalid (0x%x)", pDosHeader->e_magic);
		return nullptr;
	}

	ULONG_PTR BasePtr = reinterpret_cast<ULONG_PTR>(pDosHeader);
    LONG peNtHeaderBaseOffset = pDosHeader->e_lfanew;
    PIMAGE_NT_HEADERS pNTHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(BasePtr + peNtHeaderBaseOffset);

	if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)	//"PE"
	{
        ZY_Error("NT header signature is invalid (0x%lx)", pNTHeader->Signature);
        return nullptr;
	}

	return pNTHeader;
}

PVOID ZY_GetImageDirectionEntry(PVOID handle, DWORD nIndex)
{
	ULONG_PTR h = reinterpret_cast<ULONG_PTR>(handle);
	bool flag = true;
	if (h & 1)
	{
		h = h & (~1ULL);
		flag = false;
	}
	PIMAGE_NT_HEADERS pNTHeader = ZY_GetImageNTHeaders(reinterpret_cast<PIMAGE_DOS_HEADER>(h));
	if (!pNTHeader)
		return nullptr;

	DWORD nNum = pNTHeader->OptionalHeader.NumberOfRvaAndSizes;
	if (nNum < nIndex)
	{
        ZY_Error("directory is out of range invalid (%lu but only %lu directories)", nIndex, nNum);
		return nullptr;
	}

	ULONG dwImage_Export_Directory_RVA = pNTHeader->OptionalHeader.DataDirectory[nIndex].VirtualAddress;
	if (dwImage_Export_Directory_RVA == 0)
		return nullptr;

	if (flag || dwImage_Export_Directory_RVA < pNTHeader->OptionalHeader.SizeOfHeaders)
		return reinterpret_cast<PVOID>(h + dwImage_Export_Directory_RVA);
	else
		return ZY_GetImageDirectionEntry2(pNTHeader, reinterpret_cast<PVOID>(h), dwImage_Export_Directory_RVA);
}

PVOID ZY_GetImageDirectionEntry2(PIMAGE_NT_HEADERS pNtHeader, PVOID handle, DWORD offset)
{
	PIMAGE_SECTION_HEADER pSectionHeader = ZY_GetImageSectionHeader(pNtHeader, offset);
	if (!pSectionHeader)
		return nullptr;
	ULONG_PTR header = reinterpret_cast<ULONG_PTR>(handle) + pSectionHeader->PointerToRawData + offset;
	return reinterpret_cast<PVOID>(header - pSectionHeader->VirtualAddress);
}

PIMAGE_SECTION_HEADER ZY_GetImageSectionHeader(PIMAGE_NT_HEADERS pNtHeader, DWORD offset)
{
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);
	WORD nNumOfSection = pNtHeader->FileHeader.NumberOfSections;
    for (int i = 0; i < nNumOfSection; ++i)
    {
		DWORD dwAddr = pSectionHeader->VirtualAddress;
		if (dwAddr < offset && offset < dwAddr + pSectionHeader->Misc.VirtualSize)
			return pSectionHeader;
		++pSectionHeader;
    }
	return nullptr;
}

PVOID ZY_GetCurrentModuleHandle()
{
	PPEB pPeb = RtlGetCurrentPeb();
	if (pPeb)
		return pPeb->Reserved3[1];

	return nullptr;
}

PVOID* ZY_GetTlsCallBacks()
{
	PVOID handle = ZY_GetCurrentModuleHandle();
	if (!handle)
		return nullptr;

	PIMAGE_TLS_DIRECTORY pTlsDict = static_cast<PIMAGE_TLS_DIRECTORY>(ZY_GetImageDirectionEntry(handle, IMAGE_DIRECTORY_ENTRY_TLS));
	if (!pTlsDict)
		return nullptr;
	return reinterpret_cast<PVOID*>(pTlsDict->AddressOfCallBacks);
}

VOID NTAPI EnumProc(PZYLDR_DATA_TABLE_ENTRY ModuleInformation, PVOID Context, BOOLEAN* Stop)
{
	PVOID handle = nullptr;
	if (NT_SUCCESS(LdrGetDllHandle(nullptr, nullptr, &ModuleInformation->FullDllName, &handle)))
	{
		CHAR buf[MAX_BUF_LEN];
		ANSI_STRING strAnsi;
		strAnsi.Length = 0;
		strAnsi.MaximumLength = MAX_BUF_LEN;
		strAnsi.Buffer = buf;
		RtlUnicodeStringToAnsiString(&strAnsi, &ModuleInformation->FullDllName, false);
		ZyEnumLoadedModuleContext* pCtx = reinterpret_cast<ZyEnumLoadedModuleContext*>(Context);
		if (!pCtx->func(buf, handle, pCtx->pContext))
		{
			pCtx->bStatus = false;
		}
	}
}

bool ZY_EnumerateLoadedModules(PMY_ENUMLOADED_MODULES_CALLBACK func, FuncContext* pContext)
{
	return ZY_EnumerateNtLoadedModules(func, pContext, true, true);
}

bool ZY_EnumerateNtLoadedModules(PMY_ENUMLOADED_MODULES_CALLBACK func, FuncContext* pContext, bool bLoad, bool bPrint)
{
	ZyEnumLoadedModuleContext context = { func, pContext, true };
    void* handle = ZY_GetModelHandle("ntdll.dll");
    if (!handle)
        return false;

    PZYLDR_DATA_TABLE_ENTRY pEntry = ZY_GetDataTableEntry(handle);
    if (!pEntry)
        return false;

	if (bPrint)
	{
		if (bLoad)
			ZY_Trace("module %s order:", "load");
		else
			ZY_Trace("module %s order:", "initialization");
	}

    LIST_ENTRY* pEntryBegin = bLoad ? &pEntry->InLoadOrderLinks : &pEntry->InInitializationOrderLinks;
    LIST_ENTRY* pEntryIter = pEntryBegin;
    int i = 0;
    do
    {
        SIZE_T nOffset = bLoad ? offsetof(ZYLDR_DATA_TABLE_ENTRY, InLoadOrderLinks) : offsetof(ZYLDR_DATA_TABLE_ENTRY, InInitializationOrderLinks);
        PZYLDR_DATA_TABLE_ENTRY pEntryCur = reinterpret_cast<PZYLDR_DATA_TABLE_ENTRY>((reinterpret_cast<char*>(pEntryIter) - nOffset));
		if (!pEntryCur->DllBase || !pEntryCur->FullDllName.Buffer)
		{
			if(bPrint)
				ZY_Trace("%d: skipping empty module, base: %p", i, pEntryCur);
		}
		else
		{
			CHAR buf[MAX_BUF_LEN] = { 0 };
			ANSI_STRING strAnsi;
			strAnsi.Length = 0;
			strAnsi.MaximumLength = MAX_BUF_LEN;
			strAnsi.Buffer = buf;
			ZY_UnicodeStringToAnsiString(&strAnsi, &pEntryCur->FullDllName);
			if (bPrint)
			{
				if (pEntryCur->Flags & LDRP_PROCESS_ATTACH_CALLED)
					ZY_Trace("%d: %s, %s, base: %p", i, buf, "initialized", pEntryCur);
				else
					ZY_Trace("%d: %s, %s, base: %p", i, buf, "uninitialized", pEntryCur);
			}
			ZY_ProcessModuleForEnumerate(buf, pEntryCur->DllBase, &context);
		}
        pEntryIter = pEntryIter->Flink;
        ++i;
    } while (pEntryIter && pEntryIter != pEntryBegin);

	return context.bStatus;
}

void ZY_ProcessModuleForEnumerate(const char* pDllName, PVOID dllBase, ZyEnumLoadedModuleContext* context)
{
	if (!pDllName || !*pDllName)
		return;
	if (!context->func(pDllName, dllBase, context->pContext))
		context->bStatus = false;
}

char ZY_ToLower(char c)
{
	if (c < 'A' || c>'Z')
		return c;
	return c + 32;
}

int ZY_StrLen(const char* pStr)
{
	if (!pStr)
		return 0;
	int nSize = 0;
	while (*(pStr+nSize))
	{
		++nSize;
	}
	return nSize;
}

int ZY_ComapreNoCase(const char* pStr1, const char* pStr2, int nSize)
{
	if (!pStr1)
	{
		if (!pStr2)
			return 0;
		return -1;
	}

	if (!pStr2)
		return 1;

	if (0 == nSize)
		return 0;

	const char* pIter1 = pStr1;
	const char* pIter2 = pStr2;
	char c1, c2;
	do
	{
		c1 = *pIter1++;
		c2 = *pIter2++;
		--nSize;
		if (c1 != c2)
		{
			if (ZY_ToLower(c1) != ZY_ToLower(c2))
				return c1 - c2;
		}
	} while (nSize && c1 && c2);

	return 0;
}

int ZY_ComapreNoCase2(const char* pStr1, const char* pStr2)
{
	while (*pStr1 && *pStr2)
	{
		if (pStr1 != pStr2)
		{
			if (ZY_ToLower(*pStr1) != ZY_ToLower(*pStr2))
			{
				break;
			}
		}
		++pStr1;
		++pStr2;
	}

	return ZY_ToLower(*pStr1) - ZY_ToLower(*pStr2);
}

bool ZY_IsSameStrNoCase(const char* pStr1, const char* pStr2)
{
	return 0 == ZY_ComapreNoCase(pStr1, pStr2, ZY_StrLen(pStr2));
}

int ZY_CompareStr(const char* pStr1, const char* pStr2)
{
	while (*pStr1 && *pStr2 && *pStr1 == *pStr2)
	{
		++pStr1;
		++pStr2;
	}
	return *pStr1 - *pStr2;
}

int ZY_CompareStr2(const char* pStr1, const char* pStr2, int nSize)
{
	if (!pStr1)
	{
		if (!pStr2)
			return 0;
		return -1;
	}

	if (!pStr2)
		return 1;

	while (nSize)
	{
		char c1 = *pStr1++;
		char c2 = *pStr2++;
		--nSize;
		if (c1 != c2)
			return c1 - c2;
	}

	return 0;
}

const char* ZY_FindNoCase(const char* pStr, char c)
{
	char c1 = ZY_ToLower(c);
	do 
	{
		if (*pStr == c || ZY_ToLower(*pStr) == c1)
			return pStr;
	} while (*pStr++);
	return nullptr;
}

const char* ZY_FindStrNoCase(const char* pStr, const char* pFind)
{
	int nLen = ZY_StrLen(pFind);
	const char* pIter = ZY_FindNoCase(pStr, *pFind);
	while (pIter)
	{
		if (0 == ZY_ComapreNoCase(pIter, pFind, nLen))
			return pIter;
		pIter = ZY_FindNoCase(pIter + 1, *pFind);
	}
	return nullptr;
}

const char* ZY_FindChar(const char* pStr, char c)
{
	const char* pPos = nullptr;
	do 
	{
		if (*pStr == c)
			pPos = pStr;
	} while (*pStr++);
	return pPos;
}

void Zy_Memcpy(void* pDest, void* pSrc, SIZE_T size)
{
	BYTE* pIter1 = reinterpret_cast<BYTE*>(pDest);
	BYTE* pIter2 = reinterpret_cast<BYTE*>(pSrc);
	while (size--)
	{
		*pIter1++ = *pIter2++;
	}
}

void ZY_PutString(const char* pStr)
{
	if (pStr)
	{
		for (int i = 0; *(pStr + i) && g_nBufLen < GLOBAL_BUF_LEN; ++i)
		{
			g_szBuf[g_nBufLen++] = *(pStr + i);
		}
		g_szBuf[g_nBufLen] = 0;
	}
}

void ZY_PutChar(char c)
{
	if (g_nBufLen < GLOBAL_BUF_LEN)
	{
		g_szBuf[g_nBufLen++] = c;
		g_szBuf[g_nBufLen] = 0;
	}
}

void ZY_PutFormatInt(LONG_PTR n, int m, char c1, char c2, int nLen)
{
	if (n == 0 || m == 0 || m > 16)
	{
		if (c1 != 0)
			ZY_PutChar(c1);
		ZY_PutChar('0');
	}

	SIZE_T nOldLen = g_nBufLen;
	while (n)
	{
		int a = n % m;
		if (a > 9)
			ZY_PutChar(a - 10 + 'a');
		else
			ZY_PutChar(a + '0');
		n /= m;
	}

	if (c1 != 0)
		ZY_PutChar(c1);

	int i;
	for (i = g_nBufLen - nOldLen; i < nLen && g_nBufLen < GLOBAL_BUF_LEN; ++i)
		ZY_PutChar(c2);

	for (int j = 0; j < i / 2; ++j)
	{
		char c = g_szBuf[g_nBufLen - j - 1];
		g_szBuf[g_nBufLen - j - 1] = g_szBuf[j + nOldLen];
		g_szBuf[j + nOldLen] = c;
	}
}

#define GoNext() \
	c = *(pFormat + i);\
	++i;\
	if (c == 0)\
		break;\

void ZY_Printf(const char* pPrev, const char* pFormat, va_list va)
{
	if (pPrev)
		ZY_PutString(pPrev);
	if (!va)
		return;

	int i = 0;
	while (true)
	{
		if(g_nBufLen >= GLOBAL_BUF_LEN)
			break;
		char c;
		GoNext();

		if (c != '%')
		{
			ZY_PutChar(c);
		}
		else
		{
			GoNext()
			char c1 = ' ';
			char c2 = 0;
			int nLen = 0;
			if (c == '+' || c == ' ')
			{
				c2 = c;
				GoNext()
			}
			if (c == '-')
			{
				GoNext();
			}
			if (c == '0')
			{
				c1 = c;
				GoNext();
			}
			if (c >= '1' && c <= '9')
			{
				nLen = c - '0';
				GoNext();
			}
			if (c == 'z' || c == 'l')
			{
				GoNext();
			}
			switch (c)
			{
			case 's':
			{
				char* s = va_arg(va, char*);
				ZY_PutString(s);
				break;
			}
			case 'p':
			case 'x':
			case 'u':
			{
				LONG_PTR n = va_arg(va, LONG_PTR);
				if (c == 'p')
				{
					ZY_PutString("0x");
					if (nLen == 0)
					{
						nLen = 16;
						c1 = '0';
					}
				}
				if (c == 'x' || c == 'p')
					ZY_PutFormatInt(n, 16, c2, c1, nLen);
				else
					ZY_PutFormatInt(n, 10, c2, c1, nLen);
				break;
			}
			case 'i':
			case 'd':
			{
				int n = va_arg(va, int);
				char c3 = 0;
				if (n >= 0)
				{
					if (c2)
						c3 = c2;
				}
				else
				{
					c3 = '-';
					n = -n;
				}
				ZY_PutFormatInt(n, 10, c3, c1, nLen);
				break;
			}
			default:
				ZY_PutChar(c);
				break;
			}
		}
	}
}

void ZY_Trace(const char* pFormat, ...)
{
	va_list va;
	va_start(va, pFormat);
	if (g_nVerbose)
	{
		ZY_Printf("mimalloc-redirect: trace: ", pFormat, va);
		ZY_PutChar('\n');
	}
	va_end(va);
}

void ZY_Warning(const char* pFormat, ...)
{
	va_list va;
	va_start(va, pFormat);
	ZY_Printf("mimalloc-redirect: warning: ", pFormat, va);
	ZY_PutChar('\n');
	va_end(va);
}

void ZY_Error(const char* pFormat, ...)
{
	va_list va;
	va_start(va, pFormat);
	ZY_Printf("mimalloc-redirect: error: ", pFormat, va);
	ZY_PutChar('\n');
	va_end(va);
}

void Zy_InitFuncAddress(void* handle, FuncContext* pContext)
{
	for (int i = 0;; ++i)
	{
		FuncContext* pCurContext = pContext + i;
		if(!pCurContext->pName1)
			break;
		if (!pCurContext->pFunc4)
		{
			pCurContext->pFunc4 = ZY_GetActProcFunc("mimalloc", handle, pCurContext->pName2);
			if (!pCurContext->pFunc4)
			{
				ZY_Warning("cannot resolve target %s.", pCurContext->pName2);
			}
			if (pCurContext->pName3
				&& !pCurContext->pFunc5)
			{
				pCurContext->pFunc5 = ZY_GetActProcFunc("mimalloc", handle, pCurContext->pName3);
			}
		}
	}
}

bool ZY_EnumLoadedModulesCallback(const char* pDllName, void* handle, FuncContext* pContext)
{
	const char* pName = ZY_FindChar(pDllName, '\\');
	if (pName)
		pName++;
	else
		pName = pDllName;

	bool bIsUcrtbase = ZY_IsSameStrNoCase(pName, "ucrtbase");
	if (!bIsUcrtbase && (0 != ZY_ComapreNoCase2(pName, "shell32.dll") || !ZY_IsWin11OrGreater()))
		return true;
	if(g_nVerbose >= 5)
		ZY_Trace("resolving \"%s\"", pName);
	ZY_ResolveFunction(pName, handle, pContext, !bIsUcrtbase);
	if (!ZY_IsProcessAttachCalled(handle))
		return true;
	ZY_Error("mimalloc-redirect.dll seems to be initialized after %s\n"
		"  (hint: try to link with the mimalloc library earlier on the command line?)"
		, pName
	);
	ZY_PrintNtDllOrder(true);
	ZY_PrintNtDllOrder(false);

	return false;
}

void ZY_ResolveFunction(const char* pModuleName, void* handle, FuncContext* pContext, bool bResolveImport)
{
	size_t nSize = 0;
	void* pCode = ZY_GetCodeSegment(handle, &nSize);
	ZY_Trace("resolving module: %s 0x%zx: code start 0x%zx, size: 0x%zx", pModuleName, handle, pCode, nSize);
	for (int i = 0;; ++i)
	{
		FuncContext* pCurContext = pContext + i;
		if (!pCurContext->pName1)
			break;

		int j = 0;
		for (; j < 4 && pCurContext->m_c[j].pFunc; ++j);

		if (j >= 4)
			continue;

		if (pCurContext->pDllName || bResolveImport)
		{
			if (pCurContext->pDllName && (g_bPatchImportsOn || bResolveImport))
			{
				void* pFunc = ZY_GetFuncAddress3(pModuleName, handle, pCurContext->pDllName, pCurContext->pName1);
				if (pFunc)
				{
					if (pCurContext->ppFunc7)
						*pCurContext->ppFunc7 = pFunc;
					pCurContext->m_c[j].nFlag = 1;
					pCurContext->m_c[j].pFunc = pFunc;
					if(g_nVerbose >= 5)
						ZY_Trace("resolve import \"%s!%s\" in %s at %p to %p (%i)", pCurContext->pDllName, pCurContext->pName1, pModuleName, pFunc, pCurContext->pFunc4, j);
				}
			}
		}
		else
		{
			void* pFunc = ZY_GetActProcFunc(pModuleName, handle, pCurContext->pName1);
			if (pFunc)
			{
				pCurContext->m_c[j].nFlag = 0;
				pCurContext->m_c[j].pFunc = pFunc;
				pCurContext->m_c[j].pCode = pCode;
				pCurContext->m_c[j].nCodeSize = nSize;
				if(g_nVerbose >= 5)
					ZY_Trace("resolve \"%s\" at %s!%p to mimalloc!%p (%i)", pCurContext->pName1, pModuleName, pFunc, pCurContext->pFunc4, j);
			}
		}
	}
}

void* ZY_ResolveProcess(void* handle2, FuncContext* pContext, const char** pOverrideDlls, bool bForceRedirect, FuncContext* pNTContext, char* pPatchNtDlls)
{
	void* handle = nullptr;
	for (int i = 0; !handle && pOverrideDlls[i]; ++i)
	{
		ZY_Trace("checking for target %s", pOverrideDlls[i]);
		handle = ZY_GetModelHandle(pOverrideDlls[i]);
	}
	if (!handle)
	{
		ZY_Error("unable to find target module.");
		return nullptr;
	}
	Zy_InitFuncAddress(handle, pContext);
	if(pNTContext)
		Zy_InitFuncAddress(handle, pNTContext);
	if (!ZY_EnumerateLoadedModules(ZY_EnumLoadedModulesCallback, pContext))
	{
		if (!bForceRedirect)
			return nullptr;
		ZY_Warning("there were errors during resolving but these are ignored (due to MIMALLOC_FORCE_REDIRECT=1).");
	}

	if (pNTContext && pPatchNtDlls)
	{
		const char* pIter = pPatchNtDlls;
		while (pIter && *pIter)
		{
			char* pEnd = const_cast<char*>(ZY_FindNoCase(pIter, ';'));
			if (pEnd)
				*(pEnd++) = 0;

			void* ntHandle = ZY_GetModelHandle(pIter);
			if (ntHandle)
				ZY_ResolveFunction(pIter, ntHandle, pNTContext, true);
			else
				ZY_Error("unable to find module '%s'", pIter);
		}
	}

	return handle;
}

void ZY_PrioritizeLoadOrder(void* handle)
{
	PZYLDR_DATA_TABLE_ENTRY pEntry = nullptr;
	if (!NT_SUCCESS(LdrFindEntryForAddress(handle, &pEntry)))
	{
		return;
	}

	void* ntHandle = ZY_GetModelHandle("ntdll.dll");
	PZYLDR_DATA_TABLE_ENTRY pNtEntry = nullptr;
	if (!NT_SUCCESS(LdrFindEntryForAddress(ntHandle, &pNtEntry)))
	{
		return;
	}

	if (pEntry == pNtEntry)
		return;

	if (pNtEntry->InLoadOrderLinks.Flink == &pEntry->InLoadOrderLinks)
		return;

	PLIST_ENTRY pFlink = pEntry->InLoadOrderLinks.Flink;
	PLIST_ENTRY pBlink = pEntry->InLoadOrderLinks.Blink;
	if (pFlink)
		pFlink->Blink = pBlink;
	if (pBlink)
		pBlink->Flink = pFlink;

	PLIST_ENTRY pFlink2 = pNtEntry->InLoadOrderLinks.Flink;
	pEntry->InLoadOrderLinks.Flink = pFlink2;
	if (pFlink2)
		pFlink2->Blink = &pEntry->InLoadOrderLinks;
	pEntry->InLoadOrderLinks.Blink = &pNtEntry->InLoadOrderLinks;
	pNtEntry->InLoadOrderLinks.Flink = &pEntry->InLoadOrderLinks;
}

void ZY_TlsEntryOverride(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	if (g_tlsEntry)
		g_tlsEntry(hModule, ul_reason_for_call, lpReserved);
	if (ul_reason_for_call == DLL_THREAD_DETACH)
	{
		if (g_redirect_entry)
			g_redirect_entry(DLL_THREAD_DETACH);
	}
}

bool ZY_IsTlsEntryPatched()
{
	return reinterpret_cast<ULONG_PTR>(g_tlsEntry) >= 2;
}

char* GetRedirectMessage()
{
	g_szBuf[g_nBufLen] = 0;
	if (g_nBufLen && g_szBuf[0])
		return g_szBuf;
	return nullptr;
}
