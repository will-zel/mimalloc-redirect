#pragma once

//////////////////////////////////////////////////////////////////////////
//for research and learning only
//////////////////////////////////////////////////////////////////////////

#define MAX_BUF_LEN 260

typedef struct ZY_LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	SHORT LoadCount;
	SHORT TlsIndex;
	union
	{
		LIST_ENTRY HashLinks;
		struct {
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union
	{
		ULONG TimeDateStamp;
		void* LoadedImports;
	};
	PVOID EntryPointActivationContext;
	PVOID PatchInformation;
} ZYLDR_DATA_TABLE_ENTRY, *PZYLDR_DATA_TABLE_ENTRY;

#define LDRP_PROCESS_ATTACH_CALLED 0x00080000

typedef VOID(NTAPI LDR_ENUM_CALLBACK)(PZYLDR_DATA_TABLE_ENTRY ModuleInformation, PVOID Context, BOOLEAN* Stop);
typedef LDR_ENUM_CALLBACK* PLDR_ENUM_CALLBACK;

struct CodeContext
{
	int nFlag;
	void* pFunc;
	int nRedirectFlag;
	void* pCode;
	SIZE_T nCodeSize;
	SIZE_T nWriteOffset;
	void* pCopyAddr;
	SIZE_T nCopySize;
	BYTE szCopyCode[16];
};

struct FuncContext
{
	const char* pName1;
	const char* pName2;
	const char* pName3;
	void* pFunc4;
	void* pFunc5;
	const char* pDllName;
	void** ppFunc7;
	CodeContext m_c[4];
};

typedef BOOL(*RedirectFuncPtr)(DWORD);
typedef void(*TlsEntryFuncPtr)(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved);

extern HANDLE g_processHeaps;
extern int g_nVerbose;
extern bool g_bPatchImportsOn;
extern bool g_bRedirected;
extern FuncContext g_szFuncCtxs[];
extern FuncContext* g_redirectContexts[];
extern TlsEntryFuncPtr g_tlsEntry;
extern RedirectFuncPtr g_redirect_entry;

void ZY_ToUnicodeString(PUNICODE_STRING pDestinationString, const char* pSource);
void ZY_AnsiStringToUnicodeString(PUNICODE_STRING pDestinationString, PCANSI_STRING pSourceString);
void ZY_UnicodeStringToAnsiString(PANSI_STRING pDestinationString, PCUNICODE_STRING pSourceString);
int ZY_GetEnvironmentVariable(const char* lpName, char* lpBuffer, int nSize);
size_t ZY_GetSysVersion(size_t* pMinorVersion, size_t* pBuildNumber);
bool ZY_IsWin11OrGreater();

PZYLDR_DATA_TABLE_ENTRY ZY_GetDataTableEntry(void* handle);
bool ZY_IsProcessAttachCalled(void* handle);
void ZY_PrintNtDllOrder(bool bLoad);
bool ZY_ProtectVirtualMemory(PVOID BaseAddress, SIZE_T NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection);
HANDLE ZY_GetOneProcessHeaps();
bool ZY_IsGlobalProcessHeaps(HANDLE handle);

PIMAGE_NT_HEADERS ZY_GetImageNTHeaders(PIMAGE_DOS_HEADER pDosHeader);
PVOID ZY_GetImageDirectionEntry(PVOID handle, DWORD nIndex);
PVOID ZY_GetImageDirectionEntry2(PIMAGE_NT_HEADERS pNtHeader, PVOID handle, DWORD offset);
PIMAGE_SECTION_HEADER ZY_GetImageSectionHeader(PIMAGE_NT_HEADERS pNtHeader, DWORD offset);
PVOID ZY_GetCurrentModuleHandle();
PVOID* ZY_GetTlsCallBacks();

void* ZY_GetModelHandle(const char* pModelName);
void* ZY_GetFuncAddress(void* handle, const char* pFuncName);
void* ZY_GetFuncAddress2(void* handle, const char* pModelName, const char* pFuncName, void** ppFunc);
void* ZY_GetFuncAddress3(const char* pModelName1, void* handle, const char* pModelName2, const char* pFuncName);
void* ZY_GetActProcFunc(const char* pModelName, void* handle, const char* pFuncName);
void* ZY_GetCodeSegment(void* handle, size_t* nSize);

void* ZY_GetJmpCallFunc(void* pFunc);
int ZY_CheckInvalidCode(void* addr, int nSize);
bool ZY_CheckInvalidCode2(void* addr, int nSize);
void ZY_CopyCode(CodeContext* pContext, void* addr, int nSize);
bool ZY_WriteCode(void* addr, LONG_PTR code);
void* ZY_WriteCode2(void* addr, SIZE_T size, LONG_PTR code);
bool ZY_WriteCode3(PVOID addr, ULONG_PTR code, ULONG_PTR* oldCode);

void ZY_RedirectFunction(CodeContext* pContext, void* pFunc);
void ZY_RedirectFunction2(CodeContext* pContext, void* pFunc);
bool ZY_RedirectFunction3(FuncContext* pContext, int nRedirectFlag, int nSeg);
bool ZY_RedirectFunction4(FuncContext* pContext, int nRedirectFlag);
bool ZY_RedirectFunction5(int nRedirectFlag, FuncContext** ppContexts);
int ZY_RedirectFunction6(int nRedirectFlag, FuncContext** ppContexts);
void ZY_RollBackCode(CodeContext* pContext);

char ZY_ToLower(char c);
int ZY_StrLen(const char* pStr);
int ZY_ComapreNoCase(const char* pStr1, const char* pStr2, int nSize);
int ZY_ComapreNoCase2(const char* pStr1, const char* pStr2);
bool ZY_IsSameStrNoCase(const char* pStr1, const char* pStr2);
int ZY_CompareStr(const char* pStr1, const char* pStr2);
int ZY_CompareStr2(const char* pStr1, const char* pStr2, int nSize);
const char* ZY_FindNoCase(const char* pStr, const char c);
const char* ZY_FindStrNoCase(const char* pStr, const char* pFind);
const char* ZY_FindCharR(const char* pStr, char c);
void Zy_Memcpy(void* pDest, void* pSrc, SIZE_T size);

void ZY_PutString(const char*);
void ZY_PutChar(char c);
void ZY_PutFormatInt(LONG_PTR n, int m, char c1, char c2, int nLen);
void ZY_Printf(const char* pPrev, const char* pFormat, va_list va);
void ZY_Trace(const char* pFormat, ...);
void ZY_Warning(const char* pFormat, ...);
void ZY_Error(const char* pFormat, ...);

void Zy_InitFuncAddress(void* handle, FuncContext* pContext);

typedef bool(ZY_ENUMLOADED_MODULES_CALLBACK)(const char*, void*, FuncContext*);
typedef ZY_ENUMLOADED_MODULES_CALLBACK* PMY_ENUMLOADED_MODULES_CALLBACK;

struct ZyEnumLoadedModuleContext
{
    PMY_ENUMLOADED_MODULES_CALLBACK func;
    FuncContext* pContext;
    bool bStatus;
};

bool ZY_EnumerateLoadedModules(PMY_ENUMLOADED_MODULES_CALLBACK func, FuncContext* pContext);
bool ZY_EnumerateNtLoadedModules(PMY_ENUMLOADED_MODULES_CALLBACK func, FuncContext* pContext, bool bLoad, bool bPrint);
void ZY_ProcessModuleForEnumerate(const char* pDllName, PVOID dllBase, ZyEnumLoadedModuleContext* context);
bool ZY_EnumLoadedModulesCallback(const char*, void*, FuncContext*);
void ZY_ResolveFunction(const char* pModuleName, void* handle, FuncContext* pContext, bool bResolveImport);
void* ZY_ResolveProcess(void* handle, FuncContext* pContext, const char** pOverrideDlls, bool bForceRedirect,
	FuncContext* pNTContext, char* pPatchNtDlls);
void ZY_PrioritizeLoadOrder(void* handle);

void ZY_TlsEntryOverride(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved);
bool ZY_IsTlsEntryPatched();

char* GetRedirectMessage();
