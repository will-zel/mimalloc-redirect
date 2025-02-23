//////////////////////////////////////////////////////////////////////////
//for research and learning only
//////////////////////////////////////////////////////////////////////////

#include "pch.h"
#include "InternalFunc.h"
#include "mimalloc_redirect.h"
#include <stdint.h>

#define CUR_VER "v1.3.2"

#define ADDCONTEXT0(func1, func2) {#func1, #func2},
#define ADDCONTEXT1(func1, func2) {#func1, #func2, 0, 0, 0, 0, 0, {{0, &func1}}},
#define ADDCONTEXT2(func1, func2, func3) {#func1, #func2, #func3, 0, &func3},
#define ADDCONTEXT3(func1, func2, func3) {#func1, #func2, #func3, &func2, &func3},
#define ADDCONTEXT4(func1, func2, dll, var) {#func1, #func2, 0, &func2, 0, dll, reinterpret_cast<void**>(&var)},
#define ADDCONTEXT5(func1, func2) {#func1, #func2, 0, &func2},

FuncContext g_szFuncCtxs[] = {
    ADDCONTEXT1(_mi_recalloc_ind,mi_recalloc)
    ADDCONTEXT1(_mi_malloc_ind,mi_malloc)
    ADDCONTEXT1(_mi_calloc_ind,mi_calloc)
    ADDCONTEXT1(_mi_realloc_ind,mi_realloc)
    ADDCONTEXT1(_mi_free_ind,mi_free)
    ADDCONTEXT1(_mi_expand_ind,mi_expand)
    ADDCONTEXT1(_mi_usable_size_ind,mi_usable_size)
    ADDCONTEXT1(_mi_new_nothrow_ind,mi_new_nothrow)
    ADDCONTEXT1(_mi_is_in_heap_region_ind,mi_is_in_heap_region)
    ADDCONTEXT1(_mi_malloc_aligned_ind,mi_malloc_aligned)
    ADDCONTEXT1(_mi_realloc_aligned_ind,mi_realloc_aligned)
    ADDCONTEXT1(_mi_aligned_recalloc_ind,mi_aligned_recalloc)
    ADDCONTEXT1(_mi_malloc_aligned_at_ind,mi_malloc_aligned_at)
    ADDCONTEXT1(_mi_realloc_aligned_at_ind,mi_realloc_aligned_at)
    ADDCONTEXT1(_mi_aligned_offset_recalloc_ind,mi_aligned_offset_recalloc)
    ADDCONTEXT0(malloc,mi_malloc)
    ADDCONTEXT0(calloc,mi_calloc)
    ADDCONTEXT2(realloc,mi_realloc,_mi_realloc_term)
    ADDCONTEXT2(free,mi_free,_mi_free_term)
    ADDCONTEXT2(_expand,mi_expand,_mi__expand_term)
    ADDCONTEXT2(_recalloc,mi_recalloc,_mi__recalloc_term)
    ADDCONTEXT2(_msize,mi_usable_size,_mi__msize_term)
    ADDCONTEXT0(aligned_alloc,mi_aligned_alloc)
    ADDCONTEXT0(_aligned_alloc,mi_aligned_alloc)
    ADDCONTEXT0(_malloc_base,mi_malloc)
    ADDCONTEXT0(_calloc_base,mi_calloc)
    ADDCONTEXT2(_realloc_base,mi_realloc,_mi_realloc_term)
    ADDCONTEXT2(_free_base,mi_free,_mi_free_term)
    ADDCONTEXT3(_expand_base,_mi__expand_base,_mi__expand_base_term)
    ADDCONTEXT3(_recalloc_base,_mi__recalloc_base,_mi__recalloc_base_term)
    ADDCONTEXT3(_msize_base,_mi__msize_base,_mi__msize_base_term)
    ADDCONTEXT4(RtlSizeHeap,_mi_safe_RtlSizeHeap,"ntdll.dll",g_RtlSizeHeap)
    ADDCONTEXT4(RtlFreeHeap,_mi_safe_RtlFreeHeap,"ntdll.dll",g_RtlFreeHeap)
    ADDCONTEXT4(RtlReAllocateHeap,_mi_safe_RtlReAllocateHeap,"ntdll.dll",g_RtlReAllocateHeap)
    ADDCONTEXT0(_aligned_malloc,mi_malloc_aligned)
    ADDCONTEXT2(_aligned_realloc,mi_realloc_aligned,_mi__aligned_realloc_term)
    ADDCONTEXT2(_aligned_free,mi_free,_mi_free_term)
    ADDCONTEXT2(_aligned_recalloc,mi_aligned_recalloc,_mi__aligned_recalloc_term)
    ADDCONTEXT3(_aligned_msize,_mi__aligned_msize,_mi__aligned_msize_term)
    ADDCONTEXT0(_aligned_offset_malloc,mi_malloc_aligned_at)
    ADDCONTEXT2(_aligned_offset_realloc,mi_realloc_aligned_at,_mi__aligned_offset_realloc_term)
    ADDCONTEXT2(_aligned_offset_recalloc,mi_aligned_offset_recalloc,_mi__aligned_offset_recalloc_term)
    ADDCONTEXT5(_malloc_dbg,_mi__malloc_dbg)
    ADDCONTEXT5(_realloc_dbg,_mi__realloc_dbg)
    ADDCONTEXT5(_calloc_dbg,_mi__calloc_dbg)
    ADDCONTEXT5(_free_dbg,_mi__free_dbg)
    ADDCONTEXT3(_expand_dbg,_mi__expand_dbg,_mi__expand_dbg_term)
    ADDCONTEXT3(_recalloc_dbg,_mi__recalloc_dbg,_mi__recalloc_dbg_term)
    ADDCONTEXT3(_msize_dbg,_mi__msize_dbg,_mi__msize_dbg_term)
    ADDCONTEXT5(_aligned_malloc_dbg,_mi__aligned_malloc_dbg)
    ADDCONTEXT3(_aligned_realloc_dbg,_mi__aligned_realloc_dbg,_mi__aligned_realloc_dbg_term)
    ADDCONTEXT2(_aligned_free_dbg,mi_free,_mi_free_term)
    ADDCONTEXT3(_aligned_msize_dbg,_mi__aligned_msize,_mi__aligned_msize_term)
    ADDCONTEXT3(_aligned_recalloc_dbg,_mi__aligned_recalloc_dbg,_mi__aligned_recalloc_dbg_term)
    ADDCONTEXT5(_aligned_offset_malloc_dbg,_mi__aligned_offset_malloc_dbg)
    ADDCONTEXT3(_aligned_offset_realloc_dbg,_mi__aligned_offset_realloc_dbg,_mi__aligned_offset_realloc_dbg_term)
    ADDCONTEXT3(_aligned_offset_recalloc_dbg, _mi__aligned_offset_recalloc_dbg, _mi__aligned_offset_recalloc_dbg_term)
    {0}
};

FuncContext g_szNTHeapFuncCtxs[] = {
    ADDCONTEXT4(RtlAllocateHeap, _mi_RtlAllocateHeap, "ntdll.dll", g_RtlAllocateHeap)
    ADDCONTEXT4(RtlSizeHeap, _mi_RtlSizeHeap, "ntdll.dll", g_RtlSizeHeap)
    ADDCONTEXT4(RtlFreeHeap, _mi_RtlFreeHeap, "ntdll.dll", g_RtlFreeHeap)
    ADDCONTEXT4(RtlReAllocateHeap, _mi_RtlReAllocateHeap, "ntdll.dll", g_RtlReAllocateHeap)
    ADDCONTEXT4(HeapAlloc, _mi_RtlAllocateHeap, "kernel32.dll", g_RtlAllocateHeap)
    ADDCONTEXT4(HeapSize, _mi_RtlSizeHeap, "kernel32.dll", g_RtlSizeHeap)
    ADDCONTEXT4(HeapFree, _mi_RtlFreeHeap, "kernel32.dll", g_RtlFreeHeap)
    ADDCONTEXT4(HeapReAlloc, _mi_RtlReAllocateHeap, "kernel32.dll", g_RtlReAllocateHeap)
    {0}
};


FuncContext* g_redirectContexts[3] = { 0 };
RedirectFuncPtr g_redirect_entry = nullptr;
TlsEntryFuncPtr g_tlsEntry = nullptr;
bool g_bRedirected = false;

bool ProcessRedirect(HMODULE hModule)
{
    bool bR = true;
    char szVal[MAX_BUF_LEN];
    bool nRet = ZY_GetEnvironmentVariable("MIMALLOC_DISABLE_REDIRECT", szVal, MAX_BUF_LEN);
    if (!nRet)
    {
        nRet = ZY_GetEnvironmentVariable("MIMALLOC_DISABLE_OVERRIDE", szVal, MAX_BUF_LEN);
    }
    nRet = nRet && (0 == szVal[0] || ZY_FindStrNoCase("1;TRUE;YES;ON", szVal));
    if (!nRet)
    {
        nRet = ZY_GetEnvironmentVariable("MIMALLOC_ENABLE_REDIRECT", szVal, MAX_BUF_LEN)
            && ZY_FindStrNoCase("0;FALSE;NO;OFF", szVal);
    }
    if (!nRet)
    {
        if (ZY_GetEnvironmentVariable("MIMALLOC_VERBOSE", szVal, MAX_BUF_LEN)
            && szVal[0] >= '3' && szVal[0] <= '9')
            g_nVerbose = szVal[0] - '0';
        g_nVerbose = 9;

        bool bLoadOrderOn = ZY_GetEnvironmentVariable("MIMALLOC_PRIORITIZE_LOAD_ORDER", szVal, MAX_BUF_LEN)
            && (0 == szVal[0] || ZY_FindStrNoCase("1;TRUE;YES;ON", szVal));

        g_bPatchImportsOn = ZY_GetEnvironmentVariable("MIMALLOC_PATCH_IMPORTS", szVal, MAX_BUF_LEN)
            && (0 == szVal[0] || ZY_FindStrNoCase("1;TRUE;YES;ON", szVal));

        bool bForceRedirect = ZY_GetEnvironmentVariable("MIMALLOC_FORCE_REDIRECT", szVal, MAX_BUF_LEN)
            && (0 == szVal[0] || ZY_FindStrNoCase("1;TRUE;YES;ON", szVal));

        bool bHasPatchNTHeap = ZY_GetEnvironmentVariable("MIMALLOC_PATCH_NTHEAP", szVal, MAX_BUF_LEN)
            && (0 != szVal[0]);

        ZY_Trace("build: " CUR_VER "," __DATE__);

        SIZE_T nMinorVersion = 0;
        SIZE_T nBuildNumber = 0;
        SIZE_T nMajorVersion = ZY_GetSysVersion(&nMinorVersion, &nBuildNumber);
        ZY_Trace("windows version: %zu.%zu.%zu", nMajorVersion, nMinorVersion, nBuildNumber);

        const char* szDlls[] = {
            "mimalloc.dll",
            "mimalloc-override.dll",
            "mimalloc-secure.dll",
            "mimalloc-secure-debug.dll",
            "mimalloc-debug.dll",
            "mimalloc-release.dll",
            0,
        };

        void* handle = ZY_ResolveProcess(hModule, g_szFuncCtxs, szDlls, bForceRedirect,
            bHasPatchNTHeap ? g_szNTHeapFuncCtxs : nullptr,
            bHasPatchNTHeap ? szVal : nullptr);
        if (handle)
        {
            reinterpret_cast<void*&>(g_redirect_entry) = ZY_GetFuncAddress(handle, "_mi_redirect_entry");
            if (g_redirect_entry && bLoadOrderOn)
                ZY_PrioritizeLoadOrder(hModule);
            g_redirectContexts[0] = g_szFuncCtxs;
            if (bHasPatchNTHeap)
                g_redirectContexts[1] = g_szNTHeapFuncCtxs;

            int nRet = ZY_RedirectFunction6(1, g_redirectContexts);
            if (0 == nRet || bForceRedirect)
            {
                if (bForceRedirect)
                    ZY_Warning("there were errors during patching but these are ignored (due to MIMALLOC_FORCE_REDIRECT=1).");
                g_bRedirected = true;
            }
            else if (nRet == 2)
            {
                ZY_Warning("redirection failed with partially applied patches -- aborting dll loading.");
                bR = false;
            }
            else
            {
                ZY_Warning("redirection patching failed");
            }
        }
    }

    if (g_bRedirected)
        ZY_Trace("standard malloc is redirected " CUR_VER "," __DATE__ ", x64");
    else
        ZY_Warning("standard malloc is _not_ redirected! -- using regular malloc/free. (" CUR_VER ")");

    return bR;
}

void ProcessTlsEntry()
{
    if (g_tlsEntry)
        return;
    reinterpret_cast<ULONG_PTR&>(g_tlsEntry) = 1;

    PVOID* pCallbacks = ZY_GetTlsCallBacks();
    if (!pCallbacks)
    {
        ZY_Error("unable to find tls entries");
        return;
    }

    PVOID* pEntry = nullptr;
    for (PVOID* pIter = pCallbacks; *pIter; ++pIter)
        pEntry = pIter;

    if (!pEntry || !*pEntry)
    {
        ZY_Error("tls entries are empty");
        return;
    }

    if (!ZY_WriteCode3(pEntry, reinterpret_cast<ULONG_PTR>(&ZY_TlsEntryOverride), reinterpret_cast<ULONG_PTR*>(&g_tlsEntry)))
    {
        ZY_Error("unable to patch tls entry (%p); unable to get write permission", pEntry);
        return;
    }
}

BOOL APIENTRY _DllMainCRTStartup( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    BOOL bRet = TRUE;
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
        bRet = ProcessRedirect(hModule);

    if (g_bRedirected && g_redirect_entry)
    {
        if (ul_reason_for_call == DLL_THREAD_ATTACH)
            ProcessTlsEntry();
        if (ul_reason_for_call != DLL_THREAD_DETACH || !ZY_IsTlsEntryPatched())
            g_redirect_entry(ul_reason_for_call);
    }

    return bRet;
}

