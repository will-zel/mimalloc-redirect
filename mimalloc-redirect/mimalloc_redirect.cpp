//////////////////////////////////////////////////////////////////////////
//for research and learning only
//////////////////////////////////////////////////////////////////////////

#include "pch.h"
#include "mimalloc_redirect.h"
#include "stdcpp_override.h"
#include "InternalFunc.h"

RtlSizeHeapFunc* g_safe_RtlSizeHeap = nullptr;
RtlFreeHeapFunc* g_safe_RtlFreeHeap = nullptr;
RtlReAllocateHeapFunc* g_safe_RtlReAllocateHeap = nullptr;

RtlAllocateHeap* g_RtlAllocateHeap = nullptr;
RtlSizeHeapFunc* g_RtlSizeHeap = nullptr;
RtlFreeHeapFunc* g_RtlFreeHeap = nullptr;
RtlReAllocateHeapFunc* g_RtlReAllocateHeap = nullptr;

#pragma optimize("", off)
size_t return_this(size_t s)
{
	return s;
}

#define DEFINE_IND1() {return_this(return_this(1));return 0;}
#define DEFINE_IND2() {return_this(return_this(1));}
#define DEFINE_TERM1() {}

void* _mi_recalloc_ind(void* p, size_t newcount, size_t size)													DEFINE_IND1()
void* _mi_malloc_ind(size_t size)																				DEFINE_IND1()
void* _mi_calloc_ind(size_t count, size_t size)																	DEFINE_IND1()
void* _mi_realloc_ind(void* p, size_t newsize)																	DEFINE_IND1()
void  _mi_free_ind(void* p)																						DEFINE_IND2()
void* _mi_expand_ind(void* p, size_t newsize)																	DEFINE_IND1()
size_t _mi_usable_size_ind(const void* p)																		DEFINE_IND1()
void* _mi_new_nothrow_ind(size_t size)																			DEFINE_IND1()
bool _mi_is_in_heap_region_ind(const void* p)																	DEFINE_IND1()
void* _mi_malloc_aligned_ind(size_t size, size_t alignment)														DEFINE_IND1()
void* _mi_realloc_aligned_ind(void* p, size_t newsize, size_t alignment)										DEFINE_IND1()
void* _mi_aligned_recalloc_ind(void* p, size_t newcount, size_t size, size_t alignment)							DEFINE_IND1()
void* _mi_malloc_aligned_at_ind(size_t size, size_t alignment, size_t offset)									DEFINE_IND1()
void* _mi_realloc_aligned_at_ind(void* p, size_t newsize, size_t alignment, size_t offset)						DEFINE_IND1()
void* _mi_aligned_offset_recalloc_ind(void* p, size_t newcount, size_t size, size_t alignment, size_t offset)	DEFINE_IND1()

void* _mi_realloc_term(void* p, size_t newsize)
{
	MI_UNUSED(p);
	MI_UNUSED(newsize);
	return 0;
}

void _mi_free_term(void* p)
{
	if (p)
	{
		if (_mi_is_in_heap_region_ind(p))
			_mi_free_ind(p);
	}
}

void* _mi__expand_term(void* p, size_t newsize)
{
	MI_UNUSED(p);
	MI_UNUSED(newsize);
	return 0;
}

void* _mi__recalloc_term(void* p, size_t newcount, size_t size)
{
	MI_UNUSED(p);
	MI_UNUSED(newcount);
	MI_UNUSED(size);
	return 0;
}

size_t _mi__msize_term(const void* p)
{
	if (p && _mi_is_in_heap_region_ind(p))
		return _mi_usable_size_ind(p);
	return 0;
}

void* _mi__aligned_realloc_term(void* p, size_t newsize, size_t alignment)
{
	MI_UNUSED(p);
	MI_UNUSED(newsize);
	MI_UNUSED(alignment);
	return 0;
}

void* _mi__aligned_recalloc_term(void* p, size_t newcount, size_t size, size_t alignment)
{
	MI_UNUSED(p);
	MI_UNUSED(newcount);
	MI_UNUSED(size);
	MI_UNUSED(alignment);
	return 0;
}

void* _mi__aligned_offset_realloc_term(void* p, size_t newsize, size_t alignment, size_t offset)
{
	MI_UNUSED(p);
	MI_UNUSED(newsize);
	MI_UNUSED(alignment);
	MI_UNUSED(offset);
	return 0;
}

void* _mi__aligned_offset_recalloc_term(void* p, size_t newcount, size_t size, size_t alignment, size_t offset)
{
	MI_UNUSED(p);
	MI_UNUSED(newcount);
	MI_UNUSED(size);
	MI_UNUSED(alignment);
	MI_UNUSED(offset);
	return 0;
}

void* _mi__expand_base(void* p, size_t newsize)
{
	return _mi_expand_ind(p, newsize);
}

void* _mi__expand_base_term(void* p, size_t newsize)
{
	return _mi__expand_term(p, newsize);
}

void* _mi__recalloc_base(void* p, size_t newcount, size_t size)
{
	return _mi_recalloc_ind(p, newcount, size);
}

void* _mi__recalloc_base_term(void* p, size_t newcount, size_t size)
{
	return _mi__recalloc_term(p, newcount, size);
}

size_t _mi__msize_base(const void* p)
{
	return _mi_usable_size_ind(p);
}

size_t _mi__msize_base_term(const void* p)
{
	return _mi__msize_term(p);
}

size_t _mi__aligned_msize(void* _Block, size_t _Alignment, size_t _Offset)
{
	return _mi_usable_size_ind(_Block);
}

size_t _mi__aligned_msize_term(void* _Block, size_t _Alignment, size_t _Offset)
{
	return _mi__msize_term(_Block);
}

SIZE_T _mi_safe_RtlSizeHeap(HANDLE HeapPtr, ULONG Flags, PVOID Ptr)
{
    if (_mi_is_in_heap_region_ind(Ptr))
        return _mi_usable_size_ind(Ptr);
    if (g_safe_RtlSizeHeap)
        return g_safe_RtlSizeHeap(HeapPtr, Flags, Ptr);
    return 0i64;
}

BOOLEAN _mi_safe_RtlFreeHeap(PVOID HeapHandle, ULONG Flags, PVOID HeapBase)
{
    if (!HeapBase)
        return true;

    if (_mi_is_in_heap_region_ind(HeapBase))
    {
        _mi_free_ind(HeapBase);
        return true;
    }

    if (g_safe_RtlFreeHeap)
        return g_safe_RtlFreeHeap(HeapHandle, Flags, HeapBase);

    return false;
}

PVOID _mi_safe_RtlReAllocateHeap(PVOID HeapHandle, ULONG Flags, PVOID BaseAddress, SIZE_T Size)
{
    if (BaseAddress && _mi_is_in_heap_region_ind(BaseAddress))
    {
        if (Flags & 0x10)
        {
            void* P = _mi_expand_ind(BaseAddress, Size);
            if (P && (Flags & 8))
            {
                SIZE_T S = _mi_usable_size_ind(P);
                if (S < Size)
                    ZY_Memset(reinterpret_cast<BYTE*>(P) + Size, 0, Size - S);
            }
            return P;
        }

        if (Flags & 8)
        {
            return _mi_recalloc_ind(BaseAddress, Size, 1);
        }

        return _mi_realloc_ind(BaseAddress, Size);
    }

    if (g_safe_RtlReAllocateHeap)
        return g_safe_RtlReAllocateHeap(HeapHandle, Flags, BaseAddress, Size);

    return nullptr;
}

void* _mi_RtlAllocateHeap(PVOID HeapHandle, ULONG Flags, SIZE_T Size)
{
    if (ZY_IsGlobalProcessHeaps(HeapHandle))
    {
        if ((Flags & 8))
            return _mi_calloc_ind(Size, 1);
        else
            return _mi_malloc_ind(Size);
    }
    else if (g_RtlAllocateHeap)
    {
        return g_RtlAllocateHeap(HeapHandle, Flags, Size);
    }
    else
    {
        return nullptr;
    }
}

SIZE_T _mi_RtlSizeHeap(HANDLE HeapPtr, ULONG Flags, PVOID Ptr)
{
	if (ZY_IsGlobalProcessHeaps(HeapPtr)
		&& _mi_is_in_heap_region_ind(Ptr))
		return _mi_usable_size_ind(Ptr);
    if (g_RtlSizeHeap)
        return g_RtlSizeHeap(HeapPtr, Flags, Ptr);
    return 0;
}

BOOLEAN _mi_RtlFreeHeap(PVOID HeapHandle, ULONG Flags, PVOID HeapBase)
{
    if (!HeapBase)
        return true;

    if (ZY_IsGlobalProcessHeaps(HeapHandle))
    {
        _mi_free_ind(HeapBase);
        return true;
    }
    else if (g_RtlFreeHeap)
    {
        return g_RtlFreeHeap(HeapHandle, Flags, HeapBase);
    }
    else
    {
        return 0;
    }
}

PVOID NTAPI _mi_RtlReAllocateHeap(PVOID HeapHandle, ULONG Flags, PVOID BaseAddress, SIZE_T Size)
{
    if (!BaseAddress)
        return _mi_RtlAllocateHeap(HeapHandle, Flags, Size);

    if (ZY_IsGlobalProcessHeaps(HeapHandle)
		&& _mi_is_in_heap_region_ind(BaseAddress))
    {
        if (Flags & 0x10)
        {
            PVOID addr = _mi_expand_ind(BaseAddress, Size);
            if (addr && (Flags & 8))
            {
                SIZE_T size = _mi_usable_size_ind(BaseAddress);
                if (size < Size)
                    ZY_Memset(reinterpret_cast<char*>(addr) + Size, 0, Size - size);
            }
            return addr;
        }
        else if (Flags & 8)
        {
            return _mi_recalloc_ind(BaseAddress, Size, 1);
        }
        else
        {
            return _mi_realloc_ind(BaseAddress, Size);
        }
    }
    else if (g_RtlReAllocateHeap)
    {
        return g_RtlReAllocateHeap(HeapHandle, Flags, BaseAddress, Size);
    }
    else
    {
        return 0;
    }
}

void* _mi__malloc_dbg(size_t _Size, int _BlockUse, char const* _FileName, int _LineNumber)
{
	MI_UNUSED(_FileName);
	MI_UNUSED(_LineNumber);
	MI_UNUSED(_BlockUse);
	return _mi_malloc_ind(_Size);
}

void* _mi__realloc_dbg(void* _Block, size_t _Size, int _BlockUse, char const* _FileName, int _LineNumber)
{
	MI_UNUSED(_FileName);
	MI_UNUSED(_LineNumber);
	MI_UNUSED(_BlockUse);
	return _mi_realloc_ind(_Block, _Size);
}

void* _mi__calloc_dbg(size_t _Count, size_t _Size, int _BlockUse, char const* _FileName, int _LineNumber)
{
	MI_UNUSED(_FileName);
	MI_UNUSED(_LineNumber);
	MI_UNUSED(_BlockUse);
	return _mi_calloc_ind(_Count, _Size);
}

void _mi__free_dbg(void* _Block, int _BlockUse)
{
	MI_UNUSED(_BlockUse);
	_mi_free_ind(_Block);
}

void* _mi__expand_dbg(void* _Block, size_t _Size, int _BlockUse, char const* _FileName, int _LineNumber)
{
	MI_UNUSED(_FileName);
	MI_UNUSED(_LineNumber);
	MI_UNUSED(_BlockUse);
	return _mi_expand_ind(_Block, _Size);
}

void* _mi__expand_dbg_term(void* _Block, size_t _Size, int _BlockUse, char const* _FileName, int _LineNumber)
{
	MI_UNUSED(_FileName);
	MI_UNUSED(_LineNumber);
	MI_UNUSED(_BlockUse);
	return _mi__expand_term(_Block, _Size);
}

void* _mi__recalloc_dbg(void* _Block, size_t _Count, size_t _Size, int _BlockUse, char const* _FileName, int _LineNumber)
{
	MI_UNUSED(_FileName);
	MI_UNUSED(_LineNumber);
	MI_UNUSED(_BlockUse);
	return _mi_recalloc_ind(_Block, _Count, _Size);
}

void* _mi__recalloc_dbg_term(void* _Block, size_t _Count, size_t _Size, int _BlockUse, char const* _FileName, int _LineNumber)
{
	MI_UNUSED(_FileName);
	MI_UNUSED(_LineNumber);
	MI_UNUSED(_BlockUse);
	return _mi__recalloc_term(_Block, _Count, _Size);
}

size_t _mi__msize_dbg(void* _Block, int _BlockUse)
{
	MI_UNUSED(_BlockUse);
	return _mi_usable_size_ind(_Block);
}

size_t _mi__msize_dbg_term(void* _Block, int _BlockUse)
{
	MI_UNUSED(_BlockUse);
	return _mi__msize_term(_Block);
}

void* _mi__aligned_malloc_dbg(size_t _Size, size_t _Alignment, char const* _FileName, int _LineNumber)
{
	MI_UNUSED(_FileName);
	MI_UNUSED(_LineNumber);
	return _mi_malloc_aligned_ind(_Size, _Alignment);
}

void* _mi__aligned_realloc_dbg(void* _Block, size_t _Size, size_t _Alignment, char const* _FileName, int _LineNumber)
{
	MI_UNUSED(_FileName);
	MI_UNUSED(_LineNumber);
	return _mi_realloc_aligned_ind(_Block, _Size, _Alignment);
}

void* _mi__aligned_realloc_dbg_term(void* _Block, size_t _Size, size_t _Alignment, char const* _FileName, int _LineNumber)
{
	MI_UNUSED(_Block);
	MI_UNUSED(_Size);
	MI_UNUSED(_Alignment);
	MI_UNUSED(_FileName);
	MI_UNUSED(_LineNumber);
	return nullptr;
}

void* _mi__aligned_recalloc_dbg(void* _Block, size_t _Count, size_t _Size, size_t _Alignment, char const* _FileName, int _LineNumber)
{
	MI_UNUSED(_FileName);
	MI_UNUSED(_LineNumber);
	return _mi_aligned_recalloc_ind(_Block, _Count, _Size, _Alignment);
}

void* _mi__aligned_recalloc_dbg_term(void* _Block, size_t _Count, size_t _Size, size_t _Alignment, char const* _FileName, int _LineNumber)
{
	MI_UNUSED(_Block);
	MI_UNUSED(_Count);
	MI_UNUSED(_Size);
	MI_UNUSED(_Alignment);
	MI_UNUSED(_FileName);
	MI_UNUSED(_LineNumber);
	return nullptr;
}

void* _mi__aligned_offset_malloc_dbg(size_t _Size, size_t _Alignment, size_t _Offset, char const* _FileName, int _LineNumber)
{
	MI_UNUSED(_FileName);
	MI_UNUSED(_LineNumber);
	return _mi_malloc_aligned_at_ind(_Size, _Alignment, _Offset);
}

void* _mi__aligned_offset_realloc_dbg(void* _Block, size_t _Size, size_t _Alignment, size_t _Offset, char const* _FileName, int _LineNumber)
{
	MI_UNUSED(_FileName);
	MI_UNUSED(_LineNumber);
	return _mi_realloc_aligned_at_ind(_Block, _Size, _Alignment, _Offset);
}

void* _mi__aligned_offset_realloc_dbg_term(void* _Block, size_t _Size, size_t _Alignment, size_t _Offset, char const* _FileName, int _LineNumber)
{
	MI_UNUSED(_Block);
	MI_UNUSED(_Size);
	MI_UNUSED(_Alignment);
	MI_UNUSED(_Offset);
	MI_UNUSED(_FileName);
	MI_UNUSED(_LineNumber);
	return nullptr;
}

void* _mi__aligned_offset_recalloc_dbg(void* _Block, size_t _Count, size_t _Size, size_t _Alignment, size_t _Offset, char const* _FileName, int _LineNumber)
{
	MI_UNUSED(_FileName);
	MI_UNUSED(_LineNumber);
	return _mi_aligned_offset_recalloc_ind(_Block, _Count, _Size, _Alignment, _Offset);
}

void* _mi__aligned_offset_recalloc_dbg_term(void* _Block, size_t _Count, size_t _Size, size_t _Alignment, size_t _Offset, char const* _FileName, int _LineNumber)
{
	MI_UNUSED(_Block);
	MI_UNUSED(_Count);
	MI_UNUSED(_Size);
	MI_UNUSED(_Alignment);
	MI_UNUSED(_Offset);
	MI_UNUSED(_FileName);
	MI_UNUSED(_LineNumber);
	return nullptr;
}

void mi_allocator_done()
{
	
}

bool mi_allocator_init(const char** message)
{
	if (message)
		*message = GetRedirectMessage();
	return g_bRedirected;
}

int mi_redirect_disable()
{
	return ZY_RedirectFunction6(0, g_redirectContexts);
}

bool mi_redirect_enable()
{
	return ZY_RedirectFunction6(1, g_redirectContexts) == 0;
}

bool mi_redirect_enable_term()
{
	return ZY_RedirectFunction6(2, g_redirectContexts) == 0;
}

#pragma optimize("", on)
