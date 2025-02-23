#pragma once

//////////////////////////////////////////////////////////////////////////
//for research and learning only
//////////////////////////////////////////////////////////////////////////

#define mi_decl_noinline              __declspec(noinline)
#define mi_cdecl                      __cdecl

#define MI_UNUSED(x) (void)(x)

#ifdef MIMALLOCREDIRECT_EXPORTS
#define mr_decl_export                __declspec(dllexport)
#else
#define mr_decl_export
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef PVOID(RtlAllocateHeap)(PVOID  HeapHandle, ULONG  Flags, SIZE_T Size);
typedef SIZE_T(NTAPI RtlSizeHeapFunc)(HANDLE, ULONG, PVOID);
typedef BOOLEAN(NTAPI RtlFreeHeapFunc)(PVOID, ULONG, PVOID);
typedef PVOID(NTAPI RtlReAllocateHeapFunc)(PVOID, ULONG, PVOID, SIZE_T);

extern RtlSizeHeapFunc* g_safe_RtlSizeHeap;
extern RtlFreeHeapFunc* g_safe_RtlFreeHeap;
extern RtlReAllocateHeapFunc* g_safe_RtlReAllocateHeap;

extern RtlAllocateHeap* g_RtlAllocateHeap;
extern RtlSizeHeapFunc* g_RtlSizeHeap;
extern RtlFreeHeapFunc* g_RtlFreeHeap;
extern RtlReAllocateHeapFunc* g_RtlReAllocateHeap;

mi_decl_noinline void* _mi_recalloc_ind(void* p, size_t newcount, size_t size);
mi_decl_noinline void* _mi_malloc_ind(size_t size);
mi_decl_noinline void* _mi_calloc_ind(size_t count, size_t size);
mi_decl_noinline void* _mi_realloc_ind(void* p, size_t newsize);
mi_decl_noinline void  _mi_free_ind(void* p);
mi_decl_noinline void* _mi_expand_ind(void* p, size_t newsize);
mi_decl_noinline size_t _mi_usable_size_ind(const void* p);
mi_decl_noinline void* _mi_new_nothrow_ind(size_t size);
mi_decl_noinline bool _mi_is_in_heap_region_ind(const void* p);
mi_decl_noinline void* _mi_malloc_aligned_ind(size_t size, size_t alignment);
mi_decl_noinline void* _mi_realloc_aligned_ind(void* p, size_t newsize, size_t alignment);
mi_decl_noinline void* _mi_aligned_recalloc_ind(void* p, size_t newcount, size_t size, size_t alignment);
mi_decl_noinline void* _mi_malloc_aligned_at_ind(size_t size, size_t alignment, size_t offset);
mi_decl_noinline void* _mi_realloc_aligned_at_ind(void* p, size_t newsize, size_t alignment, size_t offset);
mi_decl_noinline void* _mi_aligned_offset_recalloc_ind(void* p, size_t newcount, size_t size, size_t alignment, size_t offset);

mi_decl_noinline void* _mi_realloc_term(void* p, size_t newsize);
mi_decl_noinline void  _mi_free_term(void* p);
mi_decl_noinline void* _mi__expand_term(void* p, size_t newsize);
mi_decl_noinline void* _mi__recalloc_term(void* p, size_t newcount, size_t size);
mi_decl_noinline size_t _mi__msize_term(const void* p);
mi_decl_noinline void* _mi__aligned_realloc_term(void* p, size_t newsize, size_t alignment);
mi_decl_noinline void* _mi__aligned_recalloc_term(void* p, size_t newcount, size_t size, size_t alignment);
mi_decl_noinline void* _mi__aligned_offset_realloc_term(void* p, size_t newsize, size_t alignment, size_t offset);
mi_decl_noinline void* _mi__aligned_offset_recalloc_term(void* p, size_t newcount, size_t size, size_t alignment, size_t offset);

mi_decl_noinline void* _mi__expand_base(void* p, size_t newsize);
mi_decl_noinline void* _mi__expand_base_term(void* p, size_t newsize);
mi_decl_noinline void* _mi__recalloc_base(void* p, size_t newcount, size_t size);
mi_decl_noinline void* _mi__recalloc_base_term(void* p, size_t newcount, size_t size);
mi_decl_noinline size_t _mi__msize_base(const void* p);
mi_decl_noinline size_t _mi__msize_base_term(const void* p);
mi_decl_noinline size_t _mi__aligned_msize(void* _Block, size_t _Alignment, size_t _Offset);
mi_decl_noinline size_t _mi__aligned_msize_term(void* _Block, size_t _Alignment, size_t _Offset);

mi_decl_noinline SIZE_T NTAPI _mi_safe_RtlSizeHeap(HANDLE HeapPtr, ULONG Flags, PVOID Ptr);
mi_decl_noinline BOOLEAN NTAPI _mi_safe_RtlFreeHeap(PVOID HeapHandle, ULONG Flags, PVOID HeapBase);
mi_decl_noinline PVOID NTAPI _mi_safe_RtlReAllocateHeap(PVOID HeapHandle, ULONG Flags, PVOID BaseAddress, SIZE_T Size);

mi_decl_noinline void* _mi__malloc_dbg(size_t _Size, int _BlockUse, char const* _FileName, int _LineNumber);
mi_decl_noinline void* _mi__realloc_dbg(void* _Block, size_t _Size, int _BlockUse, char const* _FileName, int _LineNumber);
mi_decl_noinline void* _mi__calloc_dbg(size_t _Count, size_t _Size, int _BlockUse, char const* _FileName, int _LineNumber);
mi_decl_noinline void _mi__free_dbg(void* _Block, int _BlockUse);
mi_decl_noinline void* _mi__expand_dbg(void* _Block, size_t _Size, int _BlockUse, char const* _FileName, int _LineNumber);
mi_decl_noinline void* _mi__expand_dbg_term(void* _Block, size_t _Size, int _BlockUse, char const* _FileName, int _LineNumber);
mi_decl_noinline void* _mi__recalloc_dbg(void* _Block, size_t _Count, size_t _Size, int _BlockUse, char const* _FileName, int _LineNumber);
mi_decl_noinline void* _mi__recalloc_dbg_term(void* _Block, size_t _Count, size_t _Size, int _BlockUse, char const* _FileName, int _LineNumber);
mi_decl_noinline size_t _mi__msize_dbg(void* _Block, int _BlockUse);
mi_decl_noinline size_t _mi__msize_dbg_term(void* _Block, int _BlockUse);
mi_decl_noinline void* _mi__aligned_malloc_dbg(size_t _Size, size_t _Alignment, char const* _FileName, int _LineNumber);
mi_decl_noinline void* _mi__aligned_realloc_dbg(void* _Block, size_t _Size, size_t _Alignment, char const* _FileName, int _LineNumber);
mi_decl_noinline void* _mi__aligned_realloc_dbg_term(void* _Block, size_t _Size, size_t _Alignment, char const* _FileName, int _LineNumber);
mi_decl_noinline void* _mi__aligned_recalloc_dbg(void* _Block, size_t _Count, size_t _Size, size_t _Alignment, char const* _FileName, int _LineNumber);
mi_decl_noinline void* _mi__aligned_recalloc_dbg_term(void* _Block, size_t _Count, size_t _Size, size_t _Alignment, char const* _FileName, int _LineNumber);
mi_decl_noinline void* _mi__aligned_offset_malloc_dbg(size_t _Size, size_t _Alignment, size_t _Offset, char const* _FileName, int _LineNumber);
mi_decl_noinline void* _mi__aligned_offset_realloc_dbg(void* _Block, size_t _Size, size_t _Alignment, size_t _Offset, char const* _FileName, int _LineNumber);
mi_decl_noinline void* _mi__aligned_offset_realloc_dbg_term(void* _Block, size_t _Size, size_t _Alignment, size_t _Offset, char const* _FileName, int _LineNumber);
mi_decl_noinline void* _mi__aligned_offset_recalloc_dbg(void* _Block, size_t _Count, size_t _Size, size_t _Alignment, size_t _Offset, char const* _FileName, int _LineNumber);
mi_decl_noinline void* _mi__aligned_offset_recalloc_dbg_term(void* _Block, size_t _Count, size_t _Size, size_t _Alignment, size_t _Offset, char const* _FileName, int _LineNumber);

mi_decl_noinline void* _mi_RtlAllocateHeap(PVOID HeapHandle, ULONG  Flags, SIZE_T Size);
mi_decl_noinline SIZE_T NTAPI _mi_RtlSizeHeap(HANDLE HeapPtr, ULONG Flags, PVOID Ptr);
mi_decl_noinline BOOLEAN NTAPI _mi_RtlFreeHeap(PVOID HeapHandle, ULONG Flags, PVOID HeapBase);
mi_decl_noinline PVOID NTAPI _mi_RtlReAllocateHeap(PVOID HeapHandle, ULONG Flags, PVOID BaseAddress, SIZE_T Size);

mr_decl_export void mi_cdecl mi_allocator_done(void);
mr_decl_export bool mi_cdecl mi_allocator_init(const char** message);
mr_decl_export int mi_cdecl mi_redirect_disable();
mr_decl_export bool mi_cdecl mi_redirect_enable();
mr_decl_export bool mi_cdecl mi_redirect_enable_term();

#ifdef __cplusplus
}
#endif
