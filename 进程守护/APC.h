//#pragma once
//
//#include"function.h"
//#include"PEStructs.h"
//#include<ntifs.h>
//#define CALL_COMPLETE   0xC0371E7E
//
//#define BB_POOL_TAG 'enoB'
//
//typedef struct _INJECT_BUFFER
//{
//    UCHAR code[0x200];
//    union
//    {
//        UNICODE_STRING path;
//        UNICODE_STRING32 path32;
//    };
//
//    wchar_t buffer[488];
//    PVOID module;
//    ULONG complete;
//    NTSTATUS status;
//} INJECT_BUFFER, * PINJECT_BUFFER;
//
//
//
//
//typedef struct _SYSTEM_THREAD_INFORMATION
//{
//    LARGE_INTEGER KernelTime;
//    LARGE_INTEGER UserTime;
//    LARGE_INTEGER CreateTime;
//    ULONG WaitTime;
//    PVOID StartAddress;
//    CLIENT_ID ClientId;
//    KPRIORITY Priority;
//    LONG BasePriority;
//    ULONG ContextSwitches;
//    ULONG ThreadState;
//    KWAIT_REASON WaitReason;
//}SYSTEM_THREAD_INFORMATION, * PSYSTEM_THREAD_INFORMATION;
//
//
//typedef struct _SYSTEM_PROCESS_INFO
//{
//    ULONG NextEntryOffset;
//    ULONG NumberOfThreads;
//    LARGE_INTEGER WorkingSetPrivateSize;
//    ULONG HardFaultCount;
//    ULONG NumberOfThreadsHighWatermark;
//    ULONGLONG CycleTime;
//    LARGE_INTEGER CreateTime;
//    LARGE_INTEGER UserTime;
//    LARGE_INTEGER KernelTime;
//    UNICODE_STRING ImageName;
//    KPRIORITY BasePriority;
//    HANDLE UniqueProcessId;
//    HANDLE InheritedFromUniqueProcessId;
//    ULONG HandleCount;
//    ULONG SessionId;
//    ULONG_PTR UniqueProcessKey;
//    SIZE_T PeakVirtualSize;
//    SIZE_T VirtualSize;
//    ULONG PageFaultCount;
//    SIZE_T PeakWorkingSetSize;
//    SIZE_T WorkingSetSize;
//    SIZE_T QuotaPeakPagedPoolUsage;
//    SIZE_T QuotaPagedPoolUsage;
//    SIZE_T QuotaPeakNonPagedPoolUsage;
//    SIZE_T QuotaNonPagedPoolUsage;
//    SIZE_T PagefileUsage;
//    SIZE_T PeakPagefileUsage;
//    SIZE_T PrivatePageCount;
//    LARGE_INTEGER ReadOperationCount;
//    LARGE_INTEGER WriteOperationCount;
//    LARGE_INTEGER OtherOperationCount;
//    LARGE_INTEGER ReadTransferCount;
//    LARGE_INTEGER WriteTransferCount;
//    LARGE_INTEGER OtherTransferCount;
//    SYSTEM_THREAD_INFORMATION Threads[1];
//}SYSTEM_PROCESS_INFO, * PSYSTEM_PROCESS_INFO;
//
//
////

//
//
//// Image name resolve flags
//typedef enum _ResolveFlags
//{
//    KApiShemaOnly = 1,
//    KSkipSxS = 2,
//    KFullPath = 4,
//} ResolveFlags;
//
//
///// <summary>
///// User-mode memory region
///// </summary>
//typedef struct _USER_CONTEXT
//{
//    UCHAR code[0x1000];             // Code buffer
//    union
//    {
//        UNICODE_STRING ustr;
//        UNICODE_STRING32 ustr32;
//    };
//    wchar_t buffer[0x400];          // Buffer for unicode string
//
//
//    // Activation context data
//    union
//    {
//        ACTCTXW actx;
//        ACTCTXW32 actx32;
//    };
//    HANDLE hCTX;
//    ULONG hCookie;
//
//    PVOID ptr;                      // Tmp data
//    union
//    {
//        NTSTATUS status;            // Last execution status
//        PVOID retVal;               // Function return value
//        ULONG retVal32;             // Function return value
//    };
//
//    //UCHAR tlsBuf[0x100];
//} USER_CONTEXT, * PUSER_CONTEXT;
//
///// <summary>
///// Manual map context
///// </summary>
//typedef struct _MMAP_CONTEXT
//{
//    PEPROCESS pProcess;     // Target process
//    PVOID pWorkerBuf;       // Worker thread code buffer
//    HANDLE hWorker;         // Worker thread handle
//    PETHREAD pWorker;       // Worker thread object
//    LIST_ENTRY modules;     // Manual module list
//    PUSER_CONTEXT userMem;  // Tmp buffer in user space
//    HANDLE hSync;           // APC sync handle
//    PKEVENT pSync;          // APC sync object
//    PVOID pSetEvent;        // ZwSetEvent address
//    PVOID pLoadImage;       // LdrLoadDll address
//    BOOLEAN tlsInitialized; // Static TLS was initialized
//} MMAP_CONTEXT, * PMMAP_CONTEXT;
//
//
////APC×¢Èë
//NTSTATUS BBInjectDll(IN PINJECT_DLL pData);
//PVOID BBGetUserModule(IN PEPROCESS pProcess, IN PUNICODE_STRING ModuleName, IN BOOLEAN isWow64);
//PINJECT_BUFFER BBGetWow64Code(IN PVOID LdrLoadDll, IN PUNICODE_STRING pPath);
//NTSTATUS BBApcInject(IN PINJECT_BUFFER pUserBuf, IN PEPROCESS pProcess, IN ULONG initRVA, IN PCWCHAR InitArg);
//PVOID BBGetModuleExport(IN PVOID pBase, IN PCCHAR name_ord, IN PEPROCESS pProcess, IN PUNICODE_STRING baseName);
//
//NTSTATUS BBResolveImagePath(
//    IN PMMAP_CONTEXT pContext,
//    IN PEPROCESS pProcess,
//    IN ResolveFlags flags,
//    IN PUNICODE_STRING path,
//    IN PUNICODE_STRING baseImage,
//    OUT PUNICODE_STRING resolved
//);