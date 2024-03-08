#pragma once
#include<ntifs.h>
#include"NativeStructs10.h"
#include"VadHelpers.h"
#include"NativeEnums.h"
#define kmalloc(_s)    ExAllocatePoolWithTag(NonPagedPool, _s, 'SYSQ')
#define kfree(_p)    ExFreePool(_p)

#define EX_ADDITIONAL_INFO_SIGNATURE (ULONG_PTR)(-2)

#define ASSERT( exp ) \
    ((!(exp)) ? \
        (RtlAssert( (PVOID)#exp, (PVOID)__FILE__, __LINE__, NULL ),FALSE) : \
        TRUE)
#define ExpIsValidObjectEntry(Entry) \
    ( (Entry != NULL) && (Entry->LowValue != 0) && (Entry->HighValue != EX_ADDITIONAL_INFO_SIGNATURE) )


#define HANDLE_VALUE_INC 4

#define TABLE_PAGE_SIZE	PAGE_SIZE
#define LOWLEVEL_COUNT (TABLE_PAGE_SIZE / sizeof(HANDLE_TABLE_ENTRY))
#define MIDLEVEL_COUNT (PAGE_SIZE / sizeof(PHANDLE_TABLE_ENTRY))

#define LEVEL_CODE_MASK 3


typedef struct _KAPC_STATE_t
{
    LIST_ENTRY ApcListHead[2];
    PKPROCESS Process;
    UCHAR KernelApcInProgress;
    UCHAR KernelApcPending;
    UCHAR UserApcPending;
} KAPC_STATE_t, * PKAPC_STATE_t;


typedef struct __LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY64    InLoadOrderLinks;
    LIST_ENTRY64    InMemoryOrderLinks;
    LIST_ENTRY64    InInitializationOrderLinks;
    PVOID            DllBase;
    PVOID            EntryPoint;
    ULONG            SizeOfImage;
    UNICODE_STRING    FullDllName;
    UNICODE_STRING     BaseDllName;
    ULONG            Flags;
    USHORT            LoadCount;
    USHORT            TlsIndex;
    PVOID            SectionPointer;
    ULONG            CheckSum;
    PVOID            LoadedImports;
    PVOID            EntryPointActivationContext;
    PVOID            PatchInformation;
    LIST_ENTRY64    ForwarderLinks;
    LIST_ENTRY64    ServiceTagLinks;
    LIST_ENTRY64    StaticLinks;
    PVOID            ContextInformation;
    ULONG64            OriginalBase;
    LARGE_INTEGER    LoadTime;
} LDR_DATA__TABLE_ENTRY, * PLDR_DATA__TABLE_ENTRY;


typedef struct _SYSTEM_MODULE_INFORMATION_ENTRY
{
    ULONG Unknow1;
    ULONG Unknow2;
    ULONG Unknow3;
    ULONG Unknow4;
    PVOID Base;
    ULONG Size;
    ULONG Flags;
    USHORT Index;
    USHORT NameLength;
    USHORT LoadCount;
    USHORT ModuleNameOffset;
    char ImageName[256];
} SYSTEM_MODULE_INFORMATION_ENTRY, * PSYSTEM_MODULE_INFORMATION_ENTRY;

//读写内存结构体
typedef struct _COPY_MEMORY
{
    PVOID64 localbuf;         // Buffer address
    PVOID64 targetPtr;        // Target address
    ULONGLONG size;             // Buffer size
    ULONG     pid;              // Target process id
    BOOLEAN   write;            // TRUE if write operation, FALSE if read
} COPY_MEMORY, * PCOPY_MEMORY;

//获取进程模块基地址结构体
typedef struct _GET_PROCESSMODE
{
    ULONGLONG localbuf;
    ULONGLONG size;
    ULONG     pid;             
    wchar_t   name[512];
} GET_PROCESSMODE, * PGET_PROCESSMODE;

typedef struct _SYSTEM_MODULE_INFORMATION
{
    ULONG Count;//内核中以加载的模块的个数
    SYSTEM_MODULE_INFORMATION_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;


typedef enum _WinVer
{
    WINVER_7 = 0x0610,
    WINVER_7_SP1 = 0x0611,
    WINVER_8 = 0x0620,
    WINVER_81 = 0x0630,
    WINVER_10 = 0x0A00,
    WINVER_10_RS1 = 0x0A01, // Anniversary update
    WINVER_10_RS2 = 0x0A02, // Creators update
    WINVER_10_RS3 = 0x0A03, // Fall creators update
    WINVER_10_RS4 = 0x0A04, // Spring creators update
    WINVER_10_19H1 = 0x0A06, // May 2019 update 19H1
    WINVER_10_19H2 = 0x0A07, // November 2019 update 19H2
    WINVER_10_20H1 = 0x0A08, // April 2020 update 20H1
    WINVER_10_20H2 = 0x0A09,
} WinVer;

typedef struct _DYNAMIC_DATA
{
    WinVer  ver;
    ULONG   buildNo;        // OS build revision
    ULONG_PTR ActiveOffsetNext;
    ULONG_PTR  ActiveOffsetPre;
    ULONG_PTR  ImageName;
    ULONG_PTR  peboffseteprocess;
    ULONG_PTR ldroffsetpeb;
    ULONG_PTR InLoadOrderModuleList_offset;
    ULONG_PTR ObjectTable;
    ULONG_PTR   UniqueProcessId;
    ULONG_PTR   VadRoot;  ///-----

    ULONG_PTR  DYN_PDE_BASE;
    ULONG_PTR  DYN_PTE_BASE;
    ULONG_PTR  NtProtectIndex;
    ULONG_PTR  PrevMode;///-----
} DYNAMIC_DATA, * PDYNAMIC_DATA;



typedef struct _ALLOCATE_FREE_MEMORY_RESULT
{
    ULONGLONG address;          // Address of allocation
    ULONGLONG size;             // Allocated size
} ALLOCATE_FREE_MEMORY_RESULT, * PALLOCATE_FREE_MEMORY_RESULT;


typedef struct _HANDLE_GRANT_ACCESS
{
    ULONGLONG  handle;      // Handle to modify
    ULONG      pid;         // Process ID
    ULONG      access;      // Access flags to grant
} HANDLE_GRANT_ACCESS, * PHANDLE_GRANT_ACCESS;

typedef struct _HANDLE_Right_ACCESS
{
    ULONG      localtpid;      // 自己PID
    ULONG      targetpid;         // 目标PID
    ULONG      access;      // Access flags to grant
} HANDLE_Right_ACCESS, * PHANDLE_Right_ACCESS;




typedef enum _InjectType
{
    IT_Thread,      // CreateThread into LdrLoadDll
    IT_Apc,         // Force user APC into LdrLoadDll
    IT_MMap,        // Manual map
} InjectType;

typedef enum _MmapFlags
{
    KNoFlags = 0x00,    // No flags
    KManualImports = 0x01,    // Manually map import libraries
    KWipeHeader = 0x04,    // Wipe image PE headers
    KHideVAD = 0x10,    // Make image appear as PAGE_NOACESS region
    KRebaseProcess = 0x40,    // If target image is an .exe file, process base address will be replaced with mapped module value

    KNoExceptions = 0x01000, // Do not create custom exception handler
    KNoSxS = 0x08000, // Do not apply SxS activation context
    KNoTLS = 0x10000, // Skip TLS initialization and don't execute TLS callbacks
} KMmapFlags;

typedef struct _INJECT_DLL
{
    InjectType type;                // Type of injection 注入类型
    wchar_t    FullDllPath[512];    // Fully-qualified path to the target dll 目标dll的完全限定路径
    wchar_t    initArg[512];        // Init routine argument  Init程序参数
    ULONG      initRVA;             // Init routine RVA, if 0 - no init routine Init例程RVA，如果0 -没有Init例程
    ULONG      pid;                 // Target process ID  目标进程ID
    BOOLEAN    wait;                // Wait on injection thread  等待注入线程
    BOOLEAN    unlink;              // Unlink module after injection  模块注入后断开连接
    BOOLEAN    erasePE;             // Erase PE headers after injection    在注入后擦除PE头
    KMmapFlags flags;               // Manual map flags 手动映射旗帜
    ULONGLONG  imageBase;           // Image address in memory to manually map 图像地址在内存中手动映射
    ULONG      imageSize;           // Size of memory image 存储映像大小
    BOOLEAN    asImage;             // Memory chunk has image layout  内存块具有图像布局
} INJECT_DLL, * PINJECT_DLL;


typedef union _EXHANDLE
{
    struct
    {
        int TagBits : 2;
        int Index : 30;
    } u;
    void* GenericHandleOverlay;
    ULONG_PTR Value;

} EXHANDLE, * PEXHANDLE;


typedef struct _HANDLE_TABLE_ENTRY // Size=16
{
    union
    {
        ULONG_PTR VolatileLowValue; // Size=8 Offset=0
        ULONG_PTR LowValue; // Size=8 Offset=0
        struct _HANDLE_TABLE_ENTRY_INFO* InfoTable; // Size=8 Offset=0
        struct
        {
            ULONG_PTR Unlocked : 1; // Size=8 Offset=0 BitOffset=0 BitCount=1
            ULONG_PTR RefCnt : 16; // Size=8 Offset=0 BitOffset=1 BitCount=16
            ULONG_PTR Attributes : 3; // Size=8 Offset=0 BitOffset=17 BitCount=3
            ULONG_PTR ObjectPointerBits : 44; // Size=8 Offset=0 BitOffset=20 BitCount=44
        };
    };
    union
    {
        ULONG_PTR HighValue; // Size=8 Offset=8
        struct _HANDLE_TABLE_ENTRY* NextFreeHandleEntry; // Size=8 Offset=8
        union _EXHANDLE LeafHandleValue; // Size=8 Offset=8
        struct
        {
            ULONG GrantedAccessBits : 25; // Size=4 Offset=8 BitOffset=0 BitCount=25
            ULONG NoRightsUpgrade : 1; // Size=4 Offset=8 BitOffset=25 BitCount=1
            ULONG Spare : 6; // Size=4 Offset=8 BitOffset=26 BitCount=6
        };
    };
    ULONG TypeInfo; // Size=4 Offset=12
} HANDLE_TABLE_ENTRY, * PHANDLE_TABLE_ENTRY;



/// <summary>
/// Input for IOCTL_BLACKBONE_ALLOCATE_FREE_MEMORY
/// </summary>
typedef struct _ALLOCATE_FREE_MEMORY
{
    ULONGLONG base;             // Region base address
    ULONGLONG size;             // Region size
    ULONG     pid;              // Target process id
    ULONG     protection;       // Memory protection for allocation  内存分配保护
    ULONG     type;             // MEM_RESERVE/MEM_COMMIT/MEM_DECOMMIT/MEM_RELEASE
    BOOLEAN   allocate;         // TRUE if allocation, FALSE is freeing
    BOOLEAN   physical;         // If set to TRUE, physical pages will be directly mapped into UM space
} ALLOCATE_FREE_MEMORY, * PALLOCATE_FREE_MEMORY;


typedef enum _MI_VAD_TYPE
{
    VadNone,
    VadDevicePhysicalMemory,
    VadImageMap,
    VadAwe,
    VadWriteWatch,
    VadLargePages,
    VadRotatePhysical,
    VadLargePageSection
} MI_VAD_TYPE, * PMI_VAD_TYPE;



typedef struct _PROTECT_MEMORY
{
    ULONGLONG base;             // Region base address
    ULONGLONG size;             // Region size
    ULONG     pid;              // Target process id
    ULONG     newProtection;    // New protection value
} PROTECT_MEMORY, * PPROTECT_MEMORY;



#pragma warning(disable : 4214)
typedef struct _MMPTE_HARDWARE64
{
    ULONGLONG Valid : 1;
    ULONGLONG Dirty1 : 1;
    ULONGLONG Owner : 1;
    ULONGLONG WriteThrough : 1;
    ULONGLONG CacheDisable : 1;
    ULONGLONG Accessed : 1;
    ULONGLONG Dirty : 1;
    ULONGLONG LargePage : 1;
    ULONGLONG Global : 1;
    ULONGLONG CopyOnWrite : 1;
    ULONGLONG Unused : 1;
    ULONGLONG Write : 1;
    ULONGLONG PageFrameNumber : 36;
    ULONGLONG reserved1 : 4;
    ULONGLONG SoftwareWsIndex : 11;
    ULONGLONG NoExecute : 1;
} MMPTE_HARDWARE64, * PMMPTE_HARDWARE64;

typedef struct _MMPTE
{
    union
    {
        ULONG_PTR Long;
        MMPTE_HARDWARE64 Hard;
    } u;
} MMPTE;
typedef MMPTE* PMMPTE;







typedef BOOLEAN(*EX_ENUMERATE_HANDLE_ROUTINE)(
    IN PHANDLE_TABLE_ENTRY HandleTableEntry,
    IN HANDLE Handle,
    IN PVOID EnumParameter
    );

/// 函数声明
NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation
(
    IN ULONG    SystemInformationClass,
    OUT PVOID    SystemInformation,
    IN ULONG    Length,
    OUT PULONG    ReturnLength
);

NTKERNELAPI
NTSTATUS
NTAPI
MmCopyVirtualMemory(
    IN PEPROCESS FromProcess,
    IN PVOID FromAddress,
    IN PEPROCESS ToProcess,
    OUT PVOID ToAddress,
    IN SIZE_T BufferSize,
    IN KPROCESSOR_MODE PreviousMode,
    OUT PSIZE_T NumberOfBytesCopied
);

NTKERNELAPI
BOOLEAN
ExEnumHandleTable(
    IN PHANDLE_TABLE HandleTable,
    IN EX_ENUMERATE_HANDLE_ROUTINE EnumHandleProcedure,
    IN PVOID EnumParameter,
    OUT PHANDLE Handle
);


NTKERNELAPI
VOID
FASTCALL
ExfUnblockPushLock(
    IN OUT PEX_PUSH_LOCK PushLock,
    IN OUT PVOID WaitBlock
);



//提权函数 测试


NTSTATUS BBGrantAccessTest(IN PHANDLE_Right_ACCESS pAccess);

NTKERNELAPI POBJECT_TYPE ObGetObjectType(PVOID Object);



extern DYNAMIC_DATA dynData;

//获取进程模块地
NTSTATUS Process_module_traversal(IN PGET_PROCESSMODE in, OUT PALLOCATE_FREE_MEMORY_RESULT pResult);
NTSTATUS BBGetUserModule(IN PGET_PROCESSMODE in, OUT PALLOCATE_FREE_MEMORY_RESULT pResult);
//驱动扫描
VOID DriverSec(PDRIVER_OBJECT  pDriverObject);

//获取驱动模块地址
ULONG64 GetSystemModuleBase(char* lpModuleName);

//修改磁盘序列号
void SpoofHDD();
//驱动断链
VOID HideDriver(char* pDrvName, PDRIVER_OBJECT  pDriverObject);


//进程隐藏  会pg
VOID HideProcess(char* ProcessName);

//读写内存
NTSTATUS BBCopyMemory(IN PCOPY_MEMORY pCopy);

//获取系统版本
NTSTATUS BBInitDynamicData(PDYNAMIC_DATA pData);


//提权
NTSTATUS BBGrantAccess(IN PHANDLE_GRANT_ACCESS pAccess);


//分配内存
NTSTATUS BBAllocateFreeMemory(IN PALLOCATE_FREE_MEMORY pAllocFree, OUT PALLOCATE_FREE_MEMORY_RESULT pResult);

//修改权限
NTSTATUS BBProtectMemory(IN PPROTECT_MEMORY pProtect);


NTSYSAPI ULONG RtlRandomEx(
    PULONG Seed
);


