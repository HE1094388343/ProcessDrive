#include"function.h"
#include"Private.h"
#include"imports.h"
#include"NativeStructs.h"
#include<ntdef.h>
#include<ntstrsafe.h>

DYNAMIC_DATA dynData;
#define POOLTAG01 'ahIK'
#define MAX_HDDS 10
#define SERIAL_MAX_LENGTH 15

ULONG MmProtectToValue[32] =
{
	PAGE_NOACCESS,
	PAGE_READONLY,
	PAGE_EXECUTE,
	PAGE_EXECUTE_READ,
	PAGE_READWRITE,
	PAGE_WRITECOPY,
	PAGE_EXECUTE_READWRITE,
	PAGE_EXECUTE_WRITECOPY,
	PAGE_NOACCESS,
	PAGE_NOCACHE | PAGE_READONLY,
	PAGE_NOCACHE | PAGE_EXECUTE,
	PAGE_NOCACHE | PAGE_EXECUTE_READ,
	PAGE_NOCACHE | PAGE_READWRITE,
	PAGE_NOCACHE | PAGE_WRITECOPY,
	PAGE_NOCACHE | PAGE_EXECUTE_READWRITE,
	PAGE_NOCACHE | PAGE_EXECUTE_WRITECOPY,
	PAGE_NOACCESS,
	PAGE_GUARD | PAGE_READONLY,
	PAGE_GUARD | PAGE_EXECUTE,
	PAGE_GUARD | PAGE_EXECUTE_READ,
	PAGE_GUARD | PAGE_READWRITE,
	PAGE_GUARD | PAGE_WRITECOPY,
	PAGE_GUARD | PAGE_EXECUTE_READWRITE,
	PAGE_GUARD | PAGE_EXECUTE_WRITECOPY,
	PAGE_NOACCESS,
	PAGE_WRITECOMBINE | PAGE_READONLY,
	PAGE_WRITECOMBINE | PAGE_EXECUTE,
	PAGE_WRITECOMBINE | PAGE_EXECUTE_READ,
	PAGE_WRITECOMBINE | PAGE_READWRITE,
	PAGE_WRITECOMBINE | PAGE_WRITECOPY,
	PAGE_WRITECOMBINE | PAGE_EXECUTE_READWRITE,
	PAGE_WRITECOMBINE | PAGE_EXECUTE_WRITECOPY
};

PEPROCESS LookupProcess(HANDLE hPid)
{
	PEPROCESS eproc = NULL;
	if (NT_SUCCESS(PsLookupProcessByProcessId(hPid, &eproc)))//返回eprocess流程结构体
	{
		return eproc;
	}
	return NULL;
}





NTSTATUS BBFindVAD(IN PEPROCESS pProcess, IN ULONG_PTR address, OUT PMMVAD_SHORT* pResult)
{
	NTSTATUS status = STATUS_SUCCESS;
	ULONG_PTR vpnStart = address >> PAGE_SHIFT;

	ASSERT(pProcess != NULL && pResult != NULL);
	if (pProcess == NULL || pResult == NULL)
		return STATUS_INVALID_PARAMETER;

	if (dynData.VadRoot == 0)
	{
		DbgPrint("BlackBone: %s: Invalid VadRoot offset\n", __FUNCTION__);
		status = STATUS_INVALID_ADDRESS;
	}


	PMM_AVL_TABLE pTable = (PMM_AVL_TABLE)((PUCHAR)pProcess + dynData.VadRoot);
	PMM_AVL_NODE pNode = GET_VAD_ROOT(pTable);

	// Search VAD
	if (MiFindNodeOrParent(pTable, vpnStart, &pNode) == TableFoundNode)
	{
		*pResult = (PMMVAD_SHORT)pNode;
	}
	else
	{
		DbgPrint("BlackBone: %s: VAD entry for address 0x%p not found\n", __FUNCTION__, address);
		status = STATUS_NOT_FOUND;
	}

	return status;
}

NTSTATUS BBProtectVAD(IN PEPROCESS pProcess, IN ULONG_PTR address, IN ULONG prot)
{
	NTSTATUS status = STATUS_SUCCESS;
	PMMVAD_SHORT pVadShort = NULL;

	status = BBFindVAD(pProcess, address, &pVadShort);
	if (NT_SUCCESS(status))
		pVadShort->u.VadFlags.Protection = prot;

	return status;
}


PMMPTE GetPTEForVA(IN PVOID pAddress)
{
	if (dynData.ver >= WINVER_10_RS1)
	{
		// Check if large page
		PMMPTE pPDE = (PMMPTE)(((((ULONG_PTR)pAddress >> PDI_SHIFT) << PTE_SHIFT) & 0x3FFFFFF8ull) + dynData.DYN_PDE_BASE);
		if (pPDE->u.Hard.LargePage)
			return pPDE;

		return (PMMPTE)(((((ULONG_PTR)pAddress >> PTI_SHIFT) << PTE_SHIFT) & 0x7FFFFFFFF8ull) + dynData.DYN_PTE_BASE);
	}
	else
	{
		// Check if large page
		PMMPTE pPDE = MiGetPdeAddress(pAddress);
		if (pPDE->u.Hard.LargePage)
			return pPDE;

		return MiGetPteAddress(pAddress);
	}
}


NTSTATUS BBGetVadType(IN PEPROCESS pProcess, IN ULONG_PTR address, OUT PMI_VAD_TYPE pType)
{
	NTSTATUS status = STATUS_SUCCESS;
	PMMVAD_SHORT pVad = NULL;

	status = BBFindVAD(pProcess, address, &pVad);
	if (!NT_SUCCESS(status))
		return status;

	*pType = pVad->u.VadFlags.VadType;

	return status;
}

ULONG BBConvertProtection(IN ULONG prot, IN BOOLEAN fromPTE)
{
	if (fromPTE != FALSE)
	{
		// Sanity check
		if (prot < ARRAYSIZE(MmProtectToValue))
			return MmProtectToValue[prot];
	}
	else
	{
		for (int i = 0; i < ARRAYSIZE(MmProtectToValue); i++)
			if (MmProtectToValue[i] == prot)
				return i;
	}

	return 0;
}

//#define PAGE_EXECUTE_READ       0x20    
//#define PAGE_EXECUTE_READWRITE  0x40    
//
NTSTATUS BBProtectMemory(IN PPROTECT_MEMORY pProtect)
{
	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS pProcess = NULL;
	status = PsLookupProcessByProcessId((HANDLE)pProtect->pid, &pProcess);
	if (NT_SUCCESS(status))
	{
		KAPC_STATE apc;
	//	MI_VAD_TYPE vadType = VadNone;
		PVOID base = (PVOID)pProtect->base;
		SIZE_T size = (SIZE_T)pProtect->size;
		ULONG oldProt = 0;

		KeStackAttachProcess(pProcess, &apc);
		status = ZwProtectVirtualMemory(ZwCurrentProcess(), &base, &size, pProtect->newProtection, &oldProt);
		KeUnstackDetachProcess(&apc);
	}
	else
		DbgPrint("BlackBone: %s: PsLookupProcessByProcessId failed with status 0x%X\n", __FUNCTION__, status);

	if (pProcess)
		ObDereferenceObject(pProcess);

	return status;
}
//获取模块基地址
NTSTATUS BBGetUserModule(IN PGET_PROCESSMODE in, OUT PALLOCATE_FREE_MEMORY_RESULT pResult)
{
	pResult->address = NULL;
	pResult->size = NULL;
	KAPC_STATE_t  ks;
	PEPROCESS    Eprocess;
	UNICODE_STRING UnicodeString2;
	Eprocess = LookupProcess(in->pid);
	if (Eprocess == NULL)
	{
		DbgPrint("Eprocess 获取失败");
		return STATUS_SUCCESS;
	}

	__try {
		KeStackAttachProcess(Eprocess, &ks);
		RtlInitUnicodeString(&UnicodeString2, in->name);
		PPEB pPeb = PsGetProcessPeb(Eprocess);
		for (PLIST_ENTRY pListEntry = pPeb->Ldr->InLoadOrderModuleList.Flink;
			pListEntry != &pPeb->Ldr->InLoadOrderModuleList;
			pListEntry = pListEntry->Flink)
		{
			PLDR_DATA__TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA__TABLE_ENTRY, InLoadOrderLinks);
			if (RtlCompareUnicodeString(&pEntry->BaseDllName, &UnicodeString2, TRUE) == 0)
			{
				
				pResult->address = pEntry->DllBase;
				pResult->size = pEntry->SizeOfImage;
				KeUnstackDetachProcess(&ks);
				return STATUS_SUCCESS;
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		KeUnstackDetachProcess(&ks);
	}
	KeUnstackDetachProcess(&ks);
	return STATUS_SUCCESS;
}
//获取进程模块基地址32/64均可  // 遗弃
NTSTATUS Process_module_traversal(IN PGET_PROCESSMODE in, OUT PALLOCATE_FREE_MEMORY_RESULT pResult)//进程模块遍历
{
	
	KAPC_STATE_t  ks;
	NTSTATUS status = STATUS_SUCCESS;
	UNICODE_STRING UnicodeString2;

	PEPROCESS    Eprocess = LookupProcess(in->pid);
	if (Eprocess == NULL)
	{
		DbgPrint("Eprocess 获取失败");
		return STATUS_SUCCESS;
	}
	__try {
		KeStackAttachProcess(Eprocess, &ks);
		RtlInitUnicodeString(&UnicodeString2, in->name);
	
		ULONG64  peb = *(PULONG64)((ULONG64)Eprocess + dynData.peboffseteprocess);
		ULONG64 idr = *(PULONG64)(peb + dynData.ldroffsetpeb);
		PLIST_ENTRY  pListHead = (idr + dynData.InLoadOrderModuleList_offset);
		PLIST_ENTRY pMod = pListHead->Flink;
		while (pMod != pListHead)
		{
			if (RtlCompareUnicodeString(&(((PLDR_DATA__TABLE_ENTRY)pMod)->BaseDllName), &UnicodeString2, TRUE)==0)
			{
				pResult->address = (ULONGLONG)(((PLDR_DATA__TABLE_ENTRY)pMod)->DllBase);
				pResult->size =(((PLDR_DATA__TABLE_ENTRY)pMod)->SizeOfImage);
				break;
			}
			pMod = pMod->Flink;
		}

	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrint("EXCEPTION_EXECUTE_HANDLER is occure...\n");
		KeUnstackDetachProcess(&ks);
	}
	KeUnstackDetachProcess(&ks);
	return status;
}



///获取内核模块基地址
///
ULONG64 GetSystemModuleBase(char* lpModuleName)
{
	ULONG NeedSize, i, ModuleCount, BufferSize = 0x5000;
	PVOID pBuffer = NULL;
	PCHAR pDrvName = NULL;
	NTSTATUS Result;
	PSYSTEM_MODULE_INFORMATION pSystemModuleInformation;
	do
	{
		//分配内存
		pBuffer = kmalloc(BufferSize);
		if (pBuffer == NULL)
			return 0;
		//查询模块信息
		Result = ZwQuerySystemInformation(11, pBuffer, BufferSize, &NeedSize);
		if (Result == STATUS_INFO_LENGTH_MISMATCH)
		{
			kfree(pBuffer);
			BufferSize *= 2;
		}
		else if (!NT_SUCCESS(Result))
		{
			//查询失败则退出
			kfree(pBuffer);
			return 0;
		}
	} while (Result == STATUS_INFO_LENGTH_MISMATCH);
	pSystemModuleInformation = (PSYSTEM_MODULE_INFORMATION)pBuffer;
	//获得模块的总数量
	ModuleCount = pSystemModuleInformation->Count;
	//遍历所有的模块
	for (i = 0; i < ModuleCount; i++)
	{
		if ((ULONG64)(pSystemModuleInformation->Module[i].Base) > (ULONG64)0x8000000000000000)
		{
			pDrvName = pSystemModuleInformation->Module[i].ImageName + pSystemModuleInformation->Module[i].ModuleNameOffset;
			if (_stricmp(pDrvName, lpModuleName) == 0)
			{
				return (ULONG64)pSystemModuleInformation->Module[i].Base;		
			}
				
		}
	}
	kfree(pBuffer);
	return 0;
}

///遍历驱动模块
VOID DriverSec(PDRIVER_OBJECT  pDriverObject)
{
	PLDR_DATA__TABLE_ENTRY pLdr = NULL;
	PLIST_ENTRY pListEntry = NULL;
	PLIST_ENTRY pCurrentListEntry = NULL;
	PLDR_DATA__TABLE_ENTRY pCurrentModule = NULL;
	pLdr = (PLDR_DATA__TABLE_ENTRY)pDriverObject->DriverSection;
	pListEntry = pLdr->InLoadOrderLinks.Flink;
	pCurrentListEntry = pListEntry->Flink;

	while (pCurrentListEntry != pListEntry)
	{
		pCurrentModule = CONTAINING_RECORD(pCurrentListEntry, LDR_DATA__TABLE_ENTRY, InLoadOrderLinks);
		if (pCurrentModule->BaseDllName.Buffer != 0)
		{
			DbgPrint("ModuleName = %wZ ModuleBase = %p \r\n",pCurrentModule->BaseDllName,pCurrentModule->DllBase);
		}
		pCurrentListEntry = pCurrentListEntry->Flink;
	}

	return ;
	
}

//断链隐藏模块  会pg  会被ark工具检测
VOID HideDriver(char* pDrvName, PDRIVER_OBJECT  pDriverObject)
{
	PLDR_DATA__TABLE_ENTRY entry = (PLDR_DATA__TABLE_ENTRY)pDriverObject->DriverSection;
	PLDR_DATA__TABLE_ENTRY firstentry;
	ULONG64 pDrvBase = 0;
	KIRQL OldIrql;
	firstentry = entry;
	pDrvBase = GetSystemModuleBase(pDrvName);
	while ((PLDR_DATA__TABLE_ENTRY)entry->InLoadOrderLinks.Flink != firstentry)
	{
		if (entry->DllBase == pDrvBase)
		{

			OldIrql = KeRaiseIrqlToDpcLevel();
			((LIST_ENTRY64*)(entry->InLoadOrderLinks.Flink))->Blink = entry->InLoadOrderLinks.Blink;
			((LIST_ENTRY64*)(entry->InLoadOrderLinks.Blink))->Flink = entry->InLoadOrderLinks.Flink;
			entry->InLoadOrderLinks.Flink = 0;
			entry->InLoadOrderLinks.Blink = 0;
			KeLowerIrql(OldIrql);
			DbgPrint("Remove LIST_ENTRY64 OK!");
			break;
		}
		entry = (PLDR_DATA__TABLE_ENTRY)entry->InLoadOrderLinks.Flink;
	}
}




//
PLIST_ENTRY Temp = NULL;
PLIST_ENTRY HeadEntry = NULL;

//进程隐藏  会pg 会被ark工具检测
VOID HideProcess(char* ProcessName)
{
	
	ULONG_PTR ActiveOffsetPre = dynData.ActiveOffsetPre;
	ULONG_PTR ActiveOffsetNext = dynData.ActiveOffsetNext;
	ULONG_PTR ImageName = dynData.ImageName;
	PEPROCESS EProcessCurrent = PsGetCurrentProcess(); //  KPCR --> 0x124偏移也就是 -->  +0x004 CurrentThread    : Ptr32 _KTHREAD   当前线程信息
	PEPROCESS EProcessPre = NULL, EProcessPre2 = NULL;


	EProcessPre = ((ULONG_PTR)(*((ULONG_PTR*)((ULONG_PTR)EProcessCurrent + ActiveOffsetPre))) - ActiveOffsetNext);//获得下一个节点
	//这里传这么多指针相当于  _KPCR  --->_KPRCB -->CurrentThread
	while (EProcessCurrent != EProcessPre)
	{
		if (strcmp((char*)((ULONG_PTR)EProcessCurrent + ImageName), ProcessName) == 0)  //拿_eprocess +0x174 偏移处的名字和当前传入的名字比较是否是同一个进程
		{
			Temp = (PLIST_ENTRY)((ULONG_PTR)EProcessCurrent + ActiveOffsetNext);//如果是同一个进程 那就当前进程加一个偏移获取下一个，PLIST_ENTRY 是结构体Flink Blink

			if (MmIsAddressValid(Temp))  //效验一个地址是否有效
			{
				RemoveEntryList(Temp);//移除 这个双项链表
			}
			break;
		}
		EProcessCurrent = (PEPROCESS)((ULONG_PTR)(*((ULONG_PTR*)((ULONG_PTR)EProcessCurrent + ActiveOffsetNext))) - ActiveOffsetNext);

	}
}

VOID ResumeProcess()
{

	if (Temp != NULL)
	{
		InsertHeadList(HeadEntry, Temp);
	}
}

BOOLEAN IsValidAddr(ULONG64 ptr)
{
	ULONG64 min = 0x0001000;
	ULONG64 max = 0x7FFFFFFEFFFF;
	BOOLEAN result = (ptr > min && ptr < max);
	return result;
}

//读写内存
NTSTATUS BBCopyMemory(IN PCOPY_MEMORY pCopy)
{

	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS pProcess = NULL, pSourceProc = NULL, pTargetProc = NULL;
	PVOID pSource = NULL, pTarget = NULL;

	status = PsLookupProcessByProcessId((HANDLE)pCopy->pid, &pProcess);

	if (NT_SUCCESS(status))
	{
		SIZE_T bytes = 0;

		// Write
		if (pCopy->write != FALSE)
		{
			pSourceProc = PsGetCurrentProcess();
			pTargetProc = pProcess;
			pSource = (PVOID)pCopy->localbuf;
			pTarget = (PVOID)pCopy->targetPtr;
		}
		// Read
		else
		{
			pSourceProc = pProcess;
			pTargetProc = PsGetCurrentProcess();
			pSource = (PVOID)pCopy->targetPtr;
			pTarget = (PVOID)pCopy->localbuf;
		}

		if (IsValidAddr(pCopy->targetPtr))
		{
			status = MmCopyVirtualMemory(pSourceProc, pSource, pTargetProc, pTarget, pCopy->size, KernelMode, &bytes);

		}
	}
	else
		DbgPrint("error\n");
	if (pProcess)
		ObDereferenceObject(pProcess);

	return status;
}
//回调函数  用来提权的
BOOLEAN BBHandleCallback(
#if !defined(_WIN7_)
	IN PHANDLE_TABLE HandleTable,
#endif
	IN PHANDLE_TABLE_ENTRY HandleTableEntry,
	IN HANDLE Handle,
	IN PVOID EnumParameter
)
{
	
	BOOLEAN result = FALSE;
	ASSERT(EnumParameter);
	if (EnumParameter != NULL)
	{
		PHANDLE_GRANT_ACCESS pAccess = (PHANDLE_GRANT_ACCESS)EnumParameter;
		//DbgBreakPoint();
	
		if (Handle == (HANDLE)pAccess->handle)
		{
			//DbgBreakPoint();
			if (ExpIsValidObjectEntry(HandleTableEntry))
			{
				// Update access
				HandleTableEntry->GrantedAccessBits = pAccess->access;
				result = TRUE;
			}
			else
				DbgPrint("BlackBone: %s: 0x%X:0x%X handle is invalid\n. HandleEntry = 0x%p",
					__FUNCTION__, pAccess->pid, pAccess->handle, HandleTableEntry
				);
		}
	}

#if !defined(_WIN7_)
	// Release implicit locks
	_InterlockedExchangeAdd8((char*)&HandleTableEntry->VolatileLowValue, 1);  // Set Unlocked flag to 1
	if (HandleTable != NULL && HandleTable->HandleContentionEvent)
		ExfUnblockPushLock(&HandleTable->HandleContentionEvent, NULL);
#endif
	return result;
}

///////////////////////////////////////////////////////////////////


BOOLEAN BBHandleCallbackTest(
#if !defined(_WIN7_)
	IN PHANDLE_TABLE HandleTable,
#endif
	IN PHANDLE_TABLE_ENTRY HandleTableEntry,
	IN HANDLE Handle,
	IN PVOID EnumParameter
)
{

	BOOLEAN result = FALSE;
	PVOID Object = NULL;
	POBJECT_TYPE ObjectType = NULL;

	ASSERT(EnumParameter);
	if (EnumParameter != NULL)
	{
		PHANDLE_Right_ACCESS pAccess = (PHANDLE_Right_ACCESS)EnumParameter;
		//DbgBreakPoint();
		*(ULONG_PTR*)&Object = HandleTableEntry->ObjectPointerBits;
		*(ULONG_PTR*)&Object <<= 4;
		if (Object != NULL)
		{
			*(ULONG_PTR*)&Object |= 0xFFFF000000000000;
			*(ULONG_PTR*)&Object += 0x30;
			ObjectType = ObGetObjectType(Object);
			if (wcscmp(*(PCWSTR*)((PUCHAR)ObjectType + 0x18), L"Process") == 0)
			{

				if (*(PULONG32)((PUCHAR)Object + dynData.UniqueProcessId) == pAccess->targetpid)
				{
		
					HandleTableEntry->GrantedAccessBits = pAccess->access;
					result = TRUE;
				}
			}
		}
		
	}

#if !defined(_WIN7_)
	// Release implicit locks
	_InterlockedExchangeAdd8((char*)&HandleTableEntry->VolatileLowValue, 1);  // Set Unlocked flag to 1
	if (HandleTable != NULL && HandleTable->HandleContentionEvent)
		ExfUnblockPushLock(&HandleTable->HandleContentionEvent, NULL);
#endif
	return result;

}


//IN PHANDLE_Right_ACCESS pAccess
//句柄提权

NTSTATUS BBGrantAccessTest(IN PHANDLE_Right_ACCESS pAccess)
{
	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS pProcess = NULL;
	//DbgBreakPoint();
	if (dynData.ObjectTable == 0)
	{
		DbgPrint("BlackBone: %s: Invalid ObjTable address\n");
		return STATUS_INVALID_ADDRESS;
	}

	status = PsLookupProcessByProcessId((HANDLE)pAccess->localtpid, &pProcess);
	//if (NT_SUCCESS(status))
	//{
	//	status = STATUS_PROCESS_IS_TERMINATING;
	//}
	if (NT_SUCCESS(status))
	{
		//eprocess+0x418 等于 ObjectTable
		PHANDLE_TABLE pTable = *(PHANDLE_TABLE*)((PUCHAR)pProcess + dynData.ObjectTable);
		BOOLEAN found = ExEnumHandleTable(pTable, &BBHandleCallbackTest, pAccess, NULL);
		if (found == FALSE)
			status = STATUS_NOT_FOUND;
	}
	if (pProcess)
		ObDereferenceObject(pProcess);
	return status;
}


NTSTATUS BBAllocateFreeMemory(IN PALLOCATE_FREE_MEMORY pAllocFree, OUT PALLOCATE_FREE_MEMORY_RESULT pResult)
{
	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS pProcess = NULL;

	ASSERT(pResult != NULL);
	if (pResult == NULL)
		return STATUS_INVALID_PARAMETER;

	status = PsLookupProcessByProcessId((HANDLE)pAllocFree->pid, &pProcess);
	if (NT_SUCCESS(status))
	{
		KAPC_STATE apc;
		PVOID base = (PVOID)pAllocFree->base;
		ULONG_PTR size = pAllocFree->size;
		KeStackAttachProcess(pProcess, &apc);
		if (pAllocFree->allocate)
		{

				status = ZwAllocateVirtualMemory(ZwCurrentProcess(), &base, 0, &size, pAllocFree->type, pAllocFree->protection);
				pResult->address = (ULONGLONG)base;
				pResult->size = size;
		
		}
		else {
				status = ZwFreeVirtualMemory(ZwCurrentProcess(), &base, &size, pAllocFree->type);
		}

		KeUnstackDetachProcess(&apc);
	}

	if (pProcess)
		ObDereferenceObject(pProcess);

	return status;
}



//句柄提权
NTSTATUS BBGrantAccess(IN PHANDLE_GRANT_ACCESS pAccess)
{
	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS pProcess = NULL;
	//DbgBreakPoint();
	if (dynData.ObjectTable == 0)
	{
		DbgPrint("BlackBone: %s: Invalid ObjTable address\n");
		return STATUS_INVALID_ADDRESS;
	}
	
	status = PsLookupProcessByProcessId((HANDLE)pAccess->pid, &pProcess);
	//if (NT_SUCCESS(status))
	//{
	//	status = STATUS_PROCESS_IS_TERMINATING;
	//}
	if (NT_SUCCESS(status))
	{
		//eprocess+0x418 等于 ObjectTable
		PHANDLE_TABLE pTable = *(PHANDLE_TABLE*)((PUCHAR)pProcess + dynData.ObjectTable);
		BOOLEAN found = ExEnumHandleTable(pTable, &BBHandleCallback, pAccess, NULL);
		if (found == FALSE)
			status = STATUS_NOT_FOUND;
	}
	if (pProcess)
		ObDereferenceObject(pProcess);
	return status;
}

CHAR HDDSPOOF_BUFFER[MAX_HDDS][32] = { 0x20 };
CHAR HDDORG_BUFFER[MAX_HDDS][32] = { 0 };
typedef struct SSTRING
{
	unsigned  short Length;
	unsigned  short MaximumLength;
	char* Buffer;
}_SSTRING, P_SSTRING;

typedef struct SSTOR_SCSI_IDENTITY
{
	UINT64 InquiryData;
	P_SSTRING* SerialNumber;

} _SSTOR_SCSI_IDENTITY, PPSTOR_SCSI_IDENTITY;
typedef struct _RRAID_UNIT_EXTENSION
{
	char pad_0x0000[0x58];
	UINT64 Identity;

} RRAID_UNIT_EXTENSION, * PRRAID_UNIT_EXTENSION;
typedef __int64(__fastcall* RaidUnitRegisterInterfaces)(PRRAID_UNIT_EXTENSION a1);
RaidUnitRegisterInterfaces pRegDevInt = NULL;
INT HDD_count = 0;
//修改磁盘序列号
void randstring(char* randomString, size_t length) {

	static char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

	ULONG seed = KeQueryTimeIncrement();

	if (randomString)
	{
		for (int n = 0; n <= length; n++)
		{
			int key = RtlRandomEx(&seed) % (int)(sizeof(charset) - 1);
			randomString[n] = charset[key];
		}
		//randomString[length] = '\0';
	}
}
void SpoofHDD()
{

	//UINT64 adderss = GetSystemModuleBase("storport.sys");
	//pRegDevInt = adderss + 108600;
	PDEVICE_OBJECT pObject = NULL;
	PFILE_OBJECT pFileObj = NULL;

	UNICODE_STRING DestinationString;
	RtlInitUnicodeString(&DestinationString, L"\\Device\\RaidPort0");
	NTSTATUS status = IoGetDeviceObjectPointer(&DestinationString, FILE_READ_DATA, &pFileObj, &pObject);
	PDRIVER_OBJECT pDriver = pObject->DriverObject;//双向链表？
	PDEVICE_OBJECT pDevice = pDriver->DeviceObject;
	DbgPrint("11111\n");
	while (pDevice->NextDevice != NULL)
	{
		if (pDevice->DeviceType == FILE_DEVICE_DISK)
		{
			DbgPrint("222\n");
			PRRAID_UNIT_EXTENSION pDeviceHDD = pDevice->DeviceExtension;
			UINT64 Identity =((UINT64)(pDeviceHDD)+0x68);
			DbgPrint("%llx\n", Identity);
			P_SSTRING SerialNumber = *(P_SSTRING*)((UINT64)Identity +0x8);
			CHAR HDDSPOOFED_TMP[32] = { 0x0 };
			randstring(&HDDSPOOFED_TMP, SERIAL_MAX_LENGTH - 1);
			*(CHAR*)SerialNumber.Buffer = HDDSPOOFED_TMP;

		}


		pDevice = pDevice->NextDevice;
	}
}


//系统判断
NTSTATUS BBInitDynamicData(PDYNAMIC_DATA pData)
{
	NTSTATUS status = STATUS_SUCCESS;
	RTL_OSVERSIONINFOEXW verInfo = { 0 };
	if (pData == NULL)
		return STATUS_INVALID_ADDRESS;
	RtlZeroMemory(pData, sizeof(DYNAMIC_DATA));
	pData->DYN_PDE_BASE = PDE_BASE;
	pData->DYN_PTE_BASE = PTE_BASE;

	verInfo.dwOSVersionInfoSize = sizeof(verInfo);
	status = RtlGetVersion((PRTL_OSVERSIONINFOW)&verInfo);

	if (status == STATUS_SUCCESS)
	{
		ULONG ver_short = (verInfo.dwMajorVersion << 8) | (verInfo.dwMinorVersion << 4) | verInfo.wServicePackMajor;
		switch (ver_short)
		{

		case WINVER_10:
			if (verInfo.dwBuildNumber == 19041)
			{
				pData->ActiveOffsetNext = 0x2e8;
				pData->ActiveOffsetPre = 0x2e4;
				pData->ImageName = 0x450;
			}
			else if(verInfo.dwBuildNumber == 18363)//WIndows10_19H2
			{
				pData->ver = WINVER_10_19H2;
				pData->ActiveOffsetNext = 0x2f0;
				pData->ActiveOffsetPre = 0x2ec;
				pData->ImageName = 0x450;
				pData->peboffseteprocess = 0x3f8;
				pData->ldroffsetpeb = 0x18;
				pData->InLoadOrderModuleList_offset = 0x10;
				pData->ObjectTable = 0x418;
				pData->UniqueProcessId = 0x2e8;
				pData->VadRoot = 0x658;
				pData->PrevMode = 0x232;

			}
			else if (verInfo.dwBuildNumber == 19042)//WIndows10_20H2
			{
				pData->ver = WINVER_10_20H2;
				pData->ActiveOffsetNext = 0x448;  //EPROCESS--> ActiveProcessLinks
				pData->ActiveOffsetPre = 0x444;
				pData->ImageName = 0x450;//EPROCESS-->ImageFileName
				pData->peboffseteprocess = 0x550;//EPROCESS  -- >Peb
				pData->ldroffsetpeb = 0x18;// Peb --> ldr
				pData->InLoadOrderModuleList_offset = 0x10; //PEB_LDR_DATA --> InMemoryOrderModuleList
				pData->ObjectTable = 0x570;
				pData->UniqueProcessId = 0x440;//EPROCESS -- >UniqueProcessId
				pData->VadRoot = 0x7D8;//EPROCESS -- >VadRoot
				pData->PrevMode = 0x232;//EPROCESS -- >PrevMode
			}
			else if (verInfo.dwBuildNumber == 19044)//WIndows10_21H2
			{
				pData->ver = WINVER_10_20H2;
				pData->ActiveOffsetNext = 0x448;  //EPROCESS--> ActiveProcessLinks
				pData->ActiveOffsetPre = 0x444;
				pData->ImageName = 0x5a8;//EPROCESS-->ImageFileName
				pData->peboffseteprocess = 0x550;//EPROCESS  -- >Peb
				pData->ldroffsetpeb = 0x18;// Peb --> ldr
				pData->InLoadOrderModuleList_offset = 0x10; //PEB_LDR_DATA --> InMemoryOrderModuleList
				pData->ObjectTable = 0x570;//EPROCESS -- >ObjectTable
				pData->UniqueProcessId = 0x440;//EPROCESS -- >UniqueProcessId
				pData->VadRoot = 0x7D8;//EPROCESS -- >VadRoot
				pData->PrevMode = 0x232;//EPROCESS -- >PrevMode
			}
			else
			{
				return STATUS_NOT_SUPPORTED;
			}
		default:
			break;
		}
		
	}
	return status;
}

