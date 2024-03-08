//
//
//#include"APC.h"
//#include"NativeStructs.h"
//#include"imports.h"
//
//#include <Ntstrsafe.h>
//
//
//NTSTATUS BBFileExists(IN PUNICODE_STRING path);
//NTSTATUS BBResolveApiSet(
//    IN PEPROCESS pProcess,
//    IN PUNICODE_STRING name,
//    IN PUNICODE_STRING baseImage,
//    OUT PUNICODE_STRING resolved
//);
//
//NTSTATUS BBInjectDll(IN PINJECT_DLL pData)
//{
//	NTSTATUS status = STATUS_SUCCESS;
//	NTSTATUS threadStatus = STATUS_SUCCESS;
//	PEPROCESS pProcess = NULL;
//    PVOID pNtdll = NULL;
//	PVOID LdrLoadDll = NULL;
//	UNICODE_STRING ustrPath, ustrNtdll;
//	BOOLEAN isWow64 = (PsGetProcessWow64Process(pProcess) != NULL) ? TRUE : FALSE;
//	status = PsLookupProcessByProcessId((HANDLE)pData->pid, &pProcess);
//	if (NT_SUCCESS(status))
//	{
//
//	}
//
//	RtlInitUnicodeString(&ustrPath, pData->FullDllPath);
//	RtlInitUnicodeString(&ustrNtdll, L"Ntdll.dll");
//
//	RtlInitUnicodeString(&ustrPath, pData->FullDllPath);
//
//			// Get ntdll base
//	pNtdll = BBGetUserModule(pProcess, &ustrNtdll, isWow64);
//
//    // Get LdrLoadDll address
//    if (NT_SUCCESS(status))
//    {
//        LdrLoadDll = BBGetModuleExport(pNtdll, "LdrLoadDll", pProcess, NULL);
//        if (!LdrLoadDll)
//        {
//            DbgPrint("BlackBone: %s: Failed to get LdrLoadDll address\n", __FUNCTION__);
//            status = STATUS_NOT_FOUND;
//        }
//    }
//	PINJECT_BUFFER pUserBuf = BBGetWow64Code(LdrLoadDll, &ustrPath);
//
//	status = BBApcInject(pUserBuf, pProcess, pData->initRVA, pData->initArg);
//	return status;
//}
//
///// <summary>
///// Inject dll using APC
///// Must be running in target process context
///// </summary>
///// <param name="pUserBuf">Injcetion code</param>
///// <param name="pProcess">Target process</param>
///// <param name="initRVA">Init routine RVA</param>
///// <param name="InitArg">Init routine argument</param>
///// <returns>Status code</returns>
//NTSTATUS BBApcInject(IN PINJECT_BUFFER pUserBuf, IN PEPROCESS pProcess, IN ULONG initRVA, IN PCWCHAR InitArg)
//{
//
//
//}
//
///// <summary>
///// Build injection code for wow64 process
///// Must be running in target process context
///// </summary>
///// <param name="LdrLoadDll">LdrLoadDll address</param>
///// <param name="pPath">Path to the dll</param>
///// <returns>Code pointer. When not needed, it should be freed with ZwFreeVirtualMemory</returns>
//PINJECT_BUFFER BBGetWow64Code(IN PVOID LdrLoadDll, IN PUNICODE_STRING pPath)
//{
//
//}
//
//
///// <summary>
///// Get module base address by name
///// </summary>
///// <param name="pProcess">Target process</param>
///// <param name="ModuleName">Nodule name to search for</param>
///// <param name="isWow64">If TRUE - search in 32-bit PEB</param>
///// <returns>Found address, NULL if not found</returns>
//PVOID BBGetUserModule(IN PEPROCESS pProcess, IN PUNICODE_STRING ModuleName, IN BOOLEAN isWow64)
//{
//    ASSERT(pProcess != NULL);
//    if (pProcess == NULL)
//        return NULL;
//
//    // Protect from UserMode AV
//    __try
//    {
//        LARGE_INTEGER time = { 0 };
//        time.QuadPart = -250ll * 10 * 1000;     // 250 msec.
//
//        // Wow64 process
//        if (isWow64)
//        {
//            PPEB32 pPeb32 = (PPEB32)PsGetProcessWow64Process(pProcess);
//            if (pPeb32 == NULL)
//            {
//                DbgPrint("BlackBone: %s: No PEB present. Aborting\n", __FUNCTION__);
//                return NULL;
//            }
//
//            // Wait for loader a bit
//            for (INT i = 0; !pPeb32->Ldr && i < 10; i++)
//            {
//                DbgPrint("BlackBone: %s: Loader not intialiezd, waiting\n", __FUNCTION__);
//                KeDelayExecutionThread(KernelMode, TRUE, &time);
//            }
//
//            // Still no loader
//            if (!pPeb32->Ldr)
//            {
//                DbgPrint("BlackBone: %s: Loader was not intialiezd in time. Aborting\n", __FUNCTION__);
//                return NULL;
//            }
//
//            // Search in InLoadOrderModuleList
//            for (PLIST_ENTRY32 pListEntry = (PLIST_ENTRY32)((PPEB_LDR_DATA32)pPeb32->Ldr)->InLoadOrderModuleList.Flink;
//                pListEntry != &((PPEB_LDR_DATA32)pPeb32->Ldr)->InLoadOrderModuleList;
//                pListEntry = (PLIST_ENTRY32)pListEntry->Flink)
//            {
//                UNICODE_STRING ustr;
//                PLDR_DATA_TABLE_ENTRY32 pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);
//
//                RtlUnicodeStringInit(&ustr, (PWCH)pEntry->BaseDllName.Buffer);
//
//                if (RtlCompareUnicodeString(&ustr, ModuleName, TRUE) == 0)
//                    return (PVOID)pEntry->DllBase;
//            }
//        }
//        // Native process
//        else
//        {
//            PPEB pPeb = PsGetProcessPeb(pProcess);
//   
//            if (!pPeb)
//            {
//                DbgPrint("BlackBone: %s: No PEB present. Aborting\n", __FUNCTION__);
//                return NULL;
//            }
//            
//            // Wait for loader a bit
//            for (INT i = 0; !pPeb->Ldr && i < 10; i++)
//            {
//                DbgPrint("BlackBone: %s: Loader not intialiezd, waiting\n", __FUNCTION__);
//                KeDelayExecutionThread(KernelMode, TRUE, &time);
//            }
//
//            // Still no loader
//            if (!pPeb->Ldr)
//            {
//                DbgPrint("BlackBone: %s: Loader was not intialiezd in time. Aborting\n", __FUNCTION__);
//                return NULL;
//            }
//
//            // Search in InLoadOrderModuleList
//            for (PLIST_ENTRY pListEntry = pPeb->Ldr->InLoadOrderModuleList.Flink;
//                pListEntry != &pPeb->Ldr->InLoadOrderModuleList;
//                pListEntry = pListEntry->Flink)
//            {
//                PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
//                if (RtlCompareUnicodeString(&pEntry->BaseDllName, ModuleName, TRUE) == 0)
//                    return pEntry->DllBase;
//            }
//        }
//    }
//    __except (EXCEPTION_EXECUTE_HANDLER)
//    {
//        DbgPrint("BlackBone: %s: Exception, Code: 0x%X\n", __FUNCTION__, GetExceptionCode());
//    }
//
//    return NULL;
//}
//
//
//
//
///// <summary>
///// Get file name from full path
///// </summary>
///// <param name="path">Path.</param>
///// <param name="name">Resulting name</param>
///// <returns>Status code</returns>
//NTSTATUS BBStripPath(IN PUNICODE_STRING path, OUT PUNICODE_STRING name)
//{
//    ASSERT(path != NULL && name);
//    if (path == NULL || name == NULL)
//        return STATUS_INVALID_PARAMETER;
//
//    // Empty string
//    if (path->Length < 2)
//    {
//        *name = *path;
//        return STATUS_NOT_FOUND;
//    }
//
//    for (USHORT i = (path->Length / sizeof(WCHAR)) - 1; i != 0; i--)
//    {
//        if (path->Buffer[i] == L'\\' || path->Buffer[i] == L'/')
//        {
//            name->Buffer = &path->Buffer[i + 1];
//            name->Length = name->MaximumLength = path->Length - (i + 1) * sizeof(WCHAR);
//            return STATUS_SUCCESS;
//        }
//    }
//
//    *name = *path;
//    return STATUS_NOT_FOUND;
//}
//
//
///// <summary>
///// Get exported function address
///// </summary>
///// <param name="pBase">Module base</param>
///// <param name="name_ord">Function name or ordinal</param>
///// <param name="pProcess">Target process for user module</param>
///// <param name="baseName">Dll name for api schema</param>
///// <returns>Found address, NULL if not found</returns>
//PVOID BBGetModuleExport(IN PVOID pBase, IN PCCHAR name_ord, IN PEPROCESS pProcess, IN PUNICODE_STRING baseName)
//{
//    PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)pBase;
//    PIMAGE_NT_HEADERS32 pNtHdr32 = NULL;
//    PIMAGE_NT_HEADERS64 pNtHdr64 = NULL;
//    PIMAGE_EXPORT_DIRECTORY pExport = NULL;
//    ULONG expSize = 0;
//    ULONG_PTR pAddress = 0;
//
//    ASSERT(pBase != NULL);
//    if (pBase == NULL)
//        return NULL;
//
//    /// Not a PE file
//    if (pDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
//        return NULL;
//
//    pNtHdr32 = (PIMAGE_NT_HEADERS32)((PUCHAR)pBase + pDosHdr->e_lfanew);
//    pNtHdr64 = (PIMAGE_NT_HEADERS64)((PUCHAR)pBase + pDosHdr->e_lfanew);
//
//    // Not a PE file
//    if (pNtHdr32->Signature != IMAGE_NT_SIGNATURE)
//        return NULL;
//
//    // 64 bit image
//    if (pNtHdr32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
//    {
//        pExport = (PIMAGE_EXPORT_DIRECTORY)(pNtHdr64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (ULONG_PTR)pBase);
//        expSize = pNtHdr64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
//    }
//    // 32 bit image
//    else
//    {
//        pExport = (PIMAGE_EXPORT_DIRECTORY)(pNtHdr32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (ULONG_PTR)pBase);
//        expSize = pNtHdr32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
//    }
//
//    PUSHORT pAddressOfOrds = (PUSHORT)(pExport->AddressOfNameOrdinals + (ULONG_PTR)pBase);
//    PULONG  pAddressOfNames = (PULONG)(pExport->AddressOfNames + (ULONG_PTR)pBase);
//    PULONG  pAddressOfFuncs = (PULONG)(pExport->AddressOfFunctions + (ULONG_PTR)pBase);
//
//    for (ULONG i = 0; i < pExport->NumberOfFunctions; ++i)
//    {
//        USHORT OrdIndex = 0xFFFF;
//        PCHAR  pName = NULL;
//
//        // Find by index
//        if ((ULONG_PTR)name_ord <= 0xFFFF)
//        {
//            OrdIndex = (USHORT)i;
//        }
//        // Find by name
//        else if ((ULONG_PTR)name_ord > 0xFFFF && i < pExport->NumberOfNames)
//        {
//            pName = (PCHAR)(pAddressOfNames[i] + (ULONG_PTR)pBase);
//            OrdIndex = pAddressOfOrds[i];
//        }
//        // Weird params
//        else
//            return NULL;
//
//        if (((ULONG_PTR)name_ord <= 0xFFFF && (USHORT)((ULONG_PTR)name_ord) == OrdIndex + pExport->Base) ||
//            ((ULONG_PTR)name_ord > 0xFFFF && strcmp(pName, name_ord) == 0))
//        {
//            pAddress = pAddressOfFuncs[OrdIndex] + (ULONG_PTR)pBase;
//
//            // Check forwarded export
//            if (pAddress >= (ULONG_PTR)pExport && pAddress <= (ULONG_PTR)pExport + expSize)
//            {
//                WCHAR strbuf[256] = { 0 };
//                ANSI_STRING forwarder = { 0 };
//                ANSI_STRING import = { 0 };
//
//                UNICODE_STRING uForwarder = { 0 };
//                ULONG delimIdx = 0;
//                PVOID forwardBase = NULL;
//                PVOID result = NULL;
//
//                // System image, not supported
//                if (pProcess == NULL)
//                    return NULL;
//
//                RtlInitAnsiString(&forwarder, (PCSZ)pAddress);
//                RtlInitEmptyUnicodeString(&uForwarder, strbuf, sizeof(strbuf));
//
//                RtlAnsiStringToUnicodeString(&uForwarder, &forwarder, FALSE);
//                for (ULONG j = 0; j < uForwarder.Length / sizeof(WCHAR); j++)
//                {
//                    if (uForwarder.Buffer[j] == L'.')
//                    {
//                        uForwarder.Length = (USHORT)(j * sizeof(WCHAR));
//                        uForwarder.Buffer[j] = L'\0';
//                        delimIdx = j;
//                        break;
//                    }
//                }
//
//                // Get forward function name/ordinal
//                RtlInitAnsiString(&import, forwarder.Buffer + delimIdx + 1);
//                RtlAppendUnicodeToString(&uForwarder, L".dll");
//
//                //
//                // Check forwarded module
//                //
//                UNICODE_STRING resolved = { 0 };
//                UNICODE_STRING resolvedName = { 0 };
//                BBResolveImagePath(NULL, pProcess, KApiShemaOnly, &uForwarder, baseName, &resolved);
//                BBStripPath(&resolved, &resolvedName);
//
//                forwardBase = BBGetUserModule(pProcess, &resolvedName, PsGetProcessWow64Process(pProcess) != NULL);
//                result = BBGetModuleExport(forwardBase, import.Buffer, pProcess, &resolvedName);
//                RtlFreeUnicodeString(&resolved);
//
//                return result;
//            }
//
//            break;
//        }
//    }
//
//    return (PVOID)pAddress;
//}
//
///// <summary>
///// Resolve image name to fully qualified path
///// </summary>
///// <param name="pContext">Loader context</param>
///// <param name="pProcess">Target process. Must be running in the context of this process</param>
///// <param name="flags">Flags</param>
///// <param name="path">Image name to resolve</param>
///// <param name="baseImage">Base image name for API SET translation</param>
///// <param name="resolved">Resolved image path</param>
///// <returns>Status code</returns>
//NTSTATUS BBResolveImagePath(
//    IN PMMAP_CONTEXT pContext,
//    IN PEPROCESS pProcess,
//    IN ResolveFlags flags,
//    IN PUNICODE_STRING path,
//    IN PUNICODE_STRING baseImage,
//    OUT PUNICODE_STRING resolved
//)
//{
//    NTSTATUS status = STATUS_SUCCESS;
////    UNICODE_STRING pathLow = { 0 };
////    UNICODE_STRING filename = { 0 };
////    UNICODE_STRING fullResolved = { 0 };
////
////    UNREFERENCED_PARAMETER(baseImage);
////
////    ASSERT(pProcess != NULL && path != NULL && resolved != NULL);
////    if (pProcess == NULL || path == NULL || resolved == NULL)
////    {
////       // DPRINT("BlackBone: %s: Missing parameter\n", __FUNCTION__);
////        return STATUS_INVALID_PARAMETER;
////    }
////
////    RtlDowncaseUnicodeString(&pathLow, path, TRUE);
////    BBStripPath(&pathLow, &filename);
////
////    // API Schema
////    if (NT_SUCCESS(BBResolveApiSet(pProcess, &filename, baseImage, resolved)))
////    {
////     //   BBSafeAllocateString(&fullResolved, 512);
////
////        // Perpend system directory
////        if (PsGetProcessWow64Process(pProcess) != NULL)
////            RtlUnicodeStringCatString(&fullResolved, L"\\SystemRoot\\syswow64\\");
////        else
////            RtlUnicodeStringCatString(&fullResolved, L"\\SystemRoot\\system32\\");
////
////        RtlUnicodeStringCat(&fullResolved, resolved);
////        RtlFreeUnicodeString(resolved);
////        RtlFreeUnicodeString(&pathLow);
////
////        //DPRINT( "BlackBone: %s: Resolved image '%wZ' to '%wZ' by ApiSetSchema\n", __FUNCTION__, path, fullResolved );
////
////        *resolved = fullResolved;
////        return STATUS_SUCCESS;
////    }
////
////    // Api schema only
////    if (flags & KApiShemaOnly)
////        goto skip;
////
////    if (flags & KSkipSxS)
////        goto SkipSxS;
////
////    // SxS
////    //status = BBResolveSxS(pContext, &filename, resolved);
////    if (pContext && NT_SUCCESS(status))
////    {
////    //    BBSafeAllocateString(&fullResolved, 1024);
////        RtlUnicodeStringCatString(&fullResolved, L"\\??\\");
////        RtlUnicodeStringCat(&fullResolved, resolved);
////
////        RtlFreeUnicodeString(resolved);
////        RtlFreeUnicodeString(&pathLow);
////
////        *resolved = fullResolved;
////        return STATUS_SUCCESS;
////    }
////    else if (status == STATUS_UNHANDLED_EXCEPTION)
////    {
////        *resolved = pathLow;
////        return status;
////    }
////    else
////        status = STATUS_SUCCESS;
////
////SkipSxS:
////    BBSafeAllocateString(&fullResolved, 0x400);
////
////    //
////    // Executable directory
////    //
////    ULONG bytes = 0;
////    if (NT_SUCCESS(ZwQueryInformationProcess(ZwCurrentProcess(), ProcessImageFileName, fullResolved.Buffer + 0x100, 0x200, &bytes)))
////    {
////        PUNICODE_STRING pPath = (PUNICODE_STRING)(fullResolved.Buffer + 0x100);
////        UNICODE_STRING parentDir = { 0 };
////      //  BBStripFilename(pPath, &parentDir);
////
////        RtlCopyUnicodeString(&fullResolved, &parentDir);
////        RtlUnicodeStringCatString(&fullResolved, L"\\");
////        RtlUnicodeStringCat(&fullResolved, &filename);
////
////        if (NT_SUCCESS(BBFileExists(&fullResolved)))
////        {
////            RtlFreeUnicodeString(resolved);
////            RtlFreeUnicodeString(&pathLow);
////
////            *resolved = fullResolved;
////            return STATUS_SUCCESS;
////        }
////    }
////
////    fullResolved.Length = 0;
////    RtlZeroMemory(fullResolved.Buffer, 0x400);
////
////    //
////    // System directory
////    //
////    if (PsGetProcessWow64Process(pProcess) != NULL)
////        RtlUnicodeStringCatString(&fullResolved, L"\\SystemRoot\\SysWOW64\\");
////    else
////        RtlUnicodeStringCatString(&fullResolved, L"\\SystemRoot\\System32\\");
////
////    RtlUnicodeStringCat(&fullResolved, &filename);
////    if (NT_SUCCESS(BBFileExists(&fullResolved)))
////    {
////        RtlFreeUnicodeString(resolved);
////        RtlFreeUnicodeString(&pathLow);
////
////        *resolved = fullResolved;
////        return STATUS_SUCCESS;
////    }
////
////    RtlFreeUnicodeString(&fullResolved);
////
////    // Nothing found
////skip:
////    *resolved = pathLow;
//    return status;
//}
//
//
///// <summary>
///// Check if file exists
///// </summary>
///// <param name="path">Fully qualifid path to a file</param>
///// <returns>Status code</returns>
//NTSTATUS BBFileExists(IN PUNICODE_STRING path)
//{
//
//}
//
///// <summary>
///// Try to resolve image via API SET map
///// </summary>
///// <param name="pProcess">Target process. Must be run in the context of this process</param>
///// <param name="name">Name to resolve</param>
///// <param name="baseImage">Parent image name</param>
///// <param name="resolved">Resolved name if any</param>
///// <returns>Status code</returns>
//NTSTATUS BBResolveApiSet(
//    IN PEPROCESS pProcess,
//    IN PUNICODE_STRING name,
//    IN PUNICODE_STRING baseImage,
//    OUT PUNICODE_STRING resolved
//)
//{
//    NTSTATUS status = STATUS_NOT_FOUND;
//
//
//    return status;
//}