#ifndef _NTHELPER
#define _NTHELPER

#include <Windows.h>
#include <winternl.h>

#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004

typedef enum _My_SYSTEM_INFORMATION_CLASS {
    MySystemBasicInformation,
    MySystemProcessorInformation,
    MySystemPerformanceInformation,
    MySystemTimeOfDayInformation,
    MySystemPathInformation,
    MySystemProcessInformation,
    MySystemCallCountInformation,
    MySystemDeviceInformation,
    MySystemProcessorPerformanceInformation,
    MySystemFlagsInformation,
    MySystemCallTimeInformation,
    MySystemModuleInformation,
    MySystemLocksInformation,
    MySystemStackTraceInformation,
    MySystemPagedPoolInformation,
    MySystemNonPagedPoolInformation,
    MySystemHandleInformation,
    MySystemObjectInformation,
    MySystemPageFileInformation,
    MySystemVdmInstemulInformation,
    MySystemVdmBopInformation,
    MySystemFileCacheInformation,
    MySystemPoolTagInformation,
    MySystemInterruptInformation,
    MySystemDpcBehaviorInformation,
    MySystemFullMemoryInformation,
    MySystemLoadGdiDriverInformation,
    MySystemUnloadGdiDriverInformation,
    MySystemTimeAdjustmentInformation,
    MySystemSummaryMemoryInformation,
    MySystemNextEventIdInformation,
    MySystemEventIdsInformation,
    MySystemCrashDumpInformation,
    MySystemExceptionInformation,
    MySystemCrashDumpStateInformation,
    MySystemKernelDebuggerInformation,
    MySystemContextSwitchInformation,
    MySystemRegistryQuotaInformation,
    MySystemExtendServiceTableInformation,
    MySystemPrioritySeperation,
    MySystemPlugPlayBusInformation,
    MySystemDockInformation,
    MySystemPowerInformation,
    MySystemProcessorSpeedInformation,
    MySystemCurrentTimeZoneInformation,
    MySystemLookasideInformation,
    MySystemExtendedHandleInformation = 64
} My_SYSTEM_INFORMATION_CLASS, *ptr_My_SYSTEM_INFORMATION_CLASS;

#define MAXIMUM_FILENAME_LENGTH 255 

typedef struct _My_SYSTEM_MODULE {
	ULONG                Reserved1;
	ULONG                Reserved2;
#ifdef _WIN64
	ULONG				Reserved3;
#endif
	PVOID                ImageBaseAddress;
	ULONG                ImageSize;
	ULONG                Flags;
	WORD                 Id;
	WORD                 Rank;
	WORD                 w018;
	WORD                 NameOffset;
	CHAR                 Name[MAXIMUM_FILENAME_LENGTH];
}My_SYSTEM_MODULE, *ptr_My_SYSTEM_MODULE;

typedef struct _My_SYSTEM_MODULE_INFORMATION {
	ULONG                ModulesCount;
	My_SYSTEM_MODULE     Modules[1];
} My_SYSTEM_MODULE_INFORMATION, *ptr_My_SYSTEM_MODULE_INFORMATION;

typedef struct _My_SYSTEM_HANDLE
{
    PVOID Object;
	HANDLE UniqueProcessId;
	HANDLE HandleValue;
	ULONG GrantedAccess;
	USHORT CreatorBackTraceIndex;
	USHORT ObjectTypeIndex;
	ULONG HandleAttributes;
	ULONG Reserved;
} My_SYSTEM_HANDLE, *ptr_My_SYSTEM_HANDLE;

typedef struct _My_SYSTEM_HANDLE_INFORMATION
{
	ULONG_PTR HandleCount;
    ULONG_PTR Reserved;
	My_SYSTEM_HANDLE Handles[1];
} My_SYSTEM_HANDLE_INFORMATION, *ptr_My_SYSTEM_HANDLE_INFORMATION;

typedef NTSTATUS (NTAPI* FuncTy_NtQuerySystemInformation) (
    SYSTEM_INFORMATION_CLASS SystemInformationClass, 
    PVOID SystemInformation, 
    ULONG SystemInformationLength, 
    ULONG *ReturnLength
);
FuncTy_NtQuerySystemInformation g_pfnNtQuerySystemInformation = NULL;

NTSTATUS NTAPI My_NtQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass, 
    PVOID SystemInformation, 
    ULONG SystemInformationLength, 
    ULONG *ReturnLength
)
{
    if (g_pfnNtQuerySystemInformation == NULL) {
        g_pfnNtQuerySystemInformation = (FuncTy_NtQuerySystemInformation)GetProcAddress(
            LoadLibraryW(L"ntdll.dll"), "NtQuerySystemInformation"
        );
    }

    return g_pfnNtQuerySystemInformation(
        SystemInformationClass,
        SystemInformation,
        SystemInformationLength,
        ReturnLength
    );
};

NTSTATUS GetHandlesInfo(ptr_My_SYSTEM_HANDLE_INFORMATION* ppInfo) {
    *ppInfo = NULL;
    
    SIZE_T szInfo = 0x10000;
    ptr_My_SYSTEM_HANDLE_INFORMATION lpInfo =  (ptr_My_SYSTEM_HANDLE_INFORMATION)VirtualAlloc(NULL, szInfo, MEM_COMMIT, PAGE_READWRITE);

    NTSTATUS status = My_NtQuerySystemInformation(
            (SYSTEM_INFORMATION_CLASS)MySystemExtendedHandleInformation,lpInfo,szInfo,NULL);

    while (status == STATUS_INFO_LENGTH_MISMATCH) {

        VirtualFree(lpInfo, szInfo, MEM_DECOMMIT);

        szInfo *= 4;
        lpInfo =  (ptr_My_SYSTEM_HANDLE_INFORMATION)VirtualAlloc(
            NULL, szInfo, MEM_COMMIT, PAGE_READWRITE);
    
        status = My_NtQuerySystemInformation(
            (SYSTEM_INFORMATION_CLASS)MySystemExtendedHandleInformation, lpInfo, szInfo, NULL
        );
        if (NT_SUCCESS(status))
            break;
    }

    if (NT_SUCCESS(status))
        *ppInfo = lpInfo;

    return status;
}

NTSTATUS GetModulesInfo(ptr_My_SYSTEM_MODULE_INFORMATION* ppInfo) {
    *ppInfo = NULL;
    
    SIZE_T szInfo = 0x10000;

    ptr_My_SYSTEM_MODULE_INFORMATION lpInfo =  (ptr_My_SYSTEM_MODULE_INFORMATION)VirtualAlloc(NULL, szInfo, MEM_COMMIT, PAGE_READWRITE);

    NTSTATUS status = My_NtQuerySystemInformation(
            (SYSTEM_INFORMATION_CLASS)MySystemModuleInformation,lpInfo,szInfo,NULL);

    while (status == STATUS_INFO_LENGTH_MISMATCH) {

        VirtualFree(lpInfo, szInfo, MEM_DECOMMIT);

        szInfo *= 4;
        lpInfo = (ptr_My_SYSTEM_MODULE_INFORMATION)VirtualAlloc(
            NULL, szInfo, MEM_COMMIT, PAGE_READWRITE);
    
        status = My_NtQuerySystemInformation(
            (SYSTEM_INFORMATION_CLASS)MySystemModuleInformation, lpInfo, szInfo, NULL
        );
        if (NT_SUCCESS(status))
            break;
    }

    if (NT_SUCCESS(status))
        *ppInfo = lpInfo;

    return status;
};

#endif // _NTHELPER