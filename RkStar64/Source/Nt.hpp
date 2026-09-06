#pragma once
#include <ntddk.h>
#include <wdf.h>
#include <bcrypt.h>
#include <ntintsafe.h>
#include <ntstrsafe.h>

#pragma warning(push)
#pragma warning(disable: 4201)

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

extern "C" {

    NTSYSAPI 
        NTSTATUS 
        NTAPI 
        ZwQuerySystemInformation(
            _In_      ULONG  SystemInformationClass,
            _Out_opt_ PVOID  SystemInformation,
            _In_      ULONG  SystemInformationLength,
            _Out_opt_ PULONG ReturnLength
        );

    NTSYSAPI
        PVOID
        NTAPI
        PsGetProcessSectionBaseAddress(
            _In_ PEPROCESS Process
        );

    NTSYSAPI
        NTSTATUS
        NTAPI
        MmCopyVirtualMemory(
            _In_ PEPROCESS SourceProcess,
            _In_ CONST VOID* SourceAddress,
            _In_ PEPROCESS TargetProcess,
            _Out_ PVOID TargetAddress,
            _In_ SIZE_T BufferSize,
            _In_ KPROCESSOR_MODE PreviousMode,
            _Out_ PSIZE_T NumberOfBytesCopied
        );

    NTSYSAPI
        NTSTATUS
        NTAPI
        PsLookupProcessByProcessId(
            _In_ HANDLE ProcessId,
            _Out_ PEPROCESS* Process
        );
}

namespace Nt
{
    struct Fns
    {
        decltype(&MmCopyVirtualMemory) pMmCopyVirtualMemory = nullptr;
        decltype(&PsLookupProcessByProcessId) pPsLookupProcessByProcessId = nullptr;
        decltype(&PsGetProcessSectionBaseAddress) pPsGetProcessSectionBaseAddress = nullptr;
		decltype(&ZwQuerySystemInformation) pZwQuerySystemInformation = nullptr;
    };

    extern Fns g_Fns;
}

#pragma warning(pop)