// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <iostream>
#include "Minhook.h"
#include <winternl.h>
#include <windows.h>
#include "logger.hpp"
#if defined _M_X64
#pragma comment(lib, "libMinHook.x64.lib")
#elif defined _M_IX86
#pragma comment(lib, "libMinHook.x86.lib")
#endif

typedef NTSTATUS(NTAPI* pNtAllocateVirtualMemory)(
    HANDLE    ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T   RegionSize,
    ULONG     AllocationType,
    ULONG     Protect
    );

typedef NTSTATUS(NTAPI* pNtProtectVirtualMemory)(
    HANDLE    ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T   RegionSize,
    ULONG     NewProtect,
    PULONG    OldProtect
);


pNtAllocateVirtualMemory pOriginalNTallocatevirtualmemory = nullptr;
pNtProtectVirtualMemory  pOriginalNTProtectVirtualMemory = nullptr;

NTSTATUS NTAPI HookedAllocateVirtualMemory(
    HANDLE    ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T   RegionSize,
    ULONG     AllocationType,
    ULONG     Protect
) {
    if (Protect == PAGE_EXECUTE_READWRITE) {
        Logger::LogMessage("[+] NtAllocateVirtualMemory: PAGE_EXECUTE_READWRITE Detected!");
    }

    return pOriginalNTallocatevirtualmemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
}

NTSTATUS NTAPI HookedProtectVirtualMemory(
    HANDLE    ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T   RegionSize,
    ULONG     NewProtect,
    PULONG    OldProtect
) {
    if (NewProtect == PAGE_EXECUTE_READWRITE) {
        Logger::LogMessage("[+] NtProtectVirtualMemory: PAGE_EXECUTE_READWRITE Detected!");
    }

    return pOriginalNTProtectVirtualMemory(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
}

void Initializehooks() {
    if (MH_Initialize() != MH_OK) {
        Logger::LogMessage("[-] MH_Initialize failed");
        return;
    }

    if (MH_CreateHookApi(L"ntdll", "NtProtectVirtualMemory", &HookedProtectVirtualMemory, (LPVOID*)&pOriginalNTProtectVirtualMemory) != MH_OK) {
        Logger::LogMessage("[-] Failed to hook NtProtectVirtualMemory");
    }

    if (MH_CreateHookApi(L"ntdll", "NtAllocateVirtualMemory", &HookedAllocateVirtualMemory, (LPVOID*)&pOriginalNTallocatevirtualmemory) != MH_OK) {
        Logger::LogMessage("[-] Failed to hook NtAllocateVirtualMemory");
    }

    if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK) {
        Logger::LogMessage("[-] MH_EnableHook failed");
        return;
    }

    Logger::LogMessage("[+] Hooks Installed Successfully");
}



DWORD WINAPI FunctionMain(LPVOID lpParam) {

    //initialize hooks
    Logger::LogMessage("DLL_PROCESS_ATTACH reached!");
    Initializehooks();

    return 0;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        Logger::LogMessage("Injected into process!");

        FunctionMain(NULL);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

