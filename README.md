# Basic EDR 
I made my own basic EDR implementing API hooking, namedpipes for logging, Kernel Callback and APC injection.

EDR(Payload):
Implements basic VirtualAlloc/memcyp/exec calc.exe in shellcode
test API hooking through LoadLibraryA of virtualhook.DLL
Agent:
Deploys logging with named pipe
Deploys Kernel Driver
Basically tries to load that vDriver.sys file and save it as a service
Kernel Driver:
Hooks image loads using Kernel callback function PsSetLoadImageNotifyRoutine
Resolves APIs via custom PE export parsing
Performs APC-based DLL injection with KeInitializeApc
Allocates/writes memory in target processes (ZwAllocateVirtualMemory)
Logs telemetry via KdPrint for debugging
API Hooking DLL:
Hooks critical memory APIs (NtAllocateVirtualMemory, NtProtectVirtualMemory) using MinHook.
Logs detection of RWX (PAGE_EXECUTE_READWRITE) memory allocations for suspicious code injection.
Implements clean hook initialization (MH_CreateHookApi, MH_EnableHook) with custom Logger.
Injected into processes to monitor runtime memory protection changes in real time.
Logging:
Log telemetry of hooked APIs are collected using named pipe "\\.\pipe\PoopAgent"
