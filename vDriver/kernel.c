#include "driver.h"
//MUST = is just initializing the pointer to NULL (0) before it’s assigned a real address by CustomGetProcAddress.
PVOID pLoadLibraryExA = {0};


PVOID ApcKernelRoutine(PKAPC Apc, PKNORMAL_ROUTINE* NormalRoutine, PVOID* SystemArgument1, PVOID* SystemArgument2, PVOID* Context) {
    UNREFERENCED_PARAMETER(Apc);
    UNREFERENCED_PARAMETER(NormalRoutine);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);
    UNREFERENCED_PARAMETER(Context);

    ExFreePool(Apc);
    return;
}

NTSTATUS DllInject(HANDLE ProcessId, PEPROCESS PeProcess, PETHREAD PeThread, BOOLEAN Alert) {
    UNREFERENCED_PARAMETER(ProcessId);
    UNREFERENCED_PARAMETER(PeProcess);
    UNREFERENCED_PARAMETER(PeThread);
    UNREFERENCED_PARAMETER(Alert);

    NTSTATUS status;
    CHAR ProcessName[256] = { 0 };

    KdPrint(("[DllInject] Starting DLL injection for Process ID: %p\n", ProcessId));

    HANDLE hProcess;
    OBJECT_ATTRIBUTES objectAttributes = { sizeof(OBJECT_ATTRIBUTES) };
    CLIENT_ID clientId;

    InitializeObjectAttributes(&objectAttributes,
        NULL,
        OBJ_KERNEL_HANDLE,
        NULL,
        NULL);
    clientId.UniqueProcess = PsGetProcessId(PeProcess); ProcessId;
    clientId.UniqueThread = (HANDLE)0;

    KdPrint(("[DllInject] Attempting to open process: %p\n", ProcessId));
    status = ZwOpenProcess(&hProcess,
        PROCESS_ALL_ACCESS,
        &objectAttributes,
        &clientId);
    if (!NT_SUCCESS(status)) {
        KdPrint(("[DllInject] Error opening process: %p\n", ProcessId));
        return STATUS_NO_MEMORY;
    }
    KdPrint(("[DllInject] Successfully opened process: %p\n", ProcessId));

    CHAR DllFormatPath[] = "C:\\vEDR\\virtualhook.dll";
    SIZE_T Size = strlen(DllFormatPath) + 1;
    PVOID pvMemory = NULL;

    KdPrint(("[DllInject] Allocating memory in target process\n"));
    status = ZwAllocateVirtualMemory(hProcess, &pvMemory, 0, &Size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!(NT_SUCCESS(status))) {
        KdPrint(("[DllInject] Error allocating memory at: %p\n", pvMemory));
        ZwClose(hProcess);
        return STATUS_NO_MEMORY;
    }
    KdPrint(("[DllInject] Successfully allocated memory in target process\n"));

    KAPC_STATE KasState;
    PKAPC Apc;

    KeStackAttachProcess(PeProcess, &KasState);
    strcpy(pvMemory, DllFormatPath);
    KdPrint(("[DllInject] DLL path copied to allocated memory\n"));

    KdPrint(("[DllInject] Detatching from target process\n"));
    KeUnstackDetachProcess(&KasState);
    Apc = (PKAPC)ExAllocatePool(NonPagedPool, sizeof(KAPC));
    if (Apc) {
        KdPrint(("[DllInject] APC allocated; Initializing\n"));

        KeInitializeApc(Apc,
            PeThread,
            0,
            (PKKERNEL_ROUTINE)ApcKernelRoutine,
            0,
            (PKNORMAL_ROUTINE)pLoadLibraryExA,
            UserMode,
            pvMemory);
        KeInsertQueueApc(Apc, 0, 0, IO_NO_INCREMENT);
        KdPrint(("[DllInject] APC successfully queued\n"));
        return STATUS_SUCCESS;
    }
    KdPrint(("[DllInject] Failed to queue APC\n"));
    return STATUS_NO_MEMORY;


}

VOID WorkerRoutine(PVOID Context) {
    UNREFERENCED_PARAMETER(Context);

    DllInject(&((P_INJECTION_DATA)Context)->ProcessId, ((P_INJECTION_DATA)Context)->Process, ((P_INJECTION_DATA)Context)->Ethread, FALSE);
    KdPrint(("[WorkerRoutine] DLL injection complete; setting event\n"));

    KeSetEvent(&((P_INJECTION_DATA)Context)->Event, (KPRIORITY)0, FALSE);
    return;
}


VOID NTAPI ApcInjectorRoutine(PKAPC Apc, PKNORMAL_ROUTINE* NormalRoutine, PVOID* SystemArgument1, PVOID* SystemArgument2, PVOID* Context) {
    UNREFERENCED_PARAMETER(Apc);
    UNREFERENCED_PARAMETER(NormalRoutine);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);
    UNREFERENCED_PARAMETER(Context);

    KdPrint(("[APCInjectorRoutine] Starting APC injection routine\n"));

    INJECTION_DATA Id;

    RtlSecureZeroMemory(&Id, sizeof(INJECTION_DATA));
    ExFreePool(Apc);

    Id.Ethread = KeGetCurrentThread();
    Id.Process = IoGetCurrentProcess();

    KdPrint(("[APCInjectorRoutine] EThread: %p, Process: %p, Process ID: %p\n", Id.Ethread, Id.Process, Id.ProcessId));

    KeInitializeEvent(&Id.Event, NotificationEvent, FALSE);
    ExInitializeWorkItem(&Id.WorkItem, (PWORKER_THREAD_ROUTINE)WorkerRoutine, &Id);

    KdPrint(("[APCInjectorRoutine] Queuing work item\n"));
    ExQueueWorkItem(&Id.WorkItem, DelayedWorkQueue);
    KeWaitForSingleObject(&Id.Event, Executive, KernelMode, TRUE, 0);

    KdPrint(("[APCInjectorRoutine] SWork item completed\n"));
    return;

}


PVOID CustomGetProcAddress(PVOID pModuleBase, UNICODE_STRING functionName) {
    UNREFERENCED_PARAMETER(functionName);
    // Check PE header for magic bytes
    PIMAGE_DOS_HEADER ImageDosHeader = (PIMAGE_DOS_HEADER)pModuleBase;
    if (ImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return NULL;
    }
    // Check PE header for signature
    PIMAGE_NT_HEADERS ImageNtHeaders = ((PIMAGE_NT_HEADERS)(RtlOffsetToPointer(pModuleBase, ImageDosHeader->e_lfanew)));
    if (ImageNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return NULL;
    }
    // Check Optional Headers
    if (!(ImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress &&
        0 < ImageNtHeaders->OptionalHeader.NumberOfRvaAndSizes)) {
        return NULL;
    }
    // Get address of Export directory
    PIMAGE_EXPORT_DIRECTORY ImageExport = (((PIMAGE_EXPORT_DIRECTORY)(PUCHAR)RtlOffsetToPointer(pModuleBase, ImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress)));
    // Check for export directory
    if (!(ImageExport))
    {
        return NULL;
    }
    PULONG AddressOfNames = ((PULONG)RtlOffsetToPointer(pModuleBase, ImageExport->AddressOfNames));
    for (ULONG n = 0; n < ImageExport->NumberOfNames; ++n)
    {
        LPSTR FunctionName = ((LPSTR)RtlOffsetToPointer(pModuleBase, AddressOfNames[n]));
        if (strcmp("LoadLibraryExA", FunctionName) == 0) {
            PULONG AddressOfFunctions = ((PULONG)RtlOffsetToPointer(pModuleBase, ImageExport->AddressOfFunctions));
            PUSHORT AddressOfOrdinals = ((PUSHORT)RtlOffsetToPointer(pModuleBase, ImageExport->AddressOfNameOrdinals));

            PVOID pFnLoadLibraryExA = ((PVOID)RtlOffsetToPointer(pModuleBase, AddressOfFunctions[AddressOfOrdinals[n]]));

            KdPrint(("[CustomGetProcAddress] Found Function %s @ %p\n", FunctionName, pFnLoadLibraryExA));

            return pFnLoadLibraryExA;
        }
    }
    return NULL;
}

VOID LoadImageNotifyRoutine(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,                // Process into which the image is loaded
    _In_ PIMAGE_INFO ImageInfo            // Info about the image
) {
    UNREFERENCED_PARAMETER(FullImageName);
    UNREFERENCED_PARAMETER(ProcessId);
    UNREFERENCED_PARAMETER(ImageInfo);
    if (FullImageName == NULL) {
        return;
    }
    //check w rtlunicode if file is.exe 
    //initializes UNICODE_STRING structure w string ".exe".
    UNICODE_STRING exeEnding;
    //UNICODE_STRING is the kernel’s preferred way of handling wide-character strings instead regular wchar_t arrays.
    RtlInitUnicodeString(&exeEnding, L".exe");
    if (RtlSuffixUnicodeString(&exeEnding, FullImageName, TRUE)) {
        KdPrint(("LoadImageNotifyRoutine has detected the exe: %wZ for Process IDL %p\n",FullImageName,ProcessId));
    }

    //check if it is 64 bit exe looking into the file
    //ImageInfo->ImageBase is a pointer to the start of that memory region (the start of the file in memory).
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)ImageInfo->ImageBase;
    //e_magic = "MZ" (0x5A4D)         <--- IMAGE_DOS_SIGNATURE
    if (dosHeader->e_magic == IMAGE_DOS_SIGNATURE)
    {
        //e_lfanew = (offset to NT header)
        //The e_lfanew field in the DOS header tells you the offset (distance) from the start of the image to the NT headers.
        //To determine properties of the image (32-bit vs 64-bit, entry point, section info), you must read the NT headers.
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)ImageInfo->ImageBase + dosHeader->e_lfanew);
        //1. if (ntHeaders->Signature == IMAGE_NT_SIGNATURE)
        //IMAGE_NT_SIGNATURE is 0x00004550 (ASCII for "PE\0\0").
        //This ensures the file really has a valid NT header after the DOS header.
        if (ntHeaders->Signature == IMAGE_NT_SIGNATURE)
        {
            //IMAGE_FILE_MACHINE_AMD64 (0x8664) → 64-bit.
            //IMAGE_FILE_MACHINE_I386(0x14C) → 32 - bit x86.
            if (ntHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
            {
                KdPrint(("[LoadImageNotifyRoutine] x86 image detected: %wZ\n", FullImageName));
                return;
            }
        }
    }

    //check if imageloaded is Kernel32
    //This is often used with functions like FsRtlIsNameInExpression or RtlEqualUnicodeString (after converting to UNICODE_STRING) to do pattern matching.
    //They wrote it as an array because C doesn’t allow something like L"*\\KERNEL32.DLL"; to be directly used as a mutable WCHAR* without storage.
    WCHAR KERNEL32mask[] = L"*\\KERNEL32.DLL";
    UNICODE_STRING kernel32unicodestr;
    RtlInitUnicodeString(&kernel32unicodestr,KERNEL32mask);
    //FsRtlIsNameInExpression: This function checks whether a given UNICODE_STRING (in this case, ImageName) matches a wildcard pattern (kernel32unicodeString).
    if (!(FsRtlIsNameInExpression(&kernel32unicodestr, FullImageName, TRUE, NULL))) {
        return;
    }
    KdPrint(("[LoadImageNotifyRoutine] Kernel32.dll has load into process."));
    KdPrint(("[LoadImageNotifyRoutine] Attempt to resolve."));

    pLoadLibraryExA = CustomGetProcAddress((PVOID)ImageInfo->ImageBase, kernel32unicodestr);

    //In an EDR(Endpoint Detection & Response) driver, the use of an APC(Asynchronous Procedure Call) like this is typically for monitoring or interacting with user - mode processes, sometimes to :

    //Inject monitoring code(DLLs) into processes to track behaviors(e.g., API hooking or telemetry collection).

    //Run code in the context of the target process(e.g., scanning memory, intercepting calls).

    //Load specific user - mode components after key DLLs like Kernel32.dll are loaded
    PKAPC Apc;

    // Allocate memory for the APC structure from non-paged pool
    // Non-paged memory is always resident in RAM, which is necessary for kernel structures
    // KAPC (Kernel Asynchronous Procedure Call) is a Windows kernel structure used to schedule a callback function 
    // to run in the context of a specific thread, either in kernel or user mode. It acts as a mechanism for deferred 
    // execution, where the APC is queued to a thread and executed when the thread enters an alertable state or is 
    // running in kernel context. In EDR drivers, KAPCs are often used for tasks like injecting user-mode code (e.g., 
    // DLLs) into processes after critical DLLs such as Kernel32.dll are loaded, or for executing monitoring routines 
    // at safe points without disrupting normal kernel flow
    Apc = (PKAPC)ExAllocatePool(NonPagedPool, sizeof(KAPC));

    // Check if allocation failed
    if (!Apc) {
        // Log a failure message (driver debug output)
        KdPrint(("[LoadImageNotifyRoutine] Failed to allocate Apc.\n"));
        return;
    }

    // Log a message indicating we are preparing an APC
    // This APC will likely be used to queue a call into user-mode (e.g., for DLL injection or monitoring)
    KdPrint(("[LoadImageNotifyRoutine] Allocating and initializing APC for DLL injection.\n"));
    //This line is initializing a Kernel APC (Asynchronous Procedure Call) so it can later be queued for execution in the context of the current thread.
    KeInitializeApc(Apc, KeGetCurrentThread(), OriginalApcEnvironment, (PKKERNEL_ROUTINE)ApcInjectorRoutine, 0, 0, KernelMode, 0);

    if (KeInsertQueueApc(Apc, 0, 0, IO_NO_INCREMENT)) {
        KdPrint(("[LoadImageNotifyRoutine] APC successfully queued for DLL Injection.\n"));
    }
    else {
        KdPrint(("[LoadImageNotifyRoutine] Failed to queue APC for DLL injection.\n"));
    }

    return;
};

VOID NTAPI DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    PsRemoveLoadImageNotifyRoutine(&LoadImageNotifyRoutine);
    KdPrint(("Driver unloaded.\n"));
}

//NTSTATUS is just BOOL
//NTAPI is basically setting the function as __stdcall like this - NTSTATUS __stdcall MyFunction(...);


NTSTATUS NTAPI DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    //This macro is used to suppress compiler warnings when a function parameter is required by the function signature but isn't used in the function body.

    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    

    KdPrint(("Driver loaded successfully.\n"));
    
    NTSTATUS status = STATUS_SUCCESS; 
    
    KdPrint(("Registering LoadImageNotifyRoutine"));
    PsSetLoadImageNotifyRoutine(&LoadImageNotifyRoutine);

    // Optional: Set unload routine
    DriverObject->DriverUnload = DriverUnload;
    return STATUS_SUCCESS;
    
}

