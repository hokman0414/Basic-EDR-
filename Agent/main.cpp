#include <windows.h>
#include <stdio.h>
#include <threads.h>
#include <iostream>
#include <thread>
bool LoadService(const std::string& szServiceName, const std::string& szServiceDisplayName, const std::string& szServiceFile) {
    SC_HANDLE hSCManager = nullptr;
    SC_HANDLE hService = nullptr;

    hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!hSCManager) {
        printf("[!] OpenSCManager failed! Error: %ld\n", GetLastError());
        CloseServiceHandle(hSCManager);
        return false;
    }

    hService = CreateServiceA(hSCManager, szServiceName.c_str(), szServiceDisplayName.c_str(), SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER,
        SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, szServiceFile.c_str(), NULL, NULL, NULL, NULL, NULL);
    if (!hService) {
        printf("[!] CreateServiceA failed! Error: %ld\n", GetLastError());
        CloseServiceHandle(hSCManager);
        CloseServiceHandle(hService);
        return false;
    }
    return true;
}

bool StartKernelService(const std::string& szServiceName) {
    SC_HANDLE hSCManager = nullptr;
    SC_HANDLE hService = nullptr;

    hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCManager) {
        printf("[!] OpenSCManager failed! Error: %ld\n", GetLastError());
        CloseServiceHandle(hSCManager);
        return false;
    }

    hService = OpenServiceA(hSCManager, szServiceName.c_str(), SERVICE_START | SERVICE_QUERY_STATUS);
    if (!hService) {
        printf("[!] OpenServiceA failed! Error: %ld\n", GetLastError());
        CloseServiceHandle(hSCManager);
        CloseServiceHandle(hService);
        return false;
    }

    if (StartServiceA(hService, 0, NULL) == FALSE) {
        printf("[!] StartServiceA failed! Error: %ld\n", GetLastError());
        CloseServiceHandle(hSCManager);
        CloseServiceHandle(hService);
        return false;
    }

    return true;

}


void HandleClientConnection(HANDLE hPipe) {
    char buffer[512];
    DWORD bytesRead;

    while (true) {
        BOOL success = ReadFile(hPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL);
        if (!success || bytesRead == 0)
            break;

        buffer[bytesRead] = '\0';  // Null-terminate
        std::cout << "[Pipe] " << buffer << std::endl;
    }

    FlushFileBuffers(hPipe);
    DisconnectNamedPipe(hPipe);
    CloseHandle(hPipe);  //  Only closed here — owned by thread
}

void StartNamedPipeServer() {
    // Security attributes (SECURITY_ATTRIBUTES) are set so the named pipe can control 
    // which processes/users have access. Here, a NULL DACL is used, which means "allow 
    // everyone full access," useful for testing or inter-process communication but not 
    // secure for production EDRs where a restricted DACL should be applied.

    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = (PSECURITY_DESCRIPTOR)malloc(SECURITY_DESCRIPTOR_MIN_LENGTH);
    sa.bInheritHandle = TRUE;

    if (!InitializeSecurityDescriptor(sa.lpSecurityDescriptor, SECURITY_DESCRIPTOR_REVISION)) {
        printf("[!] Failed to initialize security descriptor!\n");
        return;
    }

    if (!SetSecurityDescriptorDacl(sa.lpSecurityDescriptor, TRUE, (PACL)NULL, FALSE)) {
        printf("[!] Failed to set security descriptor DACL!\n");
        return;
    }


    const wchar_t* pipeName = L"\\\\.\\pipe\\PoopAgent";


    while (true) {
        HANDLE hPipe = CreateNamedPipeW(
            pipeName,
            PIPE_ACCESS_INBOUND,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_BYTE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            0, 0, 0, NULL
        );

        if (hPipe == INVALID_HANDLE_VALUE) {
            // Fails silently without crashing host
            MessageBoxA(nullptr, "CRASHED UNABLE TO GENERATE NAMED PIPE", "Hook Alert", MB_OK | MB_ICONINFORMATION);

            break;
        }

        BOOL isConnected = ConnectNamedPipe(hPipe, NULL) ||
         GetLastError() == ERROR_PIPE_CONNECTED;
           
        printf("Waiting on Client Connection.... ");
        if (isConnected) {
            //  Handler thread takes ownership of hPipe
            printf("Successfully Created Named Pipe.....");
            std::thread(HandleClientConnection, hPipe).detach();
        }
        else {
            //  Only close if connect failed and thread wasn't created
            CloseHandle(hPipe);
        }
    }
}


bool FileExists(const std::string& path) {
    DWORD attributes = GetFileAttributesA(path.c_str());
    return (attributes != INVALID_FILE_ATTRIBUTES &&
        !(attributes & FILE_ATTRIBUTE_DIRECTORY));
}

int main(int argc, char* argv[]) {
    BOOL eKernel = FALSE;
    if (argc == 2 && std::string(argv[1]) == "kernel") {
        eKernel = TRUE;
    }
    else {
        eKernel = FALSE;
    }

    if (eKernel) {

        //preset up for driver file in Agent to deploy kernel Driver
        std::string DriverFile = "C:\\Users\\Calvi\\source\\repos\\EDR\\x64\\Debug\\VDriver.sys";
        std::string serviceName = "EDR Driver";
        //check f file exist
        if (!FileExists(DriverFile)) {
            printf("[!] Driver file %s does not exist!\n", DriverFile.c_str());
            return 0;
        }

        printf("[+] Driver: %s\n", DriverFile.c_str());
        printf("[+] Service Name: %s\n", serviceName.c_str());

        printf("[+] Attempting to start vEDR kernel service: %s\n", serviceName.c_str());
        if (LoadService(serviceName, serviceName, DriverFile) == FALSE) {
            printf("[!] An error occured loading kernel service!\n");
        }
        if (StartKernelService(serviceName) == FALSE) {
            printf("[!] An error occured starting kernel service!\n");
        }
    }
    printf("EDR Driver loaded and running!\n");
   
	printf("Starting Named Pipe server...\n");
    //start named pipe server
    StartNamedPipeServer();
}