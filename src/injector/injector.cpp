#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <cstdlib>

// Helper to check if a module is already loaded in the target process
bool IsModuleLoaded(DWORD pid, const std::string& moduleName) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (hSnap == INVALID_HANDLE_VALUE) return false;

    MODULEENTRY32 me32;
    me32.dwSize = sizeof(MODULEENTRY32);
    bool found = false;

    if (Module32First(hSnap, &me32)) {
        do {
            std::string currentModule;
            #ifdef UNICODE
            char modName[MAX_PATH];
            size_t c;
            wcstombs_s(&c, modName, MAX_PATH, me32.szModule, MAX_PATH);
            currentModule = modName;
            #else
            currentModule = me32.szModule;
            #endif

            // Case insensitive comparison
            std::string nameLower = moduleName;
            std::string currentLower = currentModule;
            std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), ::tolower);
            std::transform(currentLower.begin(), currentLower.end(), currentLower.begin(), ::tolower);

            // Check if the module name ends with our target name (handles full paths vs filenames)
            if (currentLower.find(nameLower) != std::string::npos) {
                found = true;
                break;
            }
        } while (Module32Next(hSnap, &me32));
    }
    CloseHandle(hSnap);
    return found;
}

// Helper to check file existence
bool FileExists(const std::string& name) {
    DWORD attrib = GetFileAttributesA(name.c_str());
    return (attrib != INVALID_FILE_ATTRIBUTES && !(attrib & FILE_ATTRIBUTE_DIRECTORY));
}

void EnableDebugPrivilege() {
    HANDLE hToken;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        LUID luid;
        if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
            TOKEN_PRIVILEGES tp;
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
        }
        CloseHandle(hToken);
    }
}

bool InjectLibrary(DWORD pid, const std::string& library_path) {
    EnableDebugPrivilege();

    if (!FileExists(library_path)) {
        std::cerr << "Library not found: " << library_path << std::endl;
        return false;
    }

    // Check if already injected
    std::string libName = library_path.substr(library_path.find_last_of("\\/") + 1);
    if (IsModuleLoaded(pid, libName)) {
        std::cerr << "Library already loaded in process." << std::endl;
        return true; // Already success
    }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        std::cerr << "OpenProcess failed. Error: " << GetLastError() << std::endl;
        return false;
    }

    // Allocate memory for path
    size_t pathLen = library_path.size() + 1;
    void* remotePath = VirtualAllocEx(hProcess, NULL, pathLen, MEM_COMMIT, PAGE_READWRITE);
    if (!remotePath) {
        std::cerr << "VirtualAllocEx failed. Error: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return false;
    }

    // Write path
    if (!WriteProcessMemory(hProcess, remotePath, library_path.c_str(), pathLen, NULL)) {
        std::cerr << "WriteProcessMemory failed. Error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // LoadLibraryA address (kernel32.dll is mapped at same address in all processes usually)
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    FARPROC pLoadLibrary = GetProcAddress(hKernel32, "LoadLibraryA");

    // Create Thread
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibrary, remotePath, 0, NULL);
    if (!hThread) {
        std::cerr << "CreateRemoteThread failed. Error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // Wait for thread
    WaitForSingleObject(hThread, INFINITE);

    // Check exit code
    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);
    if (exitCode == 0) {
        std::cerr << "LoadLibraryA failed in remote process." << std::endl;
    }

    // Cleanup
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    return (exitCode != 0);
}
