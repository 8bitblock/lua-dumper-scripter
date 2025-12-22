#include "ProcessManager.h"
#include <tlhelp32.h>
#include <cstdlib>

std::vector<ProcessInfo> ProcessManager::GetProcesses() {
    std::vector<ProcessInfo> list;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return list;

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hSnap, &pe32)) {
        do {
            #ifdef UNICODE
            char name[MAX_PATH];
            size_t c;
            wcstombs_s(&c, name, MAX_PATH, pe32.szExeFile, MAX_PATH);
            list.push_back({ pe32.th32ProcessID, std::string(name) });
            #else
            list.push_back({ pe32.th32ProcessID, std::string(pe32.szExeFile) });
            #endif
        } while (Process32Next(hSnap, &pe32));
    }
    CloseHandle(hSnap);
    return list;
}
