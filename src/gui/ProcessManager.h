#pragma once
#include <string>
#include <vector>
#include <windows.h>

struct ProcessInfo {
    DWORD pid;
    std::string name;
};

class ProcessManager {
public:
    static std::vector<ProcessInfo> GetProcesses();
};
