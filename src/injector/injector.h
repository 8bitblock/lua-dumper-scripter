#pragma once
#include <string>
#include <windows.h>

// Injects the DLL at library_path into the process with the given pid.
// Returns true on success (exit code of thread is non-zero), false otherwise.
bool InjectLibrary(DWORD pid, const std::string& library_path);
