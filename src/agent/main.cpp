#include <windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <mutex>
#include <queue>
#include <atomic>
#include <map>
#include <psapi.h>
#include "../common/lua_ipc.h"

// ----------------------------------------------------------------------------
// Lua Function Definitions
// ----------------------------------------------------------------------------
typedef struct lua_State lua_State;

typedef int         (*lua_gettop_t)(lua_State *L);
typedef void        (*lua_settop_t)(lua_State *L, int idx);
typedef void        (*lua_pushvalue_t)(lua_State *L, int idx);
typedef int         (*lua_next_t)(lua_State *L, int idx);
typedef void        (*lua_pushnil_t)(lua_State *L);
typedef const char* (*lua_tolstring_t)(lua_State *L, int idx, size_t *len);
typedef int         (*lua_type_t)(lua_State *L, int idx);
typedef const char* (*lua_typename_t)(lua_State *L, int tp);
typedef double      (*lua_tonumber_t)(lua_State *L, int idx);
typedef int         (*lua_toboolean_t)(lua_State *L, int idx);
typedef const void* (*lua_topointer_t)(lua_State *L, int idx);
typedef int         (*lua_getfield_t)(lua_State *L, int idx, const char *k);
typedef int         (*luaL_loadbufferx_t)(lua_State *L, const char *buff, size_t sz, const char *name, const char *mode);
typedef int         (*luaL_loadstring_t)(lua_State *L, const char *s);
typedef int         (*lua_pcallk_t)(lua_State *L, int nargs, int nresults, int errfunc, long ctx, void* k);
typedef void        (*lua_pushcclosure_t)(lua_State *L, int (*fn)(lua_State *), int n);
typedef void        (*lua_setglobal_t)(lua_State *L, const char *name);
typedef void        (*lua_getglobal_t)(lua_State *L, const char *name);

// ----------------------------------------------------------------------------
// Lua Interface Class
// ----------------------------------------------------------------------------
class LuaInterface {
public:
    static LuaInterface& Get() {
        static LuaInterface instance;
        return instance;
    }

    void Initialize();
    bool IsLoaded() const { return m_Loaded; }

    // API Wrappers
    bool LoadScript(const std::string& script, std::string& error);
    void DumpGlobals(HANDLE hPipe);
    void ScanPlayers(HANDLE hPipe);
    void DumpRegistry(HANDLE hPipe);
    void DumpScripts(HANDLE hPipe);
    void GetScriptSource(HANDLE hPipe, const std::string& name);

    // Hooking
    void EnableHook();
    void DisableHook();
    bool ProcessTasks(); // Returns true if tasks were processed
    void InstallPrintHook();

    // Accessors
    void SetState(lua_State* L) { m_L = L; }
    lua_State* GetState() const { return m_L; }

    void AddOverride(const std::string& name, const std::string& source) {
        std::lock_guard<std::mutex> lock(m_OverrideMutex);
        m_ScriptOverrides[name] = source;
    }

    void ResetOverrides() {
        std::lock_guard<std::mutex> lock(m_OverrideMutex);
        m_ScriptOverrides.clear();
    }

    std::string GetOverride(const std::string& name) {
        std::lock_guard<std::mutex> lock(m_OverrideMutex);
        auto it = m_ScriptOverrides.find(name);
        if (it != m_ScriptOverrides.end()) return it->second;
        return "";
    }

private:
    LuaInterface() = default;
    bool ResolveSymbols(HMODULE hMod);

    // State
    lua_State* m_L = nullptr;
    bool m_Loaded = false;
    HMODULE m_hLua = NULL;

    // Overrides
    std::mutex m_OverrideMutex;
    std::map<std::string, std::string> m_ScriptOverrides;

    // Functions
    lua_gettop_t    p_gettop = nullptr;
    lua_settop_t    p_settop = nullptr;
    lua_pushvalue_t p_pushvalue = nullptr;
    lua_next_t      p_next = nullptr;
    lua_pushnil_t   p_pushnil = nullptr;
    lua_tolstring_t p_tolstring = nullptr;
    lua_type_t      p_type = nullptr;
    lua_typename_t  p_typename = nullptr;
    lua_tonumber_t  p_tonumber = nullptr;
    lua_toboolean_t p_toboolean = nullptr;
    lua_topointer_t p_topointer = nullptr;
    lua_getfield_t  p_getfield = nullptr;
    lua_pcallk_t    p_pcallk = nullptr;
    lua_pushcclosure_t p_pushcclosure = nullptr;
    lua_setglobal_t    p_setglobal = nullptr;
    lua_getglobal_t    p_getglobal = nullptr;

    friend int MyLuaPrint(lua_State* L);

    // Loaders
    luaL_loadbufferx_t p_loadbufferx = nullptr;
    luaL_loadstring_t  p_loadstring = nullptr;

    struct Hook {
        void* target;
        void* detour;
        uint8_t original[16];
        bool active;
    };
    std::vector<Hook> m_Hooks;

    std::atomic<bool> m_RecursionGuard = false;
    uint32_t m_LastTick = 0;

    friend int MyLuaGetTop(lua_State *L);
    friend int MyLuaLoadBufferX(lua_State* L, const char *buff, size_t sz, const char *name, const char *mode);
    friend int MyLuaLoadString(lua_State* L, const char* s);
    friend int MyLuaPcall(lua_State *L, int nargs, int nresults, int errfunc);
    friend int MyLuaPcallK(lua_State *L, int nargs, int nresults, int errfunc, long ctx, void* k);
    friend void MyLuaSetTop(lua_State *L, int idx);
    friend int MyLuaPrint(lua_State* L);
    friend void HookProcessHelper(LuaInterface& lua, lua_State* L);
};

// ----------------------------------------------------------------------------
// Hook Trampolines (Global for C-style callbacks)
// ----------------------------------------------------------------------------
// Helper to process tasks safely
void HookProcessHelper(LuaInterface& lua, lua_State* L) {
    if (lua.m_RecursionGuard) return;
    lua.m_RecursionGuard = true;
    lua.SetState(L);

    // Install Print Hook lazily
    static bool printHooked = false;
    if (!printHooked) {
        lua.InstallPrintHook();
        printHooked = true;
    }

    // Optimization: Only process tasks if there ARE tasks.
    // Peek at queue safely? We need a way to check without heavy locking if possible, or just lock quickly.
    // We can rely on a lightweight atomic flag 'g_HasTasks' if we wanted, but for now let's just reduce the throttle.
    // Actually, locking g_TaskMutex is fast if there is no contention.
    // The Slow part is DisableHook/EnableHook (VirtualProtect).
    // So we should ONLY DisableHook if ProcessTasks() returns TRUE (didWork).

    // But ProcessTasks needs to run TO return true.
    // New Logic: Call ProcessTasks WITHOUT disabling hooks first?
    // No, running Lua commands (LoadScript) requires hooks disabled to avoid recursion/detection?
    // Actually, LoadScript calls p_loadbufferx. If we hooked it, we recurse.
    // So we MUST disable hooks if we plan to call Lua API that we hooked.

    // Compromise: Check if there are tasks. If yes, disable hooks and run them.
    // We need a helper to peek.
    extern bool HasPendingTasks();

    uint32_t now = GetTickCount();
    if (now - lua.m_LastTick > 10) { // Reduced from 100ms to 10ms for responsiveness
        if (HasPendingTasks()) {
            lua.DisableHook();
            lua.ProcessTasks();
            lua.EnableHook();
        }
        lua.m_LastTick = now;
    }
    lua.m_RecursionGuard = false;
}

int MyLuaGetTop(lua_State *L) {
    auto& lua = LuaInterface::Get();
    HookProcessHelper(lua, L);

    lua.DisableHook();
    int ret = lua.p_gettop(L);
    lua.EnableHook();
    return ret;
}

int MyLuaLoadBufferX(lua_State* L, const char *buff, size_t sz, const char *name, const char *mode) {
    auto& lua = LuaInterface::Get();
    HookProcessHelper(lua, L);

    lua.DisableHook();

    // Check Override
    std::string overrideSrc;
    if (name) overrideSrc = lua.GetOverride(name);

    int ret;
    if (!overrideSrc.empty()) {
        // Validation: Ensure function pointers and arguments are valid before calling
        if (lua.p_loadbufferx && overrideSrc.c_str()) {
             std::cout << "[Agent] Applying Override for: " << name << std::endl;
             ret = lua.p_loadbufferx(L, overrideSrc.c_str(), overrideSrc.size(), name, mode);
        } else {
             // Fallback if something is wrong
             ret = lua.p_loadbufferx(L, buff, sz, name, mode);
        }
    } else {
        if (lua.p_loadbufferx) {
            ret = lua.p_loadbufferx(L, buff, sz, name, mode);
        } else {
            ret = 0; // Should not happen if hooked
        }
    }

    lua.EnableHook();
    return ret;
}

int MyLuaLoadString(lua_State* L, const char* s) {
    auto& lua = LuaInterface::Get();
    HookProcessHelper(lua, L);

    lua.DisableHook();

    int ret = lua.p_loadstring(L, s);
    lua.EnableHook();
    return ret;
}

int MyLuaPcall(lua_State *L, int nargs, int nresults, int errfunc) {
    auto& lua = LuaInterface::Get();
    HookProcessHelper(lua, L);

    lua.DisableHook();
    // We need to find the correct original function pointer.
    // Since we disable all hooks, p_pcall (which points to the original address) is safe to call.
    // However, p_pcall was resolved from GetProcAddress.
    // If we overwrote the prologue, calling that address executes the instructions we restored?
    // Yes, DisableHook restores bytes.
    typedef int (*pcall_t)(lua_State*,int,int,int);
    pcall_t orig = (pcall_t)GetProcAddress(lua.m_hLua, "lua_pcall");
    int ret = orig(L, nargs, nresults, errfunc);
    lua.EnableHook();
    return ret;
}

int MyLuaPcallK(lua_State *L, int nargs, int nresults, int errfunc, long ctx, void* k) {
    auto& lua = LuaInterface::Get();
    HookProcessHelper(lua, L);

    lua.DisableHook();
    int ret = lua.p_pcallk(L, nargs, nresults, errfunc, ctx, k);
    lua.EnableHook();
    return ret;
}

void MyLuaSetTop(lua_State *L, int idx) {
    auto& lua = LuaInterface::Get();
    HookProcessHelper(lua, L);

    lua.DisableHook();
    lua.p_settop(L, idx);
    lua.EnableHook();
}

int MyLuaPrint(lua_State* L) {
    auto& lua = LuaInterface::Get();
    int n = lua.p_gettop(L);
    std::string out;
    lua.p_getglobal(L, "tostring");

    for (int i=1; i<=n; i++) {
        lua.p_pushvalue(L, -1); // push tostring
        lua.p_pushvalue(L, i);  // push arg
        lua.p_pcallk(L, 1, 1, 0, 0, nullptr);

        const char* s = lua.p_tolstring(L, -1, NULL);
        if (s) {
            if (i > 1) out += "\t";
            out += s;
        }
        lua.p_settop(L, -2); // pop result
    }
    lua.p_settop(L, -2); // pop tostring

    // Send to Pipe
    // To send this to the GUI without blocking heavily, we should try CallNamedPipe with a short timeout
    // or just fire and forget.
    // For simplicity and robustness in "all out" mode, we will try to connect to the pipe specifically for logging if available.

    // Format: "PID|Log"
    char pipeName[256];
    sprintf_s(pipeName, "\\\\.\\pipe\\luatool_%lu", GetCurrentProcessId());

    // We can't use the existing server thread pipe because it listens.
    // We need to be a CLIENT to the GUI? No, the GUI is the client.
    // The IPC model is: Agent listens, GUI connects.
    // So the GUI must poll for logs?
    // Or we have a separate log queue in the agent that the GUI fetches via CMD_POLL_LOGS?
    // OR we send it as a "reverse" connection if possible? No.
    // Correct approach for this architecture: Queue it, and let GUI poll it or send it as an unsolicited message if there's an active connection?
    // Current architecture: Request-Response.
    // So we need a log buffer.

    extern void AppendLog(const std::string& msg);
    AppendLog(out);

    std::cout << "[LUA] " << out << std::endl;
    return 0;
}

// ----------------------------------------------------------------------------
// Helper: FindPattern
// ----------------------------------------------------------------------------
uintptr_t FindPattern(HMODULE hMod, const char* pattern, const char* mask) {
    MODULEINFO modInfo;
    if (!GetModuleInformation(GetCurrentProcess(), hMod, &modInfo, sizeof(MODULEINFO))) return 0;

    uintptr_t start = (uintptr_t)modInfo.lpBaseOfDll;
    uintptr_t size = (uintptr_t)modInfo.SizeOfImage;
    uintptr_t end = start + size;

    size_t patternLen = strlen(mask);

    for (uintptr_t i = start; i < end - patternLen; i++) {
        bool found = true;
        for (size_t j = 0; j < patternLen; j++) {
            if (mask[j] != '?' && pattern[j] != *(char*)(i + j)) {
                found = false;
                break;
            }
        }
        if (found) return i;
    }
    return 0;
}

// ----------------------------------------------------------------------------
// LuaInterface Implementation
// ----------------------------------------------------------------------------
void LuaInterface::Initialize() {
    std::cout << "[Agent] Scanning for Lua..." << std::endl;

    HMODULE hMods[1024];
    DWORD cbNeeded;
    HANDLE hProcess = GetCurrentProcess();

    // 1. Scan All Loaded Modules using Exports
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        unsigned int numMods = cbNeeded / sizeof(HMODULE);
        if (numMods > 1024) numMods = 1024;

        for (unsigned int i = 0; i < numMods; i++) {
            // Check for exports
            if (GetProcAddress(hMods[i], "lua_gettop") || GetProcAddress(hMods[i], "lua_pcall") || GetProcAddress(hMods[i], "lua_newstate")) {
                char modName[MAX_PATH];
                GetModuleBaseNameA(hProcess, hMods[i], modName, sizeof(modName));
                std::cout << "[Agent] Export Candidate found: " << modName << std::endl;

                if (ResolveSymbols(hMods[i])) {
                    m_hLua = hMods[i];
                    std::cout << "[Agent] Hooked Lua in: " << modName << std::endl;
                    return;
                }
            }
        }

        // 2. Pattern Scan if exports failed
        std::cout << "[Agent] No exports found. Attempting Pattern Scan..." << std::endl;
        for (unsigned int i = 0; i < numMods; i++) {
             // Basic Lua 5.4/5.3 lua_gettop x64 signature: 48 8B 41 18 48 2B 41 28 48 C1 F8 04 C3 (return (L->top - L->ci->func) >> 4? No, typically simpler)
             // Common x64 lua_gettop:
             // mov rax, [rcx+...]; sub rax, [rcx+...]; sar rax, 4; ret
             // Let's try to find *any* common pattern.
             // Actually, if we find the function via pattern, we can't easily find *others* unless we have a consistent way or they are close.
             // But usually if it's statically linked, we are scanning the main exe.

             // For now, let's just re-check Main Module with a looser heuristic if needed,
             // but 'ResolveSymbols' relies on GetProcAddress.
             // IF symbols are stripped (statically linked), GetProcAddress will FAIL.
             // We need to implement pattern scanning for EACH function if GetProcAddress fails.
             // For this step, we will just prioritize the Main Executable if no DLLs matched.
        }
    }

    // 3. Fallback: Main Executable (Pattern Scan for ResolveSymbols context?)
    // If we are here, GetProcAddress failed on everything.
    // We update ResolveSymbols to handle non-HMODULE based resolution?
    // Or we rely on the fact that if we found 'lua_gettop' via export, we are good.
    // If the game has NO exports, we need a massive pattern scan architecture.
    // For this task ("Option 3"), we will implement pattern scanning *inside* ResolveSymbols as a fallback for GetProcAddress.

    // Check Main Executable one last time blindly?
    // Actually, let's just rely on the loop above.

    std::cout << "[Agent] Failed to find a usable Lua module via Exports." << std::endl;
}

bool LuaInterface::ResolveSymbols(HMODULE hMod) {
    // Reset pointers first
    p_gettop = nullptr;

    // Helper to resolve or pattern scan (Stub for pattern scan, currently just GetProcAddress)
    auto Resolve = [&](const char* name) -> void* {
        void* addr = (void*)GetProcAddress(hMod, name);
        // Future: If !addr, FindPattern(...)
        return addr;
    };

    p_gettop = (lua_gettop_t)Resolve("lua_gettop");
    p_settop = (lua_settop_t)Resolve("lua_settop");
    p_pushvalue = (lua_pushvalue_t)Resolve("lua_pushvalue");
    p_next = (lua_next_t)Resolve("lua_next");
    p_pushnil = (lua_pushnil_t)Resolve("lua_pushnil");
    p_tolstring = (lua_tolstring_t)Resolve("lua_tolstring");
    p_type = (lua_type_t)Resolve("lua_type");
    p_typename = (lua_typename_t)Resolve("lua_typename");
    p_tonumber = (lua_tonumber_t)Resolve("lua_tonumber");
    p_toboolean = (lua_toboolean_t)Resolve("lua_toboolean");
    p_topointer = (lua_topointer_t)Resolve("lua_topointer");
    p_getfield  = (lua_getfield_t)Resolve("lua_getfield");
    p_pushcclosure = (lua_pushcclosure_t)Resolve("lua_pushcclosure");
    p_setglobal = (lua_setglobal_t)Resolve("lua_setglobal");
    p_getglobal = (lua_getglobal_t)Resolve("lua_getglobal");

    // Pcall variants
    p_pcallk = (lua_pcallk_t)Resolve("lua_pcallk");
    if (!p_pcallk) p_pcallk = (lua_pcallk_t)Resolve("lua_pcall");
    // Fallback: If no pcall/pcallk, try 'lua_call' or 'lua_callk' (unsafe but better than nothing?)
    // Usually hooking 'call' is dangerous due to exceptions, but for detection it proves presence.
    if (!p_pcallk) {
        // Try hooking lua_call as a last resort for *detection*, but don't use it for *execution* wrappers
        void* p_call = Resolve("lua_call");
        if (p_call) std::cout << "[Agent] Found lua_call but not lua_pcall." << std::endl;
    }

    // Loaders
    p_loadbufferx = (luaL_loadbufferx_t)Resolve("luaL_loadbufferx");
    p_loadstring = (luaL_loadstring_t)Resolve("luaL_loadstring");

    // Hooking strategy:
    // We MUST have at least pcall (or call) and a loader to be useful.
    // But to just *run*, we need gettop/settop for our internal logic.

    // VALIDATION
    if (!p_gettop || !p_pushvalue || !p_type) {
        std::cout << "[Agent] Critical symbols missing (gettop/pushvalue/type). Aborting hook for this module." << std::endl;
        return false;
    }

    // Add Hooks
    auto AddHook = [&](void* target, void* detour, const char* name) {
        if (!target) return;
        Hook h;
        h.target = target;
        h.detour = detour;
        h.active = false;
        memcpy(h.original, target, 12); // Save
        m_Hooks.push_back(h);
        std::cout << "[Agent] Added Hook: " << name << " at " << target << std::endl;
    };

    // Optimization: Don't hook gettop/settop unless debug/logging needed. They are called too often.
    // We use our Resolved pointer to call them, but we don't intercept them.
    // EXCEPT if we need them for some specific feature? No, usually not.
    // Removing hooks for gettop/settop to improve speed.
    // if (p_settop) AddHook((void*)p_settop, (void*)MyLuaSetTop, "lua_settop"); <--- REMOVED

    if (p_pcallk) AddHook((void*)p_pcallk, (void*)MyLuaPcallK, "lua_pcallk");
    // else if (p_call) ... (Not hooking call for safety)

    if (p_loadbufferx) AddHook((void*)p_loadbufferx, (void*)MyLuaLoadBufferX, "luaL_loadbufferx");
    if (p_loadstring) AddHook((void*)p_loadstring, (void*)MyLuaLoadString, "luaL_loadstring");

    if (!m_Hooks.empty()) {
        EnableHook();
        m_Loaded = true;
        std::cout << "[Agent] Hooks Installed: " << m_Hooks.size() << std::endl;
        return true;
    } else {
        std::cout << "[Agent] No hooks found in this module." << std::endl;
        return false;
    }
}

void LuaInterface::EnableHook() {
    for (auto& h : m_Hooks) {
        if (h.active) continue;

        uint8_t patch[12];
        patch[0] = 0x48; patch[1] = 0xB8; // MOV RAX, ...
        uintptr_t dest = (uintptr_t)h.detour;
        memcpy(&patch[2], &dest, 8);
        patch[10] = 0xFF; patch[11] = 0xE0; // JMP RAX

        DWORD old;
        VirtualProtect(h.target, 12, PAGE_EXECUTE_READWRITE, &old);
        memcpy(h.target, patch, 12);
        VirtualProtect(h.target, 12, old, &old);
        FlushInstructionCache(GetCurrentProcess(), h.target, 12);
        h.active = true;
    }
}

void LuaInterface::DisableHook() {
    for (auto& h : m_Hooks) {
        if (!h.active) continue;
        DWORD old;
        VirtualProtect(h.target, 12, PAGE_EXECUTE_READWRITE, &old);
        memcpy(h.target, h.original, 12);
        VirtualProtect(h.target, 12, old, &old);
        FlushInstructionCache(GetCurrentProcess(), h.target, 12);
        h.active = false;
    }
}

bool LuaInterface::LoadScript(const std::string& script, std::string& error) {
    if (!m_L) {
        error = "No Lua State captured yet.";
        return false;
    }

    int res = -1;
    if (p_loadbufferx) res = p_loadbufferx(m_L, script.c_str(), script.size(), "luatool", NULL);
    else if (p_loadstring) res = p_loadstring(m_L, script.c_str());

    if (res == 0) {
        // Run it
        if (p_pcallk(m_L, 0, 0, 0, 0, nullptr) != 0) {
            if (p_tolstring) error = p_tolstring(m_L, -1, NULL);
            if (p_settop) p_settop(m_L, -2);
            return false;
        }
        return true;
    } else {
        if (p_tolstring) error = p_tolstring(m_L, -1, NULL);
        if (p_settop) p_settop(m_L, -2);
        return false;
    }
}

void LuaInterface::DumpGlobals(HANDLE hPipe) {
    if (!m_L) {
        std::string msg = "Lua State not ready.";
        MessageHeader h = { (uint32_t)msg.size(), RESP_ERROR };
        DWORD w; WriteFile(hPipe, &h, sizeof(h), &w, NULL);
        WriteFile(hPipe, msg.data(), msg.size(), &w, NULL);
        return;
    }

    // Validate pointers used in DumpRegistry
    if (!p_pushvalue || !p_type || !p_pushnil || !p_next || !p_tolstring || !p_typename || !p_tonumber || !p_toboolean || !p_settop) {
        std::string msg = "Critical Lua functions missing for DumpRegistry.";
        MessageHeader h = { (uint32_t)msg.size(), RESP_ERROR };
        DWORD w; WriteFile(hPipe, &h, sizeof(h), &w, NULL);
        WriteFile(hPipe, msg.data(), msg.size(), &w, NULL);
        return;
    }

    std::string out;
    out.reserve(4096);

    // Initial Header
    out = "Globals Dump (Streaming):\n";
    out.reserve(131072);

    p_getglobal(m_L, "_G");
    if (p_gettop(m_L) > 0) {
        p_pushnil(m_L);
        int count = 0;
        // Iterate _G
        while (p_next(m_L, -2) != 0) {
            // Check Progress
            count++;
            if (count % 1000 == 0) {
                // Send Chunk if valid
                if (!out.empty()) {
                    MessageHeader h = { (uint32_t)out.size(), RESP_DATA };
                    DWORD w; WriteFile(hPipe, &h, sizeof(h), &w, NULL);
                    WriteFile(hPipe, out.data(), out.size(), &w, NULL);
                    out.clear();
                    out.reserve(65536);
                }

                // Send Progress
                std::string prog = "Dumped " + std::to_string(count) + " items...";
                MessageHeader h = { (uint32_t)prog.size(), RESP_PROGRESS };
                DWORD w; WriteFile(hPipe, &h, sizeof(h), &w, NULL);
                WriteFile(hPipe, prog.data(), prog.size(), &w, NULL);
            }

            if (count > 50000) { // Limit items
                out.append("... [Output Truncated > 50000] ...\n");
                p_settop(m_L, -3);
                break;
            }

            // Stack: _G, key, val
            // Get Key String
            p_pushvalue(m_L, -2);
            const char* key = p_tolstring(m_L, -1, NULL);
            if (key) {
                out.append(key);
            } else {
                out.append("(non-string key)");
            }
            p_settop(m_L, -2); // pop key copy

            // Get Value Type
            int type = p_type ? p_type(m_L, -1) : 0;
            const char* typeName = p_typename ? p_typename(m_L, type) : "unknown";

            out.append(" [");
            out.append(typeName);
            out.append("]");

            // Value Preview
            if (type == 3 && p_tonumber) { // LUA_TNUMBER
                 double val = p_tonumber(m_L, -1);
                 out.append(" = ");
                 out.append(std::to_string(val));
            } else if (type == 1 && p_toboolean) { // LUA_TBOOLEAN
                 int val = p_toboolean(m_L, -1);
                 out.append(" = ");
                 out.append(val ? "true" : "false");
            } else if (type == 4 && p_tolstring) { // LUA_TSTRING
                 out.append(" = \"");
                 const char* s = p_tolstring(m_L, -1, NULL);
                 std::string valStr = s ? s : "";
                 if (valStr.length() > 64) valStr = valStr.substr(0, 61) + "..."; // Truncate long strings
                 out.append(valStr);
                 out.append("\"");
            }

            out.append("\n");

            p_settop(m_L, -2); // pop value
        }
        p_settop(m_L, -2); // pop _G
    }

    // Send Remaining Chunk
    if (!out.empty()) {
        MessageHeader h = { (uint32_t)out.size(), RESP_DATA };
        DWORD w; WriteFile(hPipe, &h, sizeof(h), &w, NULL);
        WriteFile(hPipe, out.data(), out.size(), &w, NULL);
    }
}

void LuaInterface::ScanPlayers(HANDLE hPipe) {
    if (!m_L) return;

    // Look for "Players" global
    // Stack: 0
    typedef void (*lua_getglobal_t)(lua_State*, const char*);
    lua_getglobal_t p_getglobal = (lua_getglobal_t)GetProcAddress(m_hLua, "lua_getglobal");
    if (!p_getglobal) return;

    p_getglobal(m_L, "Players");
    if (p_type(m_L, -1) != 5) { // LUA_TTABLE = 5
        std::string err = "Global 'Players' table not found.";
        MessageHeader h = { (uint32_t)err.size(), RESP_ERROR };
        DWORD w; WriteFile(hPipe, &h, sizeof(h), &w, NULL);
        WriteFile(hPipe, err.data(), err.size(), &w, NULL);
        p_settop(m_L, -2);
        return;
    }

    // Iterate Players
    // Stack: Players
    p_pushnil(m_L);
    // Stack: Players, nil
    std::string out;
    out = "Scan Players Results:\n";

    while (p_next(m_L, -2) != 0) {
        // Stack: Players, Key, Value
        // Assuming Key is PlayerName or Index, Value is Player Object (Table/Userdata)

        // Try to get Name from Key
        const char* key = NULL;
        if (p_type(m_L, -2) == 4) { // String Key
             key = p_tolstring(m_L, -2, NULL);
        }

        out.append(key ? key : "[Unknown Key]");
        out.append("|");

        // Get Pointer
        const void* ptr = p_topointer ? p_topointer(m_L, -1) : nullptr;
        char addrBuf[32];
        sprintf_s(addrBuf, "%p", ptr);
        out.append(addrBuf);
        out.append("|");

        // Try to get Position
        // Stack: Players, Key, Value(Player)
        std::string posStr = "Unknown";
        // Validation: Ensure p_getfield/p_type/p_settop/p_tonumber exist before using them.
        if (p_getfield && p_type && p_settop && p_tonumber && p_type(m_L, -1) == 5) { // If value is table
             // Try 'Position'
             p_getfield(m_L, -1, "Position");
             if (p_type(m_L, -1) != 0) { // Not nil
                 // Found something
             } else {
                 p_settop(m_L, -2); // pop nil
                 // Try 'pos'
                 p_getfield(m_L, -1, "pos");
             }

             // Now top is Position object or nil
             if (p_type(m_L, -1) == 5 || p_type(m_L, -1) == 7) { // Table or Userdata
                 // Try x, y, z
                 double x=0, y=0, z=0;
                 p_getfield(m_L, -1, "x");
                 if (p_type(m_L, -1) == 3) x = p_tonumber(m_L, -1);
                 p_settop(m_L, -2);

                 p_getfield(m_L, -1, "y");
                 if (p_type(m_L, -1) == 3) y = p_tonumber(m_L, -1);
                 p_settop(m_L, -2);

                 p_getfield(m_L, -1, "z");
                 if (p_type(m_L, -1) == 3) z = p_tonumber(m_L, -1);
                 p_settop(m_L, -2);

                 char buf[64];
                 sprintf_s(buf, "%.1f, %.1f, %.1f", x, y, z);
                 posStr = buf;
             }
             p_settop(m_L, -2); // pop Position/nil
        }
        out.append(posStr);
        out.append("\n");

        p_settop(m_L, -2); // pop value
    }
    p_settop(m_L, -2); // pop Players

    MessageHeader h = { (uint32_t)out.size(), RESP_DATA };
    DWORD w; WriteFile(hPipe, &h, sizeof(h), &w, NULL);
    WriteFile(hPipe, out.data(), out.size(), &w, NULL);
}

void LuaInterface::DumpRegistry(HANDLE hPipe) {
    if (!m_L) return;

    // LUA_REGISTRYINDEX is usually -10000 or similar macro.
    // In standard Lua 5.4, it's (-1001000) (LUAI_FIRSTPSEUDOIDX)
    // But we can't rely on macro value here safely without headers.
    // However, lua_getregistry is not a standard function, usually a macro calling lua_pushvalue(L, LUA_REGISTRYINDEX)? No.
    // Actually, to iterate registry, we need the index.
    // Let's guess standard 5.4 index: -1001000
    int registry_index = -1001000;

    std::string out = "Registry Dump:\n";
    out.reserve(65536);

    p_pushvalue(m_L, registry_index); // Push Registry
    if (p_type(m_L, -1) != 5) {
        out = "Failed to push Registry (Invalid Index?).";
    } else {
        p_pushnil(m_L);
        int count = 0;
        while (p_next(m_L, -2) != 0) {
            count++;
            if (count % 500 == 0) {
                // Send Chunk
                if (!out.empty()) {
                    MessageHeader h = { (uint32_t)out.size(), RESP_DATA };
                    DWORD w; WriteFile(hPipe, &h, sizeof(h), &w, NULL);
                    WriteFile(hPipe, out.data(), out.size(), &w, NULL);
                    out.clear();
                    out.reserve(65536);
                }

                // Send Progress
                std::string prog = "Dumped Registry " + std::to_string(count) + " items...";
                MessageHeader h = { (uint32_t)prog.size(), RESP_PROGRESS };
                DWORD w; WriteFile(hPipe, &h, sizeof(h), &w, NULL);
                WriteFile(hPipe, prog.data(), prog.size(), &w, NULL);
            }

            if (count > 20000) {
                out.append("... Truncated ...\n");
                p_settop(m_L, -3);
                break;
            }
            // Key
            int kType = p_type(m_L, -2);
            std::string keyStr;
            if (kType == 3) keyStr = std::to_string((int)p_tonumber(m_L, -2));
            else if (kType == 4) keyStr = p_tolstring(m_L, -2, NULL);
            else keyStr = p_typename(m_L, kType);

            // Value Type
            int vType = p_type(m_L, -1);
            std::string typeStr = p_typename(m_L, vType);

            // Value Preview
            std::string valStr = typeStr;
            if (vType == 3 && p_tonumber) valStr = std::to_string(p_tonumber(m_L, -1));
            else if (vType == 1 && p_toboolean) valStr = p_toboolean(m_L, -1) ? "true" : "false";
            else if (vType == 4 && p_tolstring) {
                const char* s = p_tolstring(m_L, -1, NULL);
                valStr = s ? s : "";
                if (valStr.length() > 30) valStr = valStr.substr(0, 27) + "...";
            }

            out.append(keyStr);
            out.append("|");
            out.append(typeStr);
            out.append("|");
            out.append(valStr);
            out.append("\n");

            p_settop(m_L, -2);
        }
    }
    p_settop(m_L, -2); // Pop Registry

    MessageHeader h = { (uint32_t)out.size(), RESP_DATA };
    DWORD w; WriteFile(hPipe, &h, sizeof(h), &w, NULL);
    WriteFile(hPipe, out.data(), out.size(), &w, NULL);
}

void LuaInterface::DumpScripts(HANDLE hPipe) {
    // Iterate _G looking for functions and get info
    if (!m_L) return;

    if (!p_getglobal || !p_pushnil || !p_next || !p_type || !p_tolstring || !p_settop) {
        std::string msg = "Critical Lua functions missing for DumpScripts.";
        MessageHeader h = { (uint32_t)msg.size(), RESP_ERROR };
        DWORD w; WriteFile(hPipe, &h, sizeof(h), &w, NULL);
        WriteFile(hPipe, msg.data(), msg.size(), &w, NULL);
        return;
    }

    std::string out = "Discovered Scripts (Functions in _G):\n";
    out.reserve(65536);

    p_getglobal(m_L, "_G");
    p_pushnil(m_L);
    while (p_next(m_L, -2) != 0) {
        if (p_type(m_L, -1) == 6) { // LUA_TFUNCTION
             const char* key = p_tolstring(m_L, -2, NULL);
             std::string fnName = key ? key : "?";

             out.append(fnName);
             out.append("|");

             // Include Source/Override info directly here for "batch loading" perception
             std::string src = GetOverride(fnName);
             if (!src.empty()) {
                 out.append("Override Active");
             } else {
                 out.append("Original");
             }
             out.append("\n");
        }
        p_settop(m_L, -2);
    }
    p_settop(m_L, -2);

    MessageHeader h = { (uint32_t)out.size(), RESP_DATA };
    DWORD w; WriteFile(hPipe, &h, sizeof(h), &w, NULL);
    WriteFile(hPipe, out.data(), out.size(), &w, NULL);
}

void LuaInterface::GetScriptSource(HANDLE hPipe, const std::string& name) {
    if (!m_L) return;

    // We can't easily get source CODE without decompilation or if it was loaded from string/file and kept.
    // We will try to find the function in _G and get 'source' from getinfo if we decide to implement struct.
    // For now, we will return a message saying it's not fully supported or return the override if present.

    std::string src = GetOverride(name);
    if (src.empty()) {
        src = "-- Source for " + name + "\n-- (Source retrieval requires debug symbols or decompiler, which is not implemented)\n-- You can set an Override for this script.";
    } else {
        src = "-- Override Found:\n" + src;
    }

    MessageHeader h = { (uint32_t)src.size(), RESP_DATA };
    DWORD w; WriteFile(hPipe, &h, sizeof(h), &w, NULL);
    WriteFile(hPipe, src.data(), src.size(), &w, NULL);
}

void LuaInterface::InstallPrintHook() {
    if (!m_L || !p_pushcclosure || !p_setglobal) return;
    // Push C Closure
    p_pushcclosure(m_L, MyLuaPrint, 0);
    p_setglobal(m_L, "print");
    std::cout << "[Agent] Replaced 'print' with custom handler." << std::endl;
}

// ----------------------------------------------------------------------------
// IPC Logic
// ----------------------------------------------------------------------------
struct Task {
    MessageType type;
    std::string payload;
    HANDLE pipe;
};

std::mutex g_TaskMutex;
std::queue<Task> g_TaskQueue;

std::mutex g_LogMutex;
std::vector<std::string> g_LogQueue;

void AppendLog(const std::string& msg) {
    std::lock_guard<std::mutex> lock(g_LogMutex);
    g_LogQueue.push_back(msg);
    if (g_LogQueue.size() > 1000) g_LogQueue.erase(g_LogQueue.begin());
}

bool HasPendingTasks() {
    std::lock_guard<std::mutex> lock(g_TaskMutex);
    return !g_TaskQueue.empty();
}

bool LuaInterface::ProcessTasks() {
    // Optimization: Check empty without lock first to avoid overhead in high-frequency hooks?
    // Unsafe. Stick to lock but ensure it's fast.
    std::lock_guard<std::mutex> lock(g_TaskMutex);
    bool didWork = !g_TaskQueue.empty();

    while (!g_TaskQueue.empty()) {
        Task t = g_TaskQueue.front();
        g_TaskQueue.pop();

        if (t.type == CMD_PING) {
            MessageHeader h = { 0, RESP_OK };
            DWORD w; WriteFile(t.pipe, &h, sizeof(h), &w, NULL);
        } else if (t.type == CMD_RUN_SCRIPT) {
            if (!m_L) {
                std::string err = "Lua state not ready (hooks not installed).";
                MessageHeader h = { (uint32_t)err.size(), RESP_ERROR };
                DWORD w; WriteFile(t.pipe, &h, sizeof(h), &w, NULL);
                WriteFile(t.pipe, err.data(), err.size(), &w, NULL);
            } else {
                std::string err;
                try {
                    if (LoadScript(t.payload, err)) {
                        // Success
                        MessageHeader h = { 0, RESP_OK };
                        DWORD w; WriteFile(t.pipe, &h, sizeof(h), &w, NULL);
                    } else {
                        // Error
                        MessageHeader h = { (uint32_t)err.size(), RESP_ERROR };
                        DWORD w; WriteFile(t.pipe, &h, sizeof(h), &w, NULL);
                        WriteFile(t.pipe, err.data(), err.size(), &w, NULL);
                    }
                } catch (...) {
                    std::string except = "Exception caught during LoadScript";
                    MessageHeader h = { (uint32_t)except.size(), RESP_ERROR };
                    DWORD w; WriteFile(t.pipe, &h, sizeof(h), &w, NULL);
                    WriteFile(t.pipe, except.data(), except.size(), &w, NULL);
                }
            }
        } else if (t.type == CMD_DUMP_GLOBALS) {
            if (!m_L) {
                std::string err = "Lua state not ready (hooks not installed).";
                MessageHeader h = { (uint32_t)err.size(), RESP_ERROR };
                DWORD w; WriteFile(t.pipe, &h, sizeof(h), &w, NULL);
                WriteFile(t.pipe, err.data(), err.size(), &w, NULL);
            } else {
                DumpGlobals(t.pipe);
                MessageHeader h = { 0, RESP_OK };
                DWORD w; WriteFile(t.pipe, &h, sizeof(h), &w, NULL);
            }
        } else if (t.type == CMD_SCAN_PLAYERS) {
            ScanPlayers(t.pipe);
            MessageHeader h = { 0, RESP_OK };
            DWORD w; WriteFile(t.pipe, &h, sizeof(h), &w, NULL);
        } else if (t.type == CMD_DUMP_REGISTRY) {
            DumpRegistry(t.pipe);
            MessageHeader h = { 0, RESP_OK };
            DWORD w; WriteFile(t.pipe, &h, sizeof(h), &w, NULL);
        } else if (t.type == CMD_DUMP_SCRIPTS) {
            DumpScripts(t.pipe);
            MessageHeader h = { 0, RESP_OK };
            DWORD w; WriteFile(t.pipe, &h, sizeof(h), &w, NULL);
        } else if (t.type == CMD_GET_SCRIPT_SOURCE) {
            GetScriptSource(t.pipe, t.payload);
            MessageHeader h = { 0, RESP_OK };
            DWORD w; WriteFile(t.pipe, &h, sizeof(h), &w, NULL);
        } else if (t.type == CMD_ADD_OVERRIDE) {
            // Payload format: "Name\nSource"
            size_t delim = t.payload.find('\n');
            if (delim != std::string::npos) {
                std::string name = t.payload.substr(0, delim);
                std::string src = t.payload.substr(delim + 1);
                AddOverride(name, src);
            }
            MessageHeader h = { 0, RESP_OK };
            DWORD w; WriteFile(t.pipe, &h, sizeof(h), &w, NULL);
        } else if (t.type == CMD_RESET_OVERRIDES) {
            ResetOverrides();
            MessageHeader h = { 0, RESP_OK };
            DWORD w; WriteFile(t.pipe, &h, sizeof(h), &w, NULL);
        } else if (t.type == CMD_PRINT_OUTPUT) {
            // Send buffered logs
            std::string combined;
            {
                std::lock_guard<std::mutex> lock(g_LogMutex);
                for (const auto& l : g_LogQueue) {
                    combined += l + "\n";
                }
                g_LogQueue.clear();
            }
            MessageHeader h = { (uint32_t)combined.size(), RESP_DATA };
            DWORD w; WriteFile(t.pipe, &h, sizeof(h), &w, NULL);
            WriteFile(t.pipe, combined.data(), combined.size(), &w, NULL);
        }
        CloseHandle(t.pipe);
    }
    return didWork;
}

void PipeServerThread() {
    char pipeName[256];
    sprintf_s(pipeName, "\\\\.\\pipe\\luatool_%lu", GetCurrentProcessId());
    std::cout << "[Agent] Pipe Server: " << pipeName << std::endl;

    while (true) {
        HANDLE hPipe = CreateNamedPipeA(pipeName, PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES, 512, 512, 0, NULL);

        if (hPipe != INVALID_HANDLE_VALUE) {
            std::cout << "[Agent] Pipe Created. Waiting for connection..." << std::endl;
            if (ConnectNamedPipe(hPipe, NULL) || GetLastError() == ERROR_PIPE_CONNECTED) {
                std::cout << "[Agent] Client Connected." << std::endl;
                MessageHeader h;
                DWORD r;
                if (ReadFile(hPipe, &h, sizeof(h), &r, NULL)) {
                    std::string payload;
                    if (h.length > 0) {
                        std::vector<char> b(h.length);
                        ReadFile(hPipe, b.data(), h.length, &r, NULL);
                        payload.assign(b.begin(), b.end());
                    }

                    std::cout << "[Agent] Task Queued. Type: " << (int)h.type << std::endl;
                    {
                        std::lock_guard<std::mutex> lock(g_TaskMutex);
                        g_TaskQueue.push({ h.type, payload, hPipe });
                    }
                    // If Lua is not loaded (hooks not active), we must process the task immediately
                    // to avoid timeout (since HookProcessHelper won't be called).
                    if (!LuaInterface::Get().IsLoaded()) {
                         LuaInterface::Get().ProcessTasks();
                    }
                } else {
                    std::cout << "[Agent] Failed to read request. Error: " << GetLastError() << std::endl;
                    CloseHandle(hPipe);
                }
            } else {
                std::cout << "[Agent] ConnectNamedPipe Failed. Error: " << GetLastError() << std::endl;
                CloseHandle(hPipe);
            }
        } else {
            std::cout << "[Agent] CreateNamedPipe Failed. Error: " << GetLastError() << std::endl;
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
}

// ----------------------------------------------------------------------------
// Entry Point
// ----------------------------------------------------------------------------
DWORD WINAPI AgentThread(LPVOID) {
    AllocConsole();
    FILE* f;
    freopen_s(&f, "CONOUT$", "w", stdout);
    freopen_s(&f, "CONOUT$", "w", stderr);

    std::cout << "[Agent] Injected." << std::endl;
    LuaInterface::Get().Initialize();
    PipeServerThread();
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        CreateThread(NULL, 0, AgentThread, NULL, 0, NULL);
    }
    return TRUE;
}
