#include <windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <mutex>
#include <queue>
#include <atomic>
#include <map>
#include <functional>
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
typedef void        (*lua_callk_t)(lua_State *L, int nargs, int nresults, long ctx, void* k);
typedef void        (*lua_pushcclosure_t)(lua_State *L, int (*fn)(lua_State *), int n);
typedef void        (*lua_setglobal_t)(lua_State *L, const char *name);
typedef void        (*lua_getglobal_t)(lua_State *L, const char *name);
typedef int         (*lua_dump_t)(lua_State *L, int (*writer)(lua_State*, const void*, size_t, void*), void* data, int strip);

// ----------------------------------------------------------------------------
// SEH Wrapper Logic
// ----------------------------------------------------------------------------
// Helper to bridge std::function to void* for C-style callback
void CallStdFunc(void* p) {
    (*(std::function<void()>*)p)();
}

// Function with NO C++ objects requiring unwinding
void SafeInvokeInternal(void(*cb)(void*), void* arg) {
    __try {
        cb(arg);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        printf("[Agent] Exception intercepted in SafeInvoke.\n");
    }
}

void SafeInvoke(std::function<void()> fn) {
    SafeInvokeInternal(CallStdFunc, &fn);
}

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
    bool ProcessTasks();
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

    // Public member for MyLuaPrint and others
    lua_getglobal_t p_getglobal = nullptr;

private:
    LuaInterface() = default;
    bool ResolveSymbols(HMODULE hMod);

    lua_State* m_L = nullptr;
    bool m_Loaded = false;
    HMODULE m_hLua = NULL;

    std::mutex m_OverrideMutex;
    std::map<std::string, std::string> m_ScriptOverrides;

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
    lua_callk_t     p_callk = nullptr;
    lua_pushcclosure_t p_pushcclosure = nullptr;
    lua_setglobal_t    p_setglobal = nullptr;
    lua_dump_t         p_dump = nullptr;

    friend int MyLuaPrint(lua_State* L);

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

// ... (HookProcessHelper, MyLuaGetTop, etc.) ...
void HookProcessHelper(LuaInterface& lua, lua_State* L) {
    if (lua.m_RecursionGuard) return;
    lua.m_RecursionGuard = true;
    lua.SetState(L);

    static bool printHooked = false;
    if (!printHooked) {
        lua.InstallPrintHook();
        printHooked = true;
    }

    extern bool HasPendingTasks();

    uint32_t now = GetTickCount();
    if (now - lua.m_LastTick > 10) {
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
    std::string overrideSrc;
    if (name) overrideSrc = lua.GetOverride(name);
    int ret;
    if (!overrideSrc.empty()) {
        if (lua.p_loadbufferx && overrideSrc.c_str()) {
             std::cout << "[Agent] Applying Override for: " << name << std::endl;
             ret = lua.p_loadbufferx(L, overrideSrc.c_str(), overrideSrc.size(), name, mode);
        } else {
             ret = lua.p_loadbufferx(L, buff, sz, name, mode);
        }
    } else {
        if (lua.p_loadbufferx) ret = lua.p_loadbufferx(L, buff, sz, name, mode);
        else ret = 0;
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
    int ret = 0;
    if (lua.p_pcallk) ret = lua.p_pcallk(L, nargs, nresults, errfunc, 0, nullptr);
    lua.EnableHook();
    return ret;
}

int MyLuaPcallK(lua_State *L, int nargs, int nresults, int errfunc, long ctx, void* k) {
    auto& lua = LuaInterface::Get();
    HookProcessHelper(lua, L);
    lua.DisableHook();
    int ret = 0;
    if (lua.p_pcallk) ret = lua.p_pcallk(L, nargs, nresults, errfunc, ctx, k);
    lua.EnableHook();
    return ret;
}

void MyLuaSetTop(lua_State *L, int idx) {
    auto& lua = LuaInterface::Get();
    HookProcessHelper(lua, L);
    lua.DisableHook();
    if (lua.p_settop) lua.p_settop(L, idx);
    lua.EnableHook();
}

int MyLuaPrint(lua_State* L) {
    auto& lua = LuaInterface::Get();
    int n = lua.p_gettop ? lua.p_gettop(L) : 0;
    std::string out;
    if (lua.p_getglobal) lua.p_getglobal(L, "tostring");

    for (int i=1; i<=n; i++) {
        if (lua.p_pushvalue) lua.p_pushvalue(L, -1);
        if (lua.p_pushvalue) lua.p_pushvalue(L, i);
        if (lua.p_pcallk) lua.p_pcallk(L, 1, 1, 0, 0, nullptr);
        else if (lua.p_callk) lua.p_callk(L, 1, 1, 0, nullptr);
        const char* s = lua.p_tolstring ? lua.p_tolstring(L, -1, NULL) : nullptr;
        if (s) {
            if (i > 1) out += "\t";
            out += s;
        }
        if (lua.p_settop) lua.p_settop(L, -2);
    }
    if (lua.p_settop) lua.p_settop(L, -2);
    char pipeName[256];
    sprintf_s(pipeName, "\\\\.\\pipe\\luatool_%lu", GetCurrentProcessId());
    extern void AppendLog(const std::string& msg);
    AppendLog(out);
    std::cout << "[LUA] " << out << std::endl;
    return 0;
}

// ----------------------------------------------------------------------------
// Helper: FindPattern (IDA Style)
// ----------------------------------------------------------------------------
uintptr_t FindPattern(HMODULE hMod, const char* signature) {
    MODULEINFO modInfo;
    if (!GetModuleInformation(GetCurrentProcess(), hMod, &modInfo, sizeof(MODULEINFO))) return 0;
    uintptr_t start = (uintptr_t)modInfo.lpBaseOfDll;
    uintptr_t size = (uintptr_t)modInfo.SizeOfImage;
    uintptr_t end = start + size;
    std::vector<int> patternBytes;
    const char* p = signature;
    while (*p) {
        if (*p == ' ') { p++; continue; }
        if (*p == '?') { patternBytes.push_back(-1); p++; if (*p == '?') p++; }
        else {
            int b = 0;
            for (int i=0; i<2; i++) {
                char c = *(p++);
                if (c == 0) break;
                b <<= 4;
                if (c >= '0' && c <= '9') b |= (c - '0');
                else if (c >= 'A' && c <= 'F') b |= (c - 'A' + 10);
                else if (c >= 'a' && c <= 'f') b |= (c - 'a' + 10);
            }
            patternBytes.push_back(b);
        }
    }
    if (patternBytes.empty()) return 0;
    int firstByte = patternBytes[0];
    size_t patternSize = patternBytes.size();
    for (uintptr_t i = start; i < end - patternSize; i++) {
        if (firstByte != -1 && *(uint8_t*)i != firstByte) continue;
        bool found = true;
        for (size_t j = 0; j < patternSize; j++) {
            if (patternBytes[j] != -1 && patternBytes[j] != *(uint8_t*)(i + j)) {
                found = false;
                break;
            }
        }
        if (found) return i;
    }
    return 0;
}

void LuaInterface::Initialize() {
    std::cout << "[Agent] Scanning for Lua..." << std::endl;
    HMODULE hMods[1024];
    DWORD cbNeeded;
    HANDLE hProcess = GetCurrentProcess();
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        unsigned int numMods = cbNeeded / sizeof(HMODULE);
        if (numMods > 1024) numMods = 1024;
        for (unsigned int i = 0; i < numMods; i++) {
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
        std::cout << "[Agent] No exports found. Attempting Heuristic Scan..." << std::endl;
        const char* heuristics[] = { "4C 75 61 20 35 2E", "4C 75 61 4A 49 54" };
        for (unsigned int i = 0; i < numMods; i++) {
             for (const char* pattern : heuristics) {
                 if (FindPattern(hMods[i], pattern)) {
                     char modName[MAX_PATH];
                     GetModuleBaseNameA(hProcess, hMods[i], modName, sizeof(modName));
                     std::cout << "[Agent] Heuristic Match: " << modName << std::endl;
                     if (ResolveSymbols(hMods[i])) {
                         m_hLua = hMods[i];
                         std::cout << "[Agent] Hooked Lua via Heuristic in: " << modName << std::endl;
                         return;
                     }
                     break;
                 }
             }
        }
        std::cout << "[Agent] Heuristic failed. Attempting Code Pattern Scan..." << std::endl;
        for (unsigned int i = 0; i < numMods; i++) {
             if (FindPattern(hMods[i], "48 8B ?? ?? 48 2B ?? ?? 48 C1 ?? 04 C3")) {
                 char modName[MAX_PATH];
                 GetModuleBaseNameA(hProcess, hMods[i], modName, sizeof(modName));
                 std::cout << "[Agent] Pattern Match (lua_gettop): " << modName << std::endl;
                 if (ResolveSymbols(hMods[i])) {
                     m_hLua = hMods[i];
                     std::cout << "[Agent] Hooked Lua via Pattern in: " << modName << std::endl;
                     return;
                 }
             }
        }
    }
    std::cout << "[Agent] Failed to find a usable Lua module." << std::endl;
}

bool LuaInterface::ResolveSymbols(HMODULE hMod) {
    p_gettop = nullptr;
    auto Resolve = [&](const char* name, const char* signature = nullptr) -> void* {
        void* addr = (void*)GetProcAddress(hMod, name);
        if (!addr && signature) {
            uintptr_t p = FindPattern(hMod, signature);
            if (p) addr = (void*)p;
        }
        return addr;
    };

    p_gettop = (lua_gettop_t)Resolve("lua_gettop", "48 8B ?? ?? 48 2B ?? ?? 48 C1 ?? 04 C3");
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

    // Add lua_dump pattern
    p_dump = (lua_dump_t)Resolve("lua_dump", "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 30 48 8B 02 48 8B F9");

    p_pcallk = (lua_pcallk_t)Resolve("lua_pcallk");
    if (!p_pcallk) p_pcallk = (lua_pcallk_t)Resolve("lua_pcall");
    p_callk = (lua_callk_t)Resolve("lua_callk");
    if (!p_callk) p_callk = (lua_callk_t)Resolve("lua_call");

    p_loadbufferx = (luaL_loadbufferx_t)Resolve("luaL_loadbufferx");
    p_loadstring = (luaL_loadstring_t)Resolve("luaL_loadstring");

    if (!p_gettop) {
        std::cout << "[Agent] Missing gettop. Aborting." << std::endl;
        return false;
    }

    auto AddHook = [&](void* target, void* detour, const char* name) {
        if (!target) return;
        Hook h;
        h.target = target;
        h.detour = detour;
        h.active = false;
        memcpy(h.original, target, 12);
        m_Hooks.push_back(h);
        std::cout << "[Agent] Added Hook: " << name << " at " << target << std::endl;
    };

    if (p_pcallk) AddHook((void*)p_pcallk, (void*)MyLuaPcallK, "lua_pcallk");
    if (p_loadbufferx) AddHook((void*)p_loadbufferx, (void*)MyLuaLoadBufferX, "luaL_loadbufferx");
    if (p_loadstring) AddHook((void*)p_loadstring, (void*)MyLuaLoadString, "luaL_loadstring");

    if (!m_Hooks.empty()) {
        EnableHook();
        m_Loaded = true;
        std::cout << "[Agent] Hooks Installed: " << m_Hooks.size() << std::endl;
        return true;
    } else {
        std::cout << "[Agent] No hooks found." << std::endl;
        return false;
    }
}

void LuaInterface::EnableHook() {
    for (auto& h : m_Hooks) {
        if (h.active) continue;
        DWORD old;
        VirtualProtect(h.target, 12, PAGE_EXECUTE_READWRITE, &old);
        uint8_t patch[12];
        patch[0] = 0x48; patch[1] = 0xB8;
        uintptr_t dest = (uintptr_t)h.detour;
        memcpy(&patch[2], &dest, 8);
        patch[10] = 0xFF; patch[11] = 0xE0;
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
    else {
        error = "No loader function available (luaL_loadbufferx/string).";
        return false;
    }
    if (res == 0) {
        if (p_pcallk) {
            if (p_pcallk(m_L, 0, 0, 0, 0, nullptr) != 0) {
                if (p_tolstring) error = p_tolstring(m_L, -1, NULL);
                if (p_settop) p_settop(m_L, -2);
                return false;
            }
        } else if (p_callk) {
             p_callk(m_L, 0, 0, 0, nullptr);
        }
        return true;
    } else {
        if (p_tolstring) error = p_tolstring(m_L, -1, NULL);
        if (p_settop) p_settop(m_L, -2);
        return false;
    }
}

// ----------------------------------------------------------------------------
// Wrapped Dump Functions
// ----------------------------------------------------------------------------

void LuaInterface::DumpGlobals(HANDLE hPipe) {
    SafeInvoke([&]() {
        if (!m_L) {
            std::string msg = "Lua State not ready.";
            MessageHeader h = { (uint32_t)msg.size(), RESP_ERROR };
            DWORD w; WriteFile(hPipe, &h, sizeof(h), &w, NULL);
            WriteFile(hPipe, msg.data(), msg.size(), &w, NULL);
            return;
        }
        if (!p_pushvalue || !p_type || !p_pushnil || !p_next || !p_tolstring || !p_typename || !p_settop) {
            std::string msg = "Critical Lua functions missing.";
            MessageHeader h = { (uint32_t)msg.size(), RESP_ERROR };
            DWORD w; WriteFile(hPipe, &h, sizeof(h), &w, NULL);
            WriteFile(hPipe, msg.data(), msg.size(), &w, NULL);
            return;
        }

        std::string out;
        out.reserve(4096);
        out = "Globals Dump (Streaming):\n";
        out.reserve(131072);

        if (p_getglobal) p_getglobal(m_L, "_G");
        if (p_gettop(m_L) > 0) {
            p_pushnil(m_L);
            int count = 0;
            while (p_next(m_L, -2) != 0) {
                count++;
                if (count % 1000 == 0) {
                    if (!out.empty()) {
                        MessageHeader h = { (uint32_t)out.size(), RESP_DATA };
                        DWORD w; WriteFile(hPipe, &h, sizeof(h), &w, NULL);
                        WriteFile(hPipe, out.data(), out.size(), &w, NULL);
                        out.clear();
                        out.reserve(65536);
                    }
                    std::string prog = "Dumped " + std::to_string(count) + " items...";
                    MessageHeader h = { (uint32_t)prog.size(), RESP_PROGRESS };
                    DWORD w; WriteFile(hPipe, &h, sizeof(h), &w, NULL);
                    WriteFile(hPipe, prog.data(), prog.size(), &w, NULL);
                }
                if (count > 50000) { out.append("... [Truncated]\n"); p_settop(m_L, -3); break; }

                p_pushvalue(m_L, -2);
                const char* key = p_tolstring(m_L, -1, NULL);
                if (key) out.append(key); else out.append("(non-string key)");
                p_settop(m_L, -2);

                int type = p_type(m_L, -1);
                const char* typeName = p_typename(m_L, type);
                out.append(" ["); out.append(typeName); out.append("]");

                if (type == 3 && p_tonumber) {
                     char buf[64]; sprintf_s(buf, " = %.14g", p_tonumber(m_L, -1)); out.append(buf);
                } else if (type == 1 && p_toboolean) {
                     out.append(" = "); out.append(p_toboolean(m_L, -1) ? "true" : "false");
                } else if (type == 4 && p_tolstring) {
                     out.append(" = \"");
                     const char* s = p_tolstring(m_L, -1, NULL);
                     std::string valStr = s ? s : "";
                     if (valStr.length() > 64) valStr = valStr.substr(0, 61) + "...";
                     out.append(valStr); out.append("\"");
                }
                out.append("\n");
                p_settop(m_L, -2);
            }
            p_settop(m_L, -2);
        }
        if (!out.empty()) {
            MessageHeader h = { (uint32_t)out.size(), RESP_DATA };
            DWORD w; WriteFile(hPipe, &h, sizeof(h), &w, NULL);
            WriteFile(hPipe, out.data(), out.size(), &w, NULL);
        }
    });
}

void LuaInterface::DumpRegistry(HANDLE hPipe) {
    SafeInvoke([&]() {
        if (!m_L) {
            std::string msg = "Lua State not ready.";
            MessageHeader h = { (uint32_t)msg.size(), RESP_ERROR };
            DWORD w; WriteFile(hPipe, &h, sizeof(h), &w, NULL);
            WriteFile(hPipe, msg.data(), msg.size(), &w, NULL);
            return;
        }
        if (!p_pushvalue || !p_type || !p_pushnil || !p_next || !p_tolstring || !p_typename || !p_settop) {
            std::string msg = "Critical Lua functions missing for DumpRegistry.";
            MessageHeader h = { (uint32_t)msg.size(), RESP_ERROR };
            DWORD w; WriteFile(hPipe, &h, sizeof(h), &w, NULL);
            WriteFile(hPipe, msg.data(), msg.size(), &w, NULL);
            return;
        }

        int registry_index = -1001000;
        std::string out = "Registry Dump:\n";
        out.reserve(65536);

        p_pushvalue(m_L, registry_index);
        if (p_type(m_L, -1) != 5) {
            out = "Failed to push Registry.";
        } else {
            p_pushnil(m_L);
            int count = 0;
            while (p_next(m_L, -2) != 0) {
                count++;
                if (count % 500 == 0) {
                    if (!out.empty()) {
                        MessageHeader h = { (uint32_t)out.size(), RESP_DATA };
                        DWORD w; WriteFile(hPipe, &h, sizeof(h), &w, NULL);
                        WriteFile(hPipe, out.data(), out.size(), &w, NULL);
                        out.clear();
                        out.reserve(65536);
                    }
                    std::string prog = "Dumped Registry " + std::to_string(count) + " items...";
                    MessageHeader h = { (uint32_t)prog.size(), RESP_PROGRESS };
                    DWORD w; WriteFile(hPipe, &h, sizeof(h), &w, NULL);
                    WriteFile(hPipe, prog.data(), prog.size(), &w, NULL);
                }
                if (count > 20000) { out.append("... Truncated ...\n"); p_settop(m_L, -3); break; }

                // Key
                int kType = p_type(m_L, -2);
                if (kType == 3 && p_tonumber) { char buf[64]; sprintf_s(buf, "%.0f", p_tonumber(m_L, -2)); out.append(buf); }
                else if (kType == 4) { const char* s = p_tolstring(m_L, -2, NULL); if(s) out.append(s); }
                else out.append(p_typename(m_L, kType));
                out.append("|");

                int vType = p_type(m_L, -1);
                out.append(p_typename(m_L, vType));
                out.append("|");

                if (vType == 3 && p_tonumber) { char buf[64]; sprintf_s(buf, "%.14g", p_tonumber(m_L, -1)); out.append(buf); }
                else if (vType == 1 && p_toboolean) out.append(p_toboolean(m_L, -1) ? "true" : "false");
                else if (vType == 4 && p_tolstring) {
                    const char* s = p_tolstring(m_L, -1, NULL);
                    std::string valStr = s ? s : "";
                    if (valStr.length() > 30) valStr = valStr.substr(0, 27) + "...";
                    out.append(valStr);
                }
                out.append("\n");
                p_settop(m_L, -2);
            }
        }
        p_settop(m_L, -2);

        MessageHeader h = { (uint32_t)out.size(), RESP_DATA };
        DWORD w; WriteFile(hPipe, &h, sizeof(h), &w, NULL);
        WriteFile(hPipe, out.data(), out.size(), &w, NULL);
    });
}

void LuaInterface::ScanPlayers(HANDLE hPipe) {
    SafeInvoke([&]() {
        if (!m_L) return;
        if (!p_getglobal) return;

        p_getglobal(m_L, "Players");
        if (p_type && p_type(m_L, -1) != 5) {
            std::string err = "Global 'Players' table not found.";
            MessageHeader h = { (uint32_t)err.size(), RESP_ERROR };
            DWORD w; WriteFile(hPipe, &h, sizeof(h), &w, NULL);
            WriteFile(hPipe, err.data(), err.size(), &w, NULL);
            if (p_settop) p_settop(m_L, -2);
            return;
        }

        if (!p_pushnil || !p_next) return;
        p_pushnil(m_L);
        std::string out = "Scan Players Results:\n";

        while (p_next(m_L, -2) != 0) {
            const char* key = NULL;
            if (p_type && p_type(m_L, -2) == 4) key = p_tolstring(m_L, -2, NULL);
            out.append(key ? key : "[Unknown Key]");
            out.append("|");

            const void* ptr = p_topointer ? p_topointer(m_L, -1) : nullptr;
            char addrBuf[32]; sprintf_s(addrBuf, "%p", ptr);
            out.append(addrBuf);
            out.append("|");

            std::string posStr = "Unknown";
            if (p_getfield && p_type && p_settop && p_tonumber && p_type(m_L, -1) == 5) {
                 p_getfield(m_L, -1, "Position");
                 if (p_type(m_L, -1) == 0) { p_settop(m_L, -2); p_getfield(m_L, -1, "pos"); }

                 if (p_type(m_L, -1) == 5 || p_type(m_L, -1) == 7) {
                     double x=0, y=0, z=0;
                     p_getfield(m_L, -1, "x"); if (p_type(m_L, -1) == 3) x = p_tonumber(m_L, -1); p_settop(m_L, -2);
                     p_getfield(m_L, -1, "y"); if (p_type(m_L, -1) == 3) y = p_tonumber(m_L, -1); p_settop(m_L, -2);
                     p_getfield(m_L, -1, "z"); if (p_type(m_L, -1) == 3) z = p_tonumber(m_L, -1); p_settop(m_L, -2);
                     char buf[64]; sprintf_s(buf, "%.1f, %.1f, %.1f", x, y, z);
                     posStr = buf;
                 }
                 p_settop(m_L, -2);
            }
            out.append(posStr); out.append("\n");
            p_settop(m_L, -2);
        }
        p_settop(m_L, -2);

        MessageHeader h = { (uint32_t)out.size(), RESP_DATA };
        DWORD w; WriteFile(hPipe, &h, sizeof(h), &w, NULL);
        WriteFile(hPipe, out.data(), out.size(), &w, NULL);
    });
}

void LuaInterface::DumpScripts(HANDLE hPipe) {
    SafeInvoke([&]() {
        if (!m_L) return;
        if (!p_getglobal || !p_pushnil || !p_next || !p_type || !p_tolstring || !p_settop) return;

        std::string out = "Discovered Scripts (Functions in _G):\n";
        out.reserve(65536);

        p_getglobal(m_L, "_G");
        if (p_type(m_L, -1) != 5) {
            std::cout << "[Agent] _G is not a table!" << std::endl;
            if (p_settop) p_settop(m_L, -2);
            return;
        }

        p_pushnil(m_L);
        while (p_next(m_L, -2) != 0) {
            if (p_type(m_L, -1) == 6) {
                 const char* key = p_tolstring(m_L, -2, NULL);
                 out.append(key ? key : "?");
                 out.append("|");
                 std::string src = GetOverride(key ? key : "?");
                 out.append(!src.empty() ? "Override Active" : "Original");
                 out.append("\n");
            }
            p_settop(m_L, -2);
        }
        p_settop(m_L, -2);

        MessageHeader h = { (uint32_t)out.size(), RESP_DATA };
        DWORD w; WriteFile(hPipe, &h, sizeof(h), &w, NULL);
        WriteFile(hPipe, out.data(), out.size(), &w, NULL);
    });
}

// Writer for lua_dump
int Writer(lua_State* L, const void* p, size_t sz, void* ud) {
    std::string* s = (std::string*)ud;
    s->append((const char*)p, sz);
    return 0;
}

void LuaInterface::GetScriptSource(HANDLE hPipe, const std::string& name) {
    SafeInvoke([&]() {
        if (!m_L) return;
        std::string src = GetOverride(name);

        if (src.empty()) {
            if (!p_dump) {
                 src = "-- Source retrieval unavailable: lua_dump not found.\n-- You can set an Override for this script.";
            } else if (p_getglobal && p_getfield) {
                p_getglobal(m_L, "_G");
                p_getfield(m_L, -1, name.c_str());
                if (p_type(m_L, -1) == 6) {
                    std::string bytecode;
                    if (p_dump(m_L, Writer, &bytecode, 0) == 0) {
                        std::string hex;
                        size_t limit = bytecode.size();
                        if (limit > 8192) limit = 8192;
                        hex.reserve(limit * 3 + 128);
                        char buf[4];
                        for (size_t i = 0; i < limit; i++) {
                            sprintf_s(buf, "%02X ", (unsigned char)bytecode[i]);
                            hex += buf;
                            if ((i + 1) % 16 == 0) hex += "\n";
                        }
                        if (bytecode.size() > limit) hex += "\n... (Truncated)";
                        src = "-- Bytecode Dump (" + std::to_string(bytecode.size()) + " bytes):\n" + hex;
                    }
                }
                p_settop(m_L, -3);
            }
            if (src.empty()) src = "-- Source for " + name + "\n-- (Source retrieval failed. Bytecode dump unavailable)\n-- You can set an Override for this script.";
        } else {
            src = "-- Override Found:\n" + src;
        }

        MessageHeader h = { (uint32_t)src.size(), RESP_DATA };
        DWORD w; WriteFile(hPipe, &h, sizeof(h), &w, NULL);
        WriteFile(hPipe, src.data(), src.size(), &w, NULL);
    });
}

void LuaInterface::InstallPrintHook() {
    if (!m_L || !p_pushcclosure || !p_setglobal) return;
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
    std::lock_guard<std::mutex> lock(g_TaskMutex);
    bool didWork = !g_TaskQueue.empty();

    while (!g_TaskQueue.empty()) {
        Task t = g_TaskQueue.front();
        g_TaskQueue.pop();

        if (t.type == CMD_PING) {
            MessageHeader h = { 0, RESP_OK };
            DWORD w; WriteFile(t.pipe, &h, sizeof(h), &w, NULL);
        } else if (t.type == CMD_RUN_SCRIPT) {
            SafeInvoke([&]() {
                if (!m_L) {
                    std::string err = "Lua state not ready (hooks not installed).";
                    MessageHeader h = { (uint32_t)err.size(), RESP_ERROR };
                    DWORD w; WriteFile(t.pipe, &h, sizeof(h), &w, NULL);
                    WriteFile(t.pipe, err.data(), err.size(), &w, NULL);
                } else {
                    std::string err;
                    try {
                        if (LoadScript(t.payload, err)) {
                            MessageHeader h = { 0, RESP_OK };
                            DWORD w; WriteFile(t.pipe, &h, sizeof(h), &w, NULL);
                        } else {
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
            });
        } else if (t.type == CMD_DUMP_GLOBALS) {
            DumpGlobals(t.pipe);
        } else if (t.type == CMD_SCAN_PLAYERS) {
            ScanPlayers(t.pipe);
        } else if (t.type == CMD_DUMP_REGISTRY) {
            DumpRegistry(t.pipe);
        } else if (t.type == CMD_DUMP_SCRIPTS) {
            DumpScripts(t.pipe);
        } else if (t.type == CMD_GET_SCRIPT_SOURCE) {
            GetScriptSource(t.pipe, t.payload);
        } else if (t.type == CMD_ADD_OVERRIDE) {
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
