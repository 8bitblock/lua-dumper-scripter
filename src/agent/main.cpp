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
typedef int         (*lua_rawgeti_t)(lua_State *L, int idx, long long n);
typedef int         (*lua_iscfunction_t)(lua_State *L, int idx);
typedef int         (*luaL_loadbufferx_t)(lua_State *L, const char *buff, size_t sz, const char *name, const char *mode);
typedef int         (*luaL_loadstring_t)(lua_State *L, const char *s);
typedef int         (*lua_pcallk_t)(lua_State *L, int nargs, int nresults, int errfunc, intptr_t ctx, void* k);
typedef void        (*lua_callk_t)(lua_State *L, int nargs, int nresults, intptr_t ctx, void* k);
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
bool SafeInvokeInternal(void(*cb)(void*), void* arg) {
    __try {
        cb(arg);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        printf("[Agent] Exception intercepted in SafeInvoke. Code: 0x%X\n", GetExceptionCode());
        return false;
    }
}

bool SafeInvoke(std::function<void()> fn) {
    return SafeInvokeInternal(CallStdFunc, &fn);
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
    bool DumpGlobals(HANDLE hPipe);
    bool ScanPlayers(HANDLE hPipe);
    bool DumpRegistry(HANDLE hPipe);
    bool InspectRegistryItem(HANDLE hPipe, const std::string& keyStr);
    bool DumpScripts(HANDLE hPipe);
    bool GetScriptSource(HANDLE hPipe, const std::string& name);

    // Hooking
    void EnableHook();
    void DisableHook();
    bool ProcessTasks();
    void InstallPrintHook();

    // Accessors
    void SetState(lua_State* L) { m_L = L; }
    lua_State* GetState() const { return m_L; }

    std::string FormatLuaValue(int idx);

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
    void* p_pcallk_trampoline = nullptr;

    std::string GetBytecodeViaLua(const std::string& name);

private:
    LuaInterface() = default;
    bool ResolveSymbols(HMODULE hMod);
    void CreateTrampoline(void* target, void*& trampoline);

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
    lua_rawgeti_t   p_rawgeti = nullptr;
    lua_iscfunction_t p_iscfunction = nullptr;
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
        uint8_t original[32];
        int size;
        bool active;
    };
    std::vector<Hook> m_Hooks;

    uint32_t m_LastTick = 0;

    friend int MyLuaLoadBufferX(lua_State* L, const char *buff, size_t sz, const char *name, const char *mode);
    friend int MyLuaLoadString(lua_State* L, const char* s);
    friend int MyLuaPcall(lua_State *L, int nargs, int nresults, int errfunc);
    friend int MyLuaPcallK(lua_State *L, int nargs, int nresults, int errfunc, intptr_t ctx, void* k);
    friend void MyLuaSetTop(lua_State *L, int idx);
    friend int MyLuaPrint(lua_State* L);
    friend void HookProcessHelper(LuaInterface& lua, lua_State* L);
};

// ... (HookProcessHelper, etc.) ...
void HookProcessHelper(LuaInterface& lua, lua_State* L) {
    static thread_local bool s_InHook = false;
    if (s_InHook) return;
    s_InHook = true;

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
            // Note: Trampoline hooks don't need DisableHook/EnableHook for the calls *they* replace,
            // but standard hooks (like pcall) might.
            // However, since we are using trampolines for gettop/settop/etc., calling Lua API functions inside ProcessTasks
            // will hit the trampoline hook again.
            // s_InHook protects against infinite recursion here.
            lua.ProcessTasks();
        }
        lua.m_LastTick = now;
    }
    s_InHook = false;
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

    // Check pending tasks
    extern bool HasPendingTasks();
    if (HasPendingTasks()) HookProcessHelper(lua, L);

    // Call via trampoline if available
    if (lua.p_pcallk_trampoline) {
        return ((lua_pcallk_t)lua.p_pcallk_trampoline)(L, nargs, nresults, errfunc, 0, nullptr);
    }

    // Fallback (shouldn't happen if initialized correctly)
    return 0;
}

int MyLuaPcallK(lua_State *L, int nargs, int nresults, int errfunc, intptr_t ctx, void* k) {
    auto& lua = LuaInterface::Get();

    extern bool HasPendingTasks();
    if (HasPendingTasks()) HookProcessHelper(lua, L);

    if (lua.p_pcallk_trampoline) {
        return ((lua_pcallk_t)lua.p_pcallk_trampoline)(L, nargs, nresults, errfunc, ctx, k);
    }
    return 0;
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
// Helper: FormatLuaValue
// ----------------------------------------------------------------------------
std::string LuaInterface::FormatLuaValue(int idx) {
    if (!m_L || !p_type) return "Error";
    int type = p_type(m_L, idx);
    if (type == 3 && p_tonumber) {
        char buf[64]; sprintf_s(buf, "%.14g", p_tonumber(m_L, idx)); return buf;
    } else if (type == 1 && p_toboolean) {
        return p_toboolean(m_L, idx) ? "true" : "false";
    } else if (type == 4 && p_tolstring) {
        const char* s = p_tolstring(m_L, idx, NULL);
        return s ? s : "";
    } else if ((type == 5 || type == 6 || type == 8) && p_topointer) {
        const void* ptr = p_topointer(m_L, idx);
        char buf[32]; sprintf_s(buf, "0x%p", ptr);
        return buf;
    }
    return p_typename ? p_typename(m_L, type) : "Unknown";
}

std::string LuaInterface::GetBytecodeViaLua(const std::string& name) {
    if (!m_L || !p_getglobal || !p_getfield || !p_pcallk) return "";

    // stack: []
    p_getglobal(m_L, "string"); // stack: [string]
    if (p_type(m_L, -1) != 5) { p_settop(m_L, -2); return ""; }

    p_getfield(m_L, -1, "dump"); // stack: [string, dump]
    if (p_type(m_L, -1) != 6) { p_settop(m_L, -3); return ""; }

    // Get target function
    p_getglobal(m_L, "_G"); // stack: [string, dump, _G]
    p_getfield(m_L, -1, name.c_str()); // stack: [string, dump, _G, func]

    if (p_type(m_L, -1) != 6) {
        p_settop(m_L, -5); // Pop all
        return "";
    }

    // Move func to be argument for dump
    // We want to call dump(func)
    // stack currently: [string, dump, _G, func]
    // We need: [string, dump, func] (actually just dump, func)

    // Let's rearrange manually or just pop _G
    // p_pcall args: nargs=1 (func), nresults=1
    // Stack before pcall must be: func(dump), arg1(target_func)

    // 1. Copy func to top
    p_pushvalue(m_L, -1); // [string, dump, _G, func, func_copy]

    // 2. Copy dump to top
    p_pushvalue(m_L, -4); // [string, dump, _G, func, func_copy, dump_copy]

    // 3. Move dump under func_copy? No, stack for call: [func_to_call, arg1, arg2...]
    // We want: [dump, target_func] at top

    p_settop(m_L, -3); // Pop func_copy, dump_copy? No, wait.
    // Reset stack logic.
    // Current: [string, dump, _G, func]

    // We want to call dump(func).
    // Push dump (copy)
    p_pushvalue(m_L, -3); // [string, dump, _G, func, dump]
    // Push func (copy)
    p_pushvalue(m_L, -2); // [string, dump, _G, func, dump, func]

    // Call: 1 arg, 1 result
    int res = 0;
    if (p_pcallk) res = p_pcallk(m_L, 1, 1, 0, 0, nullptr);
    else if (p_callk) p_callk(m_L, 1, 1, 0, nullptr);

    // Stack: [string, dump, _G, func, result_string] (if success)
    // or [string, dump, _G, func, error_msg] (if fail)

    std::string bytecode = "";
    if (res == 0 && p_type(m_L, -1) == 4) {
        size_t len = 0;
        const char* s = p_tolstring(m_L, -1, &len);
        if (s) {
            // Format as Hex
            std::string hex;
            size_t limit = len;
            if (limit > 8192) limit = 8192;
            hex.reserve(limit * 3 + 128);
            char buf[4];
            for (size_t i = 0; i < limit; i++) {
                sprintf_s(buf, "%02X ", (unsigned char)s[i]);
                hex += buf;
                if ((i + 1) % 16 == 0) hex += "\n";
            }
            if (len > limit) hex += "\n... (Truncated)";
            bytecode = "-- Bytecode via string.dump (" + std::to_string(len) + " bytes):\n" + hex;
        }
    }

    // Clean up: Pop 5 items [string, dump, _G, func, result]
    p_settop(m_L, -6);

    return bytecode;
}

// Helper: FindPattern (IDA Style)
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// Minimal Length Disassembler (LDE) for x64 Prologues
// ----------------------------------------------------------------------------
int GetInstructionLength(uint8_t* ip) {
    uint8_t b = *ip;

    // 1. PUSH reg / POP reg (50-5F)
    if (b >= 0x50 && b <= 0x5F) return 1;

    // 2. REX Prefixes (40-4F)
    if (b >= 0x40 && b <= 0x4F) {
        // Next byte is opcode
        uint8_t op = *(ip + 1);

        // PUSH/POP with REX (e.g. 40 53 -> PUSH RBX)
        if (op >= 0x50 && op <= 0x5F) return 2;

        // MOV [RSP+disp8], Reg (48 89 5C 24 08)
        // 48 89 ModRM(5C) SIB(24) Disp8(08)
        if (op == 0x89) {
            uint8_t modrm = *(ip + 2);
            // ModRM: Mod(2) Reg(3) RM(3)
            // Check for SIB byte (RM=4, i.e., 100 binary)
            int hasSIB = ((modrm & 0x07) == 0x04);
            int dispSize = 0;
            int mod = (modrm >> 6);
            if (mod == 1) dispSize = 1;
            if (mod == 2) dispSize = 4;
            // mod=0 usually 0 disp, unless RM=5 (RIP rel)

            // Simplification for common prologue moves:
            // 48 89 5C 24 08 -> Mod=1(disp8), RM=4(SIB) -> 1+1+1+1+1 = 5
            return 2 + 1 + (hasSIB ? 1 : 0) + dispSize;
        }

        // SUB RSP, imm8 (48 83 EC 20)
        if (op == 0x83) return 4;

        // SUB RSP, imm32 (48 81 EC ...)
        if (op == 0x81) return 7;

        // MOV RBP, RSP (48 8B EC)
        if (op == 0x8B) return 3;
    }

    // 3. SUB RSP, imm8 (without REX? usually has REX for 64-bit operand, but could be 32-bit stack op)

    // 4. MOV [RSP+...], ... (No REX)
    if (b == 0x89) {
         uint8_t modrm = *(ip + 1);
         int hasSIB = ((modrm & 0x07) == 0x04);
         int dispSize = 0;
         int mod = (modrm >> 6);
         if (mod == 1) dispSize = 1;
         if (mod == 2) dispSize = 4;
         return 1 + 1 + (hasSIB ? 1 : 0) + dispSize;
    }

    return 0; // Unknown
}

int CalcTrampolineSize(void* target, int minSize) {
    int size = 0;
    uint8_t* p = (uint8_t*)target;
    while (size < minSize) {
        int len = GetInstructionLength(p + size);
        if (len == 0) return 0; // Unknown instruction, unsafe to hook
        size += len;
    }
    return size;
}

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

void LuaInterface::CreateTrampoline(void* target, void*& trampoline) {
    if (!target) return;

    // Safety: Calculate exact size of instructions to steal (>= 12 bytes)
    int stolenSize = CalcTrampolineSize(target, 12);
    if (stolenSize == 0) {
        std::cout << "[Agent] Unsafe Trampoline (Complex Prologue). Aborting." << std::endl;
        trampoline = nullptr;
        return;
    }

    // Safety: Check for relative instructions in the stolen bytes
    uint8_t* t = (uint8_t*)target;
    for (int i = 0; i < stolenSize; i++) {
        uint8_t b = t[i];
        if (b == 0xE8 || b == 0xE9 || b == 0xEB) {
            std::cout << "[Agent] Unsafe Trampoline detected (Relative Jump/Call) at +" << i << ". Aborting Trampoline." << std::endl;
            trampoline = nullptr;
            return;
        }
    }

    void* buffer = VirtualAlloc(nullptr, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!buffer) return;

    // Copy stolen instructions
    memcpy(buffer, target, stolenSize);

    // Write JMP back to target + stolenSize
    uint8_t* p = (uint8_t*)buffer + stolenSize;
    // MOV RAX, target + stolenSize
    *p++ = 0x48; *p++ = 0xB8;
    uintptr_t dest = (uintptr_t)target + stolenSize;
    memcpy(p, &dest, 8);
    p += 8;
    // JMP RAX
    *p++ = 0xFF; *p++ = 0xE0;

    FlushInstructionCache(GetCurrentProcess(), buffer, 64);
    trampoline = buffer;

    // NOTE: Actual hook installation (overwriting target) is done in EnableHook or here?
    // The previous code did it in EnableHook using hardcoded 12.
    // We must update m_Hooks to store the stolenSize so EnableHook knows how many NOPs to write.
    // However, Hook struct doesn't have size.
    // For simplicity, we can do the patching HERE if we change how hooks are managed,
    // OR we assume 12 bytes for the JMP and just patch the NOPs here?
    // Wait, EnableHook overwrites 12 bytes. If stolenSize > 12, we need to NOP bytes 12..(stolenSize-1).
    // We can do that here? No, if we DisableHook, we need to restore ALL stolen bytes.
    // The Hook struct needs to know 'stolenSize'.

    std::cout << "[Agent] Created Trampoline for " << target << " (Size: " << stolenSize << ")" << std::endl;
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
    p_rawgeti   = (lua_rawgeti_t)Resolve("lua_rawgeti");
    p_iscfunction = (lua_iscfunction_t)Resolve("lua_iscfunction");
    p_pushcclosure = (lua_pushcclosure_t)Resolve("lua_pushcclosure");
    p_setglobal = (lua_setglobal_t)Resolve("lua_setglobal");
    p_getglobal = (lua_getglobal_t)Resolve("lua_getglobal");

    // Add lua_dump pattern
    p_dump = (lua_dump_t)Resolve("lua_dump", "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 30 48 8B 02 48 8B F9");
    if (p_dump) std::cout << "[Agent] Found lua_dump." << std::endl;
    else std::cout << "[Agent] lua_dump NOT found." << std::endl;

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

    auto AddHook = [&](void* target, void* detour, const char* name, int size = 12) {
        if (!target) return;
        Hook h;
        h.target = target;
        h.detour = detour;
        h.size = size;
        h.active = false;
        memcpy(h.original, target, size);
        m_Hooks.push_back(h);
        std::cout << "[Agent] Added Hook: " << name << " at " << target << " (Size: " << size << ")" << std::endl;
    };

    // Standard Hooks (Assume 12 bytes is safe for start of functions usually, but standard hooks restore original so tearing is less critical if we don't execute partials... wait, we do)
    // Actually, for standard hooks we disable, execute original, enable.
    // If we tore an instruction, 'Disable' restores it fully, so it's fine.
    // So 12 bytes is fine for standard hooks as long as we don't crash WRITING them (atomicity?).
    // But we use VirtualProtect, so it's not atomic. But we are in a single thread usually when hooking? No, game threads run.
    // Ideally we should use the same LDE logic for ALL hooks.

    int sz = 0;

    if (p_loadbufferx) {
        sz = CalcTrampolineSize((void*)p_loadbufferx, 12);
        if (sz > 0) AddHook((void*)p_loadbufferx, (void*)MyLuaLoadBufferX, "luaL_loadbufferx", sz);
    }

    if (p_loadstring) {
        sz = CalcTrampolineSize((void*)p_loadstring, 12);
        if (sz > 0) AddHook((void*)p_loadstring, (void*)MyLuaLoadString, "luaL_loadstring", sz);
    }

    // Trampoline Hooks
    if (p_pcallk) {
        // CreateTrampoline now returns the trampoline address but we need to know the stolen size for the hook
        // Let's modify CreateTrampoline to return size or just recalculate it?
        // CreateTrampoline prints it. Let's make CreateTrampoline return the size via reference?
        // Or just recalculate it here.
        int trampolineSize = CalcTrampolineSize((void*)p_pcallk, 12);
        if (trampolineSize > 0) {
            CreateTrampoline((void*)p_pcallk, p_pcallk_trampoline);
            if (p_pcallk_trampoline) AddHook((void*)p_pcallk, (void*)MyLuaPcallK, "lua_pcallk", trampolineSize);
        }
    }

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
        VirtualProtect(h.target, h.size, PAGE_EXECUTE_READWRITE, &old);

        // 1. Write Absolute JMP (12 bytes)
        uint8_t patch[12];
        patch[0] = 0x48; patch[1] = 0xB8;
        uintptr_t dest = (uintptr_t)h.detour;
        memcpy(&patch[2], &dest, 8);
        patch[10] = 0xFF; patch[11] = 0xE0;

        memcpy(h.target, patch, 12);

        // 2. NOP remaining bytes
        if (h.size > 12) {
            memset((uint8_t*)h.target + 12, 0x90, h.size - 12);
        }

        VirtualProtect(h.target, h.size, old, &old);
        FlushInstructionCache(GetCurrentProcess(), h.target, h.size);
        h.active = true;
    }
}

void LuaInterface::DisableHook() {
    for (auto& h : m_Hooks) {
        if (!h.active) continue;
        DWORD old;
        VirtualProtect(h.target, h.size, PAGE_EXECUTE_READWRITE, &old);
        memcpy(h.target, h.original, h.size);
        VirtualProtect(h.target, h.size, old, &old);
        FlushInstructionCache(GetCurrentProcess(), h.target, h.size);
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

bool LuaInterface::DumpGlobals(HANDLE hPipe) {
    return SafeInvoke([&]() {
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

                // Safe Key Formatting (Copy first)
                p_pushvalue(m_L, -2);
                std::string kStr = FormatLuaValue(-1);
                out.append(kStr);
                p_settop(m_L, -2); // Pop key copy

                int type = p_type(m_L, -1);
                const char* typeName = p_typename(m_L, type);
                out.append(" ["); out.append(typeName); out.append("]");

                // Safe Value Formatting (Copy first)
                p_pushvalue(m_L, -1);
                std::string val = FormatLuaValue(-1);
                p_settop(m_L, -2); // Pop value copy

                if (type == 4) {
                     if (val.length() > 64) val = val.substr(0, 61) + "...";
                     out.append(" = \""); out.append(val); out.append("\"");
                } else {
                     out.append(" = "); out.append(val);
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
        MessageHeader h = { 0, RESP_OK };
        DWORD w; WriteFile(hPipe, &h, sizeof(h), &w, NULL);
    });
}

bool LuaInterface::DumpRegistry(HANDLE hPipe) {
    return SafeInvoke([&]() {
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

                // Key (Copy)
                p_pushvalue(m_L, -2);
                std::string kStr = FormatLuaValue(-1);
                out.append(kStr);
                p_settop(m_L, -2);
                out.append("|");

                // Type
                int vType = p_type(m_L, -1);
                out.append(p_typename(m_L, vType));
                out.append("|");

                // Value (Copy)
                p_pushvalue(m_L, -1);
                std::string vStr = FormatLuaValue(-1);
                p_settop(m_L, -2);

                if (vType == 4 && vStr.length() > 30) vStr = vStr.substr(0, 27) + "...";
                out.append(vStr);
                out.append("\n");
                p_settop(m_L, -2);
            }
        }
        p_settop(m_L, -2);

        MessageHeader h = { (uint32_t)out.size(), RESP_DATA };
        DWORD w; WriteFile(hPipe, &h, sizeof(h), &w, NULL);
        WriteFile(hPipe, out.data(), out.size(), &w, NULL);

        MessageHeader tok = { 0, RESP_OK };
        WriteFile(hPipe, &tok, sizeof(tok), &w, NULL);
    });
}

bool LuaInterface::InspectRegistryItem(HANDLE hPipe, const std::string& keyStr) {
    return SafeInvoke([&]() {
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

        std::string out = "Inspection Results for: " + keyStr + "\n";
        out.reserve(65536);

        // Push Registry
        p_pushvalue(m_L, -1001000); // LUA_REGISTRYINDEX

        // Try to find the item
        bool found = false;
        if (p_getfield) {
            p_getfield(m_L, -1, keyStr.c_str());
            if (p_type(m_L, -1) != 0) { // Not nil
                found = true;
            } else {
                p_settop(m_L, -2); // Pop nil
            }
        }

        if (!found && p_rawgeti) {
            try {
                long long idx = std::stoll(keyStr);
                p_rawgeti(m_L, -1, idx);
                if (p_type(m_L, -1) != 0) {
                    found = true;
                } else {
                    p_settop(m_L, -2); // Pop nil
                }
            } catch (...) {}
        }

        if (!found) {
            out += "Item not found in Registry.";
            p_settop(m_L, -2); // Pop Registry
        } else {
            // Item is at top of stack (-1), Registry is at (-2)
            int targetType = p_type(m_L, -1);
            out += "Type: " + std::string(p_typename(m_L, targetType)) + "\n";

            if (targetType == 5) { // Table
                out += "Table Content:\n";
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
                    }
                    if (count > 10000) { out.append("... Truncated ...\n"); p_settop(m_L, -3); break; }

                    // Key (Copy)
                    p_pushvalue(m_L, -2);
                    std::string kStr = FormatLuaValue(-1);
                    out.append(kStr);
                    p_settop(m_L, -2);
                    out.append("|");

                    // Value Type
                    int vType = p_type(m_L, -1);
                    out.append(p_typename(m_L, vType));
                    out.append("|");

                    // Value (Copy)
                    p_pushvalue(m_L, -1);
                    std::string vStr = FormatLuaValue(-1);
                    p_settop(m_L, -2);

                    if (vType == 4 && vStr.length() > 30) vStr = vStr.substr(0, 27) + "...";
                    out.append(vStr);
                    out.append("\n");
                    p_settop(m_L, -2);
                }
                if (count == 0) out += "(Empty Table)\n";
            } else {
                out += "Value is not a table. (Type: " + std::string(p_typename(m_L, targetType)) + ")";
            }
            p_settop(m_L, -2); // Pop item
            p_settop(m_L, -2); // Pop Registry
        }

        MessageHeader h = { (uint32_t)out.size(), RESP_DATA };
        DWORD w; WriteFile(hPipe, &h, sizeof(h), &w, NULL);
        WriteFile(hPipe, out.data(), out.size(), &w, NULL);

        MessageHeader tok = { 0, RESP_OK };
        WriteFile(hPipe, &tok, sizeof(tok), &w, NULL);
    });
}

bool LuaInterface::ScanPlayers(HANDLE hPipe) {
    return SafeInvoke([&]() {
        if (!m_L) {
            std::string msg = "Lua State not ready.";
            MessageHeader h = { (uint32_t)msg.size(), RESP_ERROR };
            DWORD w; WriteFile(hPipe, &h, sizeof(h), &w, NULL);
            WriteFile(hPipe, msg.data(), msg.size(), &w, NULL);
            return;
        }
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

        MessageHeader tok = { 0, RESP_OK };
        WriteFile(hPipe, &tok, sizeof(tok), &w, NULL);
    });
}

bool LuaInterface::DumpScripts(HANDLE hPipe) {
    return SafeInvoke([&]() {
        if (!m_L) {
            std::string msg = "Lua State not ready.";
            MessageHeader h = { (uint32_t)msg.size(), RESP_ERROR };
            DWORD w; WriteFile(hPipe, &h, sizeof(h), &w, NULL);
            WriteFile(hPipe, msg.data(), msg.size(), &w, NULL);
            return;
        }
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

        MessageHeader tok = { 0, RESP_OK };
        WriteFile(hPipe, &tok, sizeof(tok), &w, NULL);
    });
}

// Writer for lua_dump
int Writer(lua_State* L, const void* p, size_t sz, void* ud) {
    std::string* s = (std::string*)ud;
    s->append((const char*)p, sz);
    return 0;
}

bool LuaInterface::GetScriptSource(HANDLE hPipe, const std::string& name) {
    return SafeInvoke([&]() {
        if (!m_L) {
            std::string msg = "Lua State not ready.";
            MessageHeader h = { (uint32_t)msg.size(), RESP_ERROR };
            DWORD w; WriteFile(hPipe, &h, sizeof(h), &w, NULL);
            WriteFile(hPipe, msg.data(), msg.size(), &w, NULL);
            return;
        }
        std::string src = GetOverride(name);

        if (src.empty()) {
            if (p_getglobal && p_getfield) {
                p_getglobal(m_L, "_G");
                p_getfield(m_L, -1, name.c_str());
                if (p_type(m_L, -1) == 6) {
                    bool dumped = false;

                    // Try dumping first
                    if (p_dump) {
                        std::string bytecode;
                        int dumpRes = p_dump(m_L, Writer, &bytecode, 0);
                        if (dumpRes == 0) {
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
                            dumped = true;
                        }
                    }

                    if (!dumped) {
                        // Attempt fallback via string.dump (Lua API)
                        std::string luaDump = GetBytecodeViaLua(name);
                        if (!luaDump.empty()) {
                            src = luaDump;
                            dumped = true;
                        }
                    }

                    if (!dumped) {
                        if (p_iscfunction && p_iscfunction(m_L, -1)) {
                            src = "-- Source for " + name + "\n-- [C Function] (No Bytecode Available)";
                        } else if (!p_dump) {
                            src = "-- Source retrieval unavailable: lua_dump symbol not found, and string.dump failed.\n";
                        } else {
                            src = "-- Source for " + name + "\n-- (lua_dump returned non-zero error)\n-- You can set an Override for this script.";
                        }
                    }
                } else {
                    src = "-- Source for " + name + "\n-- (Object is not a function)\n";
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

        MessageHeader tok = { 0, RESP_OK };
        WriteFile(hPipe, &tok, sizeof(tok), &w, NULL);
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
std::atomic<bool> g_HasTasks{false};

std::mutex g_LogMutex;
std::vector<std::string> g_LogQueue;

void AppendLog(const std::string& msg) {
    std::lock_guard<std::mutex> lock(g_LogMutex);
    g_LogQueue.push_back(msg);
    if (g_LogQueue.size() > 1000) g_LogQueue.erase(g_LogQueue.begin());
}

bool HasPendingTasks() {
    return g_HasTasks.load(std::memory_order_relaxed);
}

bool LuaInterface::ProcessTasks() {
    bool didWork = false;

    auto SendError = [](HANDLE pipe, const std::string& msg) {
        MessageHeader h = { (uint32_t)msg.size(), RESP_ERROR };
        DWORD w; WriteFile(pipe, &h, sizeof(h), &w, NULL);
        WriteFile(pipe, msg.data(), msg.size(), &w, NULL);
    };

    while (true) {
        Task t;
        {
            std::lock_guard<std::mutex> lock(g_TaskMutex);
            if (g_TaskQueue.empty()) {
                g_HasTasks = false;
                break;
            }
            t = g_TaskQueue.front();
            g_TaskQueue.pop();
            g_HasTasks = !g_TaskQueue.empty();
            didWork = true;
        }

        if (t.type == CMD_PING) {
            MessageHeader h = { 0, RESP_OK };
            DWORD w; WriteFile(t.pipe, &h, sizeof(h), &w, NULL);
        } else if (t.type == CMD_RUN_SCRIPT) {
            if (!SafeInvoke([&]() {
                if (!m_L) {
                    std::string err = "Lua state not ready (hooks not installed).";
                    SendError(t.pipe, err);
                } else {
                    std::string err;
                    try {
                        if (LoadScript(t.payload, err)) {
                            MessageHeader h = { 0, RESP_OK };
                            DWORD w; WriteFile(t.pipe, &h, sizeof(h), &w, NULL);
                        } else {
                            SendError(t.pipe, err);
                        }
                    } catch (...) {
                        SendError(t.pipe, "Exception caught during LoadScript");
                    }
                }
            })) {
                 SendError(t.pipe, "Agent Internal Error (Exception during RunScript)");
            }
        } else if (t.type == CMD_DUMP_GLOBALS) {
            if (!DumpGlobals(t.pipe)) SendError(t.pipe, "Agent Internal Error (Exception during DumpGlobals)");
        } else if (t.type == CMD_SCAN_PLAYERS) {
            if (!ScanPlayers(t.pipe)) SendError(t.pipe, "Agent Internal Error (Exception during ScanPlayers)");
        } else if (t.type == CMD_DUMP_REGISTRY) {
            if (!DumpRegistry(t.pipe)) SendError(t.pipe, "Agent Internal Error (Exception during DumpRegistry)");
        } else if (t.type == CMD_INSPECT_REGISTRY_ITEM) {
            if (!InspectRegistryItem(t.pipe, t.payload)) SendError(t.pipe, "Agent Internal Error (Exception during InspectRegistryItem)");
        } else if (t.type == CMD_DUMP_SCRIPTS) {
            if (!DumpScripts(t.pipe)) SendError(t.pipe, "Agent Internal Error (Exception during DumpScripts)");
        } else if (t.type == CMD_GET_SCRIPT_SOURCE) {
            if (!GetScriptSource(t.pipe, t.payload)) SendError(t.pipe, "Agent Internal Error (Exception during GetScriptSource)");
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

            MessageHeader tok = { 0, RESP_OK };
            WriteFile(t.pipe, &tok, sizeof(tok), &w, NULL);
        }
        // Do not CloseHandle(t.pipe) here as it is managed by PipeServerThread
    }
    return didWork;
}

void PipeServerThread() {
    char pipeName[256];
    sprintf_s(pipeName, "\\\\.\\pipe\\luatool_%lu", GetCurrentProcessId());
    std::cout << "[Agent] Pipe Server: " << pipeName << std::endl;

    // Create a single pipe instance (or recreate if needed)
    while (true) {
        HANDLE hPipe = CreateNamedPipeA(pipeName, PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES, 512, 512, 0, NULL);

        if (hPipe == INVALID_HANDLE_VALUE) {
            std::cout << "[Agent] CreateNamedPipe Failed. Error: " << GetLastError() << std::endl;
            std::this_thread::sleep_for(std::chrono::seconds(1));
            continue;
        }

        std::cout << "[Agent] Pipe Listening..." << std::endl;
        if (ConnectNamedPipe(hPipe, NULL) || GetLastError() == ERROR_PIPE_CONNECTED) {
            std::cout << "[Agent] Client Connected." << std::endl;

            // Loop for this session
            while (true) {
                MessageHeader h;
                DWORD r;
                if (!ReadFile(hPipe, &h, sizeof(h), &r, NULL) || r != sizeof(h)) {
                    // Client disconnected
                    std::cout << "[Agent] Client Disconnected." << std::endl;
                    break;
                }

                std::string payload;
                if (h.length > 0) {
                    std::vector<char> b(h.length);
                    if (!ReadFile(hPipe, b.data(), h.length, &r, NULL) || r != h.length) {
                        std::cout << "[Agent] Error reading payload." << std::endl;
                        break;
                    }
                    payload.assign(b.begin(), b.end());
                }

                // std::cout << "[Agent] Task Queued. Type: " << (int)h.type << std::endl; // Reduce spam
                {
                    std::lock_guard<std::mutex> lock(g_TaskMutex);
                    g_TaskQueue.push({ h.type, payload, hPipe });
                    g_HasTasks = true;
                }

                // If not loaded, process immediately (for initialization tasks)
                if (!LuaInterface::Get().IsLoaded()) {
                     LuaInterface::Get().ProcessTasks();
                }
            }
            DisconnectNamedPipe(hPipe);
        } else {
            std::cout << "[Agent] ConnectNamedPipe Failed. Error: " << GetLastError() << std::endl;
        }
        CloseHandle(hPipe);
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
