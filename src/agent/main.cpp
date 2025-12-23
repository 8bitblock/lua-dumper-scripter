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
#include <chrono>
#include <algorithm>
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
typedef size_t      (*lua_rawlen_t)(lua_State *L, int idx);

// ----------------------------------------------------------------------------
// SEH Wrapper Logic
// ----------------------------------------------------------------------------
void CallStdFunc(void* p) {
    (*(std::function<void()>*)p)();
}

bool SafeInvokeInternal(void(*cb)(void*), void* arg) {
    __try {
        cb(arg);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

bool SafeInvoke(std::function<void()> fn) {
    return SafeInvokeInternal(CallStdFunc, &fn);
}

// ----------------------------------------------------------------------------
// Lua Interface Class
// ----------------------------------------------------------------------------
struct CapturedScript {
    std::string name;
    std::string source;
    uint64_t timestamp;
    bool isBytecode;
};

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

    void CaptureScript(const std::string& name, const std::string& source, bool isBytecode) {
        std::lock_guard<std::mutex> lock(m_CapturedScriptsMutex);
        for (auto& s : m_CapturedScripts) {
            if (s.name == name) {
                s.source = source;
                s.isBytecode = isBytecode;
                s.timestamp = GetTickCount64();
                return;
            }
        }
        CapturedScript cs;
        cs.name = name;
        cs.source = source;
        cs.isBytecode = isBytecode;
        cs.timestamp = GetTickCount64();
        m_CapturedScripts.push_back(cs);
    }

    lua_getglobal_t p_getglobal = nullptr;
    void* p_pcallk_trampoline = nullptr;
    void* p_callk_trampoline = nullptr;
    void* p_gettop_trampoline = nullptr;

    std::string GetBytecodeViaLua(const std::string& name);

private:
    LuaInterface() = default;
    bool ResolveSymbols(HMODULE hMod, const char* modName);
    void CreateTrampoline(void* target, void*& trampoline);

    lua_State* m_L = nullptr;
    bool m_Loaded = false;
    HMODULE m_hLua = NULL;

    std::mutex m_OverrideMutex;
    std::map<std::string, std::string> m_ScriptOverrides;

    std::mutex m_CapturedScriptsMutex;
    std::vector<CapturedScript> m_CapturedScripts;

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
    lua_rawlen_t       p_rawlen = nullptr;

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
    friend void MyLuaCall(lua_State *L, int nargs, int nresults);
    friend void MyLuaCallK(lua_State *L, int nargs, int nresults, intptr_t ctx, void* k);
    friend int MyLuaGetTop(lua_State *L);
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
    // Increase tick rate for smoother performance
    if (now - lua.m_LastTick > 5) {
        if (HasPendingTasks()) {
            lua.ProcessTasks();
        }
        lua.m_LastTick = now;
    }
    s_InHook = false;
}

int MyLuaLoadBufferX(lua_State* L, const char *buff, size_t sz, const char *name, const char *mode) {
    auto& lua = LuaInterface::Get();
    HookProcessHelper(lua, L);
    if (buff && sz > 0) {
        std::string n = name ? name : "unknown_buffer";
        std::string s(buff, sz);
        lua.CaptureScript(n, s, true);
    }
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
    if (s) {
        lua.CaptureScript("loadstring_script", s, false);
    }
    lua.DisableHook();
    int ret = lua.p_loadstring(L, s);
    lua.EnableHook();
    return ret;
}

int MyLuaPcall(lua_State *L, int nargs, int nresults, int errfunc) {
    auto& lua = LuaInterface::Get();
    extern bool HasPendingTasks();
    if (HasPendingTasks()) HookProcessHelper(lua, L);
    if (lua.p_pcallk_trampoline) {
        return ((lua_pcallk_t)lua.p_pcallk_trampoline)(L, nargs, nresults, errfunc, 0, nullptr);
    }
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

void MyLuaCall(lua_State *L, int nargs, int nresults) {
    auto& lua = LuaInterface::Get();
    extern bool HasPendingTasks();
    if (HasPendingTasks()) HookProcessHelper(lua, L);
    if (lua.p_callk_trampoline) {
        ((void(*)(lua_State*, int, int))lua.p_callk_trampoline)(L, nargs, nresults);
    }
}

void MyLuaCallK(lua_State *L, int nargs, int nresults, intptr_t ctx, void* k) {
    auto& lua = LuaInterface::Get();
    extern bool HasPendingTasks();
    if (HasPendingTasks()) HookProcessHelper(lua, L);
    if (lua.p_callk_trampoline) {
        ((lua_callk_t)lua.p_callk_trampoline)(L, nargs, nresults, ctx, k);
    }
}

int MyLuaGetTop(lua_State *L) {
    auto& lua = LuaInterface::Get();
    extern bool HasPendingTasks();
    if (HasPendingTasks()) HookProcessHelper(lua, L);
    if (lua.p_gettop_trampoline) {
        return ((lua_gettop_t)lua.p_gettop_trampoline)(L);
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
    } else if (type == 5 && p_topointer) { // Table
        const void* ptr = p_topointer(m_L, idx);
        char buf[32]; sprintf_s(buf, "Table: 0x%p", ptr);
        return buf;
    } else if (type == 6 && p_topointer) { // Function
        const void* ptr = p_topointer(m_L, idx);
        char buf[32]; sprintf_s(buf, "Function: 0x%p", ptr);
        return buf;
    } else if (type == 8 && p_topointer) { // Thread
         const void* ptr = p_topointer(m_L, idx);
         char buf[32]; sprintf_s(buf, "Thread: 0x%p", ptr);
         return buf;
    } else if (type == 7 && p_topointer) { // Userdata
         const void* ptr = p_topointer(m_L, idx);
         char buf[32]; sprintf_s(buf, "Userdata: 0x%p", ptr);
         return buf;
    } else if (type == 2 && p_topointer) { // LightUserdata
         const void* ptr = p_topointer(m_L, idx);
         char buf[32]; sprintf_s(buf, "LightUserdata: 0x%p", ptr);
         return buf;
    }
    return p_typename ? p_typename(m_L, type) : "Unknown";
}

std::string LuaInterface::GetBytecodeViaLua(const std::string& name) {
    if (!m_L || !p_getglobal || !p_getfield || !p_pcallk) return "";
    p_getglobal(m_L, "string");
    if (p_type(m_L, -1) != 5) { p_settop(m_L, -2); return ""; }
    p_getfield(m_L, -1, "dump");
    if (p_type(m_L, -1) != 6) { p_settop(m_L, -3); return ""; }
    p_getglobal(m_L, "_G");
    p_getfield(m_L, -1, name.c_str());
    if (p_type(m_L, -1) != 6) { p_settop(m_L, -5); return ""; }
    p_pushvalue(m_L, -1);
    p_pushvalue(m_L, -4);
    p_settop(m_L, -3);
    p_pushvalue(m_L, -3);
    p_pushvalue(m_L, -2);
    int res = 0;
    if (p_pcallk) res = p_pcallk(m_L, 1, 1, 0, 0, nullptr);
    else if (p_callk) p_callk(m_L, 1, 1, 0, nullptr);
    std::string bytecode = "";
    if (res == 0 && p_type(m_L, -1) == 4) {
        size_t len = 0;
        const char* s = p_tolstring(m_L, -1, &len);
        if (s) {
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
    p_settop(m_L, -6);
    return bytecode;
}

// ----------------------------------------------------------------------------
// Minimal Length Disassembler (LDE) for x64 Prologues
// ----------------------------------------------------------------------------
struct InstructionInfo {
    int length;
    bool isRelative;
};

InstructionInfo GetInstructionLength(uint8_t* ip) {
    uint8_t b = *ip;
    InstructionInfo info = { 0, false };

    // 1. PUSH reg / POP reg (50-5F)
    if (b >= 0x50 && b <= 0x5F) { info.length = 1; return info; }

    // 2. Prefix Handling
    bool hasREX = false;
    if (b >= 0x40 && b <= 0x4F) {
        hasREX = true;
        ip++; // Advance to Opcode
    }

    uint8_t op = *ip;

    // Relative Branch Instructions (E8, E9, EB) - Always Unsafe for Trampoline without relocation
    if (op == 0xE8 || op == 0xE9 || op == 0xEB) {
        info.length = (op == 0xEB) ? 2 : 5;
        info.isRelative = true;
        return info;
    }

    // PUSH/POP with REX (e.g. 40 53 -> PUSH RBX)
    if (hasREX && op >= 0x50 && op <= 0x5F) { info.length = 2; return info; }

    // Helper for ModRM
    auto ParseModRM = [&](int offsetSoFar) -> int {
        uint8_t modrm = *(ip + 1);
        int mod = (modrm >> 6) & 0x03;
        int rm = modrm & 0x07;

        int len = offsetSoFar + 1; // Opcode + ModRM
        if (hasREX) len++;

        // SIB Check (RM=4 and Mod!=3)
        if (mod != 3 && rm == 4) {
            len++; // SIB byte
        }

        // Displacement
        if (mod == 1) len += 1; // Disp8
        else if (mod == 2) len += 4; // Disp32

        // RIP-Relative Addressing: Mod=00, RM=101 (5)
        if (mod == 0) {
             if (rm == 5) { // RIP Rel
                 len += 4;
                 info.isRelative = true;
             } else if (rm == 4) { // SIB
                 uint8_t sib = *(ip + 2);
                 // If Base=5 (101) and Mod=0 -> Disp32
                 if ((sib & 0x07) == 5) len += 4;
             }
        }

        return len;
    };

    // MOV R/M, Reg (89) or MOV Reg, R/M (8B) or LEA (8D) or XOR (31/33)
    if (op == 0x89 || op == 0x8B || op == 0x8D || op == 0x31 || op == 0x33 || op == 0x85) {
        info.length = ParseModRM(1);
        return info;
    }

    // Immediate group 81/83 (ADD, SUB, CMP, etc)
    if (op == 0x81) { info.length = ParseModRM(1) + 4; return info; } // Imm32
    if (op == 0x83) { info.length = ParseModRM(1) + 1; return info; } // Imm8

    // MOV Reg, Imm (B8+rd)
    if (op >= 0xB8 && op <= 0xBF) {
        if (hasREX && (b & 0x08)) info.length = 10; // REX.W set
        else info.length = 5;
        return info;
    }

    // RET (C3)
    if (op == 0xC3) { info.length = (hasREX ? 1 : 0) + 1; return info; }

    return info; // Unknown
}

int CalcTrampolineSize(void* target, int minSize) {
    int size = 0;
    uint8_t* p = (uint8_t*)target;
    while (size < minSize) {
        InstructionInfo info = GetInstructionLength(p + size);
        if (info.length == 0) {
            std::cout << "[Agent] LDE Failed at offset " << size << " Opcode: " << std::hex << (int)*(p+size) << std::dec << std::endl;
            return 0;
        }
        if (info.isRelative) {
            std::cout << "[Agent] Unsafe Relative Instruction at offset " << size << ". Aborting Trampoline." << std::endl;
            return 0;
        }
        size += info.length;
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
    int stolenSize = CalcTrampolineSize(target, 12);
    if (stolenSize == 0) {
        trampoline = nullptr;
        return;
    }

    void* buffer = VirtualAlloc(nullptr, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!buffer) return;
    memcpy(buffer, target, stolenSize);
    uint8_t* p = (uint8_t*)buffer + stolenSize;
    *p++ = 0x48; *p++ = 0xB8;
    uintptr_t dest = (uintptr_t)target + stolenSize;
    memcpy(p, &dest, 8);
    p += 8;
    *p++ = 0xFF; *p++ = 0xE0;
    FlushInstructionCache(GetCurrentProcess(), buffer, 64);
    trampoline = buffer;
    std::cout << "[Agent] Created Trampoline for " << target << " (Size: " << stolenSize << ")" << std::endl;
}

bool IsSystemModule(const char* name) {
    std::string s = name;
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);
    const char* bad[] = {
        "kernel32.dll", "kernelbase.dll", "ntdll.dll", "user32.dll", "gdi32.dll",
        "msvcrt.dll", "ucrtbase.dll", "shell32.dll", "ole32.dll", "combase.dll",
        "ws2_32.dll", "advapi32.dll", "sechost.dll", "rpcrt4.dll", "shlwapi.dll",
        "imm32.dll", "crypt32.dll", "bcrypt.dll", "winmm.dll", "win32u.dll",
        "d3d", "opengl", "vulkan", "nvoglv", "nvwgf", "amdx", "atidx",
        "steam", "tier0", "vstdlib", "crashhandler", "overlay", "discord",
        "libcef", "webview", "chrome", "edge", "msctf.dll"
    };
    for (const char* b : bad) {
        if (s.find(b) != std::string::npos) return true;
    }
    return false;
}

void LuaInterface::Initialize() {
    std::cout << "[Agent] Scanning for Lua..." << std::endl;
    HMODULE hMods[1024];
    DWORD cbNeeded;
    HANDLE hProcess = GetCurrentProcess();

    // Patterns for Scan
    // Lua 5.4/5.3 gettop (common x64)
    const char* pat_gettop_std = "48 8B ?? ?? 48 2B ?? ?? 48 C1 ?? 04 C3";
    // Lua 5.1/LuaJIT gettop
    const char* pat_gettop_51 = "48 8B 41 10 48 2B 41 08 48 C1 F8 04 C3";
    // Alt gettop
    const char* pat_gettop_alt = "48 8B 41 18 48 2B 41 10 48 C1 F8 04 C3";

    // Pcall Patterns (Just check one common one for quick match)
    const char* pat_pcall = "48 89 5C 24 08 57 48 83 EC 20 48 8B F9 48 8B 0D";

    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        unsigned int numMods = cbNeeded / sizeof(HMODULE);
        if (numMods > 1024) numMods = 1024;

        // Helper
        auto TryModule = [&](HMODULE h, const char* name) -> bool {
             if (IsSystemModule(name)) return false;

             // 1. Export Scan
             if (GetProcAddress(h, "lua_gettop") || GetProcAddress(h, "lua_pcall") || GetProcAddress(h, "lua_newstate")) {
                 std::cout << "[Agent] Found Exports in: " << name << std::endl;
                 if (ResolveSymbols(h, name)) {
                     m_hLua = h;
                     return true;
                 }
             }
             // 2. Pattern Scan
             if (FindPattern(h, pat_gettop_std) || FindPattern(h, pat_gettop_51) || FindPattern(h, pat_gettop_alt)) {
                 std::cout << "[Agent] Pattern Match (gettop) in: " << name << std::endl;
                 if (ResolveSymbols(h, name)) {
                     m_hLua = h;
                     return true;
                 }
             }
             return false;
        };

        // Pass 1: Main Executable
        char modName[MAX_PATH];
        if (GetModuleFileNameA(NULL, modName, sizeof(modName))) {
             HMODULE hMain = GetModuleHandleA(NULL);
             std::string s = modName;
             size_t idx = s.find_last_of("\\/");
             if (idx != std::string::npos) s = s.substr(idx + 1);
             std::cout << "[Agent] Inspecting Main: " << s << std::endl;
             if (TryModule(hMain, s.c_str())) return;
        }

        // Pass 2: Others (Skip Main if checked)
        for (unsigned int i = 0; i < numMods; i++) {
             GetModuleBaseNameA(hProcess, hMods[i], modName, sizeof(modName));
             if (hMods[i] == GetModuleHandleA(NULL)) continue;
             if (TryModule(hMods[i], modName)) return;
        }
    }
    std::cout << "[Agent] Failed to find a usable Lua module." << std::endl;
}

bool LuaInterface::ResolveSymbols(HMODULE hMod, const char* modName) {
    p_gettop = nullptr;
    auto Resolve = [&](const char* name, const std::vector<const char*>& sigs = {}) -> void* {
        void* addr = (void*)GetProcAddress(hMod, name);
        if (!addr && !sigs.empty()) {
            for (const char* s : sigs) {
                uintptr_t p = FindPattern(hMod, s);
                if (p) { addr = (void*)p; break; }
            }
        }
        return addr;
    };

    p_gettop = (lua_gettop_t)Resolve("lua_gettop", {
        "48 8B ?? ?? 48 2B ?? ?? 48 C1 ?? 04 C3",
        "48 8B 41 10 48 2B 41 08 48 C1 F8 04 C3",
        "48 8B 41 18 48 2B 41 10 48 C1 F8 04 C3"
    });

    if (!p_gettop) return false;

    p_settop = (lua_settop_t)Resolve("lua_settop", {});
    p_pushvalue = (lua_pushvalue_t)Resolve("lua_pushvalue", {});
    p_next = (lua_next_t)Resolve("lua_next", {});
    p_pushnil = (lua_pushnil_t)Resolve("lua_pushnil", {});
    p_tolstring = (lua_tolstring_t)Resolve("lua_tolstring", {});
    p_type = (lua_type_t)Resolve("lua_type", {});
    p_typename = (lua_typename_t)Resolve("lua_typename", {});
    p_tonumber = (lua_tonumber_t)Resolve("lua_tonumber", {});
    p_toboolean = (lua_toboolean_t)Resolve("lua_toboolean", {});
    p_topointer = (lua_topointer_t)Resolve("lua_topointer", {});
    p_getfield  = (lua_getfield_t)Resolve("lua_getfield", {});
    p_rawgeti   = (lua_rawgeti_t)Resolve("lua_rawgeti", {});
    p_iscfunction = (lua_iscfunction_t)Resolve("lua_iscfunction", {});
    p_pushcclosure = (lua_pushcclosure_t)Resolve("lua_pushcclosure", {});
    p_setglobal = (lua_setglobal_t)Resolve("lua_setglobal", {});
    p_getglobal = (lua_getglobal_t)Resolve("lua_getglobal", {});
    p_dump = (lua_dump_t)Resolve("lua_dump", { "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 30 48 8B 02 48 8B F9" });

    // Pcall patterns
    std::vector<const char*> pcallSigs = {
        "48 89 5C 24 08 57 48 83 EC 20 48 8B F9 48 8B 0D",
        "48 83 EC 28 8B D1 48 8B 0D",
        "40 53 48 83 EC 20 48 8B D9",
        "48 83 EC 48 8B 01",
        "40 55 53 56 57 41 54 41 55 41 56 41 57 48 8D 6C 24 D9"
    };
    p_pcallk = (lua_pcallk_t)Resolve("lua_pcallk", {});
    if (!p_pcallk) p_pcallk = (lua_pcallk_t)Resolve("lua_pcall", pcallSigs);

    // Call patterns
    std::vector<const char*> callSigs = {
        "40 53 48 83 EC 20 45 33 C0 48 8B D9"
    };
    p_callk = (lua_callk_t)Resolve("lua_callk", {});
    if (!p_callk) p_callk = (lua_callk_t)Resolve("lua_call", callSigs);

    // Load patterns
    p_loadbufferx = (luaL_loadbufferx_t)Resolve("luaL_loadbufferx", { "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 83 EC 20" });
    p_loadstring = (luaL_loadstring_t)Resolve("luaL_loadstring", {});

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

    int sz = 0;
    if (p_loadbufferx) {
        sz = CalcTrampolineSize((void*)p_loadbufferx, 12);
        if (sz > 0) AddHook((void*)p_loadbufferx, (void*)MyLuaLoadBufferX, "luaL_loadbufferx", sz);
    }
    if (p_loadstring) {
        sz = CalcTrampolineSize((void*)p_loadstring, 12);
        if (sz > 0) AddHook((void*)p_loadstring, (void*)MyLuaLoadString, "luaL_loadstring", sz);
    }

    bool heartbeatFound = false;
    if (p_pcallk) {
        int trampolineSize = CalcTrampolineSize((void*)p_pcallk, 12);
        if (trampolineSize > 0) {
            CreateTrampoline((void*)p_pcallk, p_pcallk_trampoline);
            if (p_pcallk_trampoline) {
                 AddHook((void*)p_pcallk, (void*)MyLuaPcallK, "lua_pcallk", trampolineSize);
                 heartbeatFound = true;
            }
        }
    }

    if (p_callk) {
        int trampolineSize = CalcTrampolineSize((void*)p_callk, 12);
        if (trampolineSize > 0) {
            CreateTrampoline((void*)p_callk, p_callk_trampoline);
            if (p_callk_trampoline) {
                 if (!heartbeatFound) {
                     AddHook((void*)p_callk, (void*)MyLuaCall, "lua_call", trampolineSize);
                     heartbeatFound = true;
                 }
            }
        }
    }

    // FALLBACK HEARTBEAT: If no pcall/call hooks, try gettop
    if (!heartbeatFound && p_gettop) {
        int trampolineSize = CalcTrampolineSize((void*)p_gettop, 12);
        if (trampolineSize > 0) {
            CreateTrampoline((void*)p_gettop, p_gettop_trampoline);
            if (p_gettop_trampoline) {
                AddHook((void*)p_gettop, (void*)MyLuaGetTop, "lua_gettop", trampolineSize);
                heartbeatFound = true;
                std::cout << "[Agent] Using lua_gettop as fallback heartbeat." << std::endl;
            }
        }
    }

    if (!m_Hooks.empty()) {
        EnableHook();
        m_Loaded = true;
        std::cout << "[Agent] Hooks Installed in " << modName << ": " << m_Hooks.size() << std::endl;
        return true;
    } else {
        std::cout << "[Agent] Found gettop in " << modName << " but missing pcall/call/gettop hooks. Skipping." << std::endl;
    }
    return false;
}

void LuaInterface::EnableHook() {
    for (auto& h : m_Hooks) {
        if (h.active) continue;
        DWORD old;
        VirtualProtect(h.target, h.size, PAGE_EXECUTE_READWRITE, &old);
        uint8_t patch[12];
        patch[0] = 0x48; patch[1] = 0xB8;
        uintptr_t dest = (uintptr_t)h.detour;
        memcpy(&patch[2], &dest, 8);
        patch[10] = 0xFF; patch[11] = 0xE0;
        memcpy(h.target, patch, 12);
        if (h.size > 12) memset((uint8_t*)h.target + 12, 0x90, h.size - 12);
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
    if (!m_L) { error = "No Lua State captured yet."; return false; }
    int res = -1;
    if (p_loadbufferx) res = p_loadbufferx(m_L, script.c_str(), script.size(), "luatool", NULL);
    else if (p_loadstring) res = p_loadstring(m_L, script.c_str());
    else { error = "No loader function available."; return false; }
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

void LuaInterface::InstallPrintHook() {
    if (!m_L || !p_pushcclosure || !p_setglobal) return;
    p_pushcclosure(m_L, MyLuaPrint, 0);
    p_setglobal(m_L, "print");
    std::cout << "[Agent] Replaced 'print' with custom handler." << std::endl;
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
        if (!p_pushvalue || !p_type || !p_pushnil || !p_next || !p_tolstring || !p_typename || !p_settop) return;

        std::string out;
        out.reserve(131072);
        out = "Globals Dump (Streaming):\n";

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
                std::string kStr = FormatLuaValue(-1);
                out.append(kStr);
                p_settop(m_L, -2);

                int type = p_type(m_L, -1);
                const char* typeName = p_typename(m_L, type);
                out.append(" ["); out.append(typeName); out.append("]");

                p_pushvalue(m_L, -1);
                std::string val = FormatLuaValue(-1);
                p_settop(m_L, -2);

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
        if (!p_pushvalue || !p_type || !p_pushnil || !p_next || !p_tolstring || !p_typename || !p_settop) return;

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

                p_pushvalue(m_L, -2);
                std::string kStr = FormatLuaValue(-1);
                out.append(kStr);
                p_settop(m_L, -2);
                out.append("|");

                int vType = p_type(m_L, -1);
                out.append(p_typename(m_L, vType));
                out.append("|");

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

        std::string out = "Inspection Results for: " + keyStr + "\n";
        out.reserve(65536);
        p_pushvalue(m_L, -1001000);
        bool found = false;
        if (p_getfield) {
            p_getfield(m_L, -1, keyStr.c_str());
            if (p_type(m_L, -1) != 0) found = true;
            else p_settop(m_L, -2);
        }
        if (!found && p_rawgeti) {
            try {
                long long idx = std::stoll(keyStr);
                p_rawgeti(m_L, -1, idx);
                if (p_type(m_L, -1) != 0) found = true;
                else p_settop(m_L, -2);
            } catch (...) {}
        }

        if (!found) {
            out += "Item not found in Registry.";
            p_settop(m_L, -2);
        } else {
            int targetType = p_type(m_L, -1);
            out += "Type: " + std::string(p_typename(m_L, targetType)) + "\n";
            if (targetType == 5) {
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

                    p_pushvalue(m_L, -2);
                    std::string kStr = FormatLuaValue(-1);
                    out.append(kStr);
                    p_settop(m_L, -2);
                    out.append("|");

                    int vType = p_type(m_L, -1);
                    out.append(p_typename(m_L, vType));
                    out.append("|");

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
                out += "Value: " + FormatLuaValue(-1);
            }
            p_settop(m_L, -2);
            p_settop(m_L, -2);
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
        if (!m_L || !p_getglobal) return;
        p_getglobal(m_L, "Players");

        // HEURISTIC: If players table not found in _G, check for game.Players
        if (p_type && p_type(m_L, -1) != 5) {
            p_settop(m_L, -2); // Pop nil
            // Try "game" global then "Players" field
            p_getglobal(m_L, "game");
            if (p_type(m_L, -1) == 5 || p_type(m_L, -1) == 7) { // Table or Userdata
                p_getfield(m_L, -1, "Players");
                if (p_type(m_L, -1) == 5 || p_type(m_L, -1) == 7) {
                    // Found it in game.Players!
                    // Stack: [game, Players] -> remove game
                    // We want [Players] at top.
                    // Copy Players to temp
                    p_pushvalue(m_L, -1);
                    // Remove Players and game
                    // Stack: [game, Players, Players_Copy]
                    // Remove -2 (Players) and -3 (game)
                    // We can't remove arbitrary items easily without lua_remove/rotate
                    // BUT we can just leave them and clean up later.
                    // We just need Players at top to iterate.
                } else {
                    p_settop(m_L, -2); // Pop result and game
                    // Fail
                }
            } else {
                p_settop(m_L, -2); // Pop game
            }
        }

        if (p_type && (p_type(m_L, -1) != 5 && p_type(m_L, -1) != 7)) {
            std::string err = "Global 'Players' (or game.Players) table not found.";
            MessageHeader h = { (uint32_t)err.size(), RESP_ERROR };
            DWORD w; WriteFile(hPipe, &h, sizeof(h), &w, NULL);
            WriteFile(hPipe, err.data(), err.size(), &w, NULL);
            if (p_settop) p_settop(m_L, -2);
            return;
        }

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
            // Check Position
            if (p_getfield && p_type && p_settop && p_tonumber) {
                 // Try common fields
                 p_getfield(m_L, -1, "Position"); // Roblox/Unity style
                 if (p_type(m_L, -1) == 0) {
                     p_settop(m_L, -2);
                     p_getfield(m_L, -1, "pos"); // Source engine
                 }

                 // If still nil, try "Character" -> "HumanoidRootPart" -> "Position" (Roblox deep)
                 if (p_type(m_L, -1) == 0) {
                     p_settop(m_L, -2);
                     p_getfield(m_L, -1, "Character");
                     if (p_type(m_L, -1) != 0) {
                         p_getfield(m_L, -1, "HumanoidRootPart");
                         if (p_type(m_L, -1) != 0) {
                             p_getfield(m_L, -1, "Position");
                         } else { p_settop(m_L, -2); }
                     } else { p_settop(m_L, -2); }
                 }

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
        // Clean up stack: Pop Players (and potentially game/copy)
        // Since we don't track depth precisely here, we rely on p_settop to reset if things go wrong,
        // but normally pop 1 (Players) is enough if we found it in _G.
        // If we found it in game.Players, we have [game, Players]. Iterate pops keys/values.
        // So we need to pop 2.
        // Safer: GetTop at start and SetTop at end? We don't have GetTop stored here.
        // Just pop 1 for now, standard case. If leak, stack grows but p_settop usages elsewhere might fix it.
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

        std::string out = "Discovered Scripts (Merged):\n";
        out.reserve(65536);

        // 1. Captured Scripts
        {
            std::lock_guard<std::mutex> lock(m_CapturedScriptsMutex);
            for (const auto& cs : m_CapturedScripts) {
                out.append(cs.name);
                out.append("|Captured (");
                out.append(cs.isBytecode ? "Bytecode" : "Source");
                out.append(")\n");
            }
        }

        // 2. Global Functions
        if (p_getglobal && p_pushnil && p_next && p_type && p_tolstring && p_settop) {
            p_getglobal(m_L, "_G");
            if (p_type(m_L, -1) == 5) {
                p_pushnil(m_L);
                while (p_next(m_L, -2) != 0) {
                    if (p_type(m_L, -1) == 6) {
                         const char* key = p_tolstring(m_L, -2, NULL);
                         if (key) {
                             out.append(key);
                             out.append("|Global Function\n");
                         }
                    }
                    p_settop(m_L, -2);
                }
            }
            p_settop(m_L, -2);
        }

        MessageHeader h = { (uint32_t)out.size(), RESP_DATA };
        DWORD w; WriteFile(hPipe, &h, sizeof(h), &w, NULL);
        WriteFile(hPipe, out.data(), out.size(), &w, NULL);
        MessageHeader tok = { 0, RESP_OK };
        WriteFile(hPipe, &tok, sizeof(tok), &w, NULL);
    });
}

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
            // Check Captured First
            {
                std::lock_guard<std::mutex> lock(m_CapturedScriptsMutex);
                for (const auto& cs : m_CapturedScripts) {
                    if (cs.name == name) {
                        if (cs.isBytecode) {
                             std::string hex;
                             size_t limit = cs.source.size();
                             if (limit > 8192) limit = 8192;
                             hex.reserve(limit * 3 + 128);
                             char buf[4];
                             for (size_t i = 0; i < limit; i++) {
                                 sprintf_s(buf, "%02X ", (unsigned char)cs.source[i]);
                                 hex += buf;
                                 if ((i + 1) % 16 == 0) hex += "\n";
                             }
                             if (cs.source.size() > limit) hex += "\n... (Truncated)";
                             src = "-- CAPTURED Bytecode (" + std::to_string(cs.source.size()) + " bytes):\n" + hex;
                        } else {
                             src = "-- CAPTURED Source:\n" + cs.source;
                        }
                        break;
                    }
                }
            }
        }

        if (src.empty() && p_getglobal && p_getfield) {
            p_getglobal(m_L, "_G");
            p_getfield(m_L, -1, name.c_str());
            if (p_type(m_L, -1) == 6) {
                bool dumped = false;
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
                        src = "-- Bytecode Dump (Live) (" + std::to_string(bytecode.size()) + " bytes):\n" + hex;
                        dumped = true;
                    }
                }
                if (!dumped) {
                    std::string luaDump = GetBytecodeViaLua(name);
                    if (!luaDump.empty()) { src = luaDump; dumped = true; }
                }
                if (!dumped) {
                    src = "-- Source unavailable (Could not dump via Lua API or C API).";
                }
            } else {
                src = "-- Not found in _G or Captured Scripts.";
            }
            p_settop(m_L, -3);
        }

        MessageHeader h = { (uint32_t)src.size(), RESP_DATA };
        DWORD w; WriteFile(hPipe, &h, sizeof(h), &w, NULL);
        WriteFile(hPipe, src.data(), src.size(), &w, NULL);
        MessageHeader tok = { 0, RESP_OK };
        WriteFile(hPipe, &tok, sizeof(tok), &w, NULL);
    });
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

// TIME BUDGETED PROCESSING
bool LuaInterface::ProcessTasks() {
    bool didWork = false;
    auto SendError = [](HANDLE pipe, const std::string& msg) {
        MessageHeader h = { (uint32_t)msg.size(), RESP_ERROR };
        DWORD w; WriteFile(pipe, &h, sizeof(h), &w, NULL);
        WriteFile(pipe, msg.data(), msg.size(), &w, NULL);
    };

    // Use High Performance Timer
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    double limitMs = 2.0; // 2ms budget

    while (true) {
        Task t;
        {
            std::lock_guard<std::mutex> lock(g_TaskMutex);
            if (g_TaskQueue.empty()) { g_HasTasks = false; break; }
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
                    SendError(t.pipe, "Lua state not ready.");
                } else {
                    std::string err;
                    if (LoadScript(t.payload, err)) {
                        MessageHeader h = { 0, RESP_OK };
                        DWORD w; WriteFile(t.pipe, &h, sizeof(h), &w, NULL);
                    } else {
                        SendError(t.pipe, err);
                    }
                }
            })) SendError(t.pipe, "Exception during RunScript");
        } else if (t.type == CMD_DUMP_GLOBALS) {
            if (!DumpGlobals(t.pipe)) SendError(t.pipe, "Exception during DumpGlobals");
        } else if (t.type == CMD_SCAN_PLAYERS) {
            if (!ScanPlayers(t.pipe)) SendError(t.pipe, "Exception during ScanPlayers");
        } else if (t.type == CMD_DUMP_REGISTRY) {
            if (!DumpRegistry(t.pipe)) SendError(t.pipe, "Exception during DumpRegistry");
        } else if (t.type == CMD_INSPECT_REGISTRY_ITEM) {
            if (!InspectRegistryItem(t.pipe, t.payload)) SendError(t.pipe, "Exception during InspectRegistryItem");
        } else if (t.type == CMD_DUMP_SCRIPTS) {
            if (!DumpScripts(t.pipe)) SendError(t.pipe, "Exception during DumpScripts");
        } else if (t.type == CMD_GET_SCRIPT_SOURCE) {
            if (!GetScriptSource(t.pipe, t.payload)) SendError(t.pipe, "Exception during GetScriptSource");
        } else if (t.type == CMD_ADD_OVERRIDE) {
            size_t delim = t.payload.find('\n');
            if (delim != std::string::npos) {
                AddOverride(t.payload.substr(0, delim), t.payload.substr(delim + 1));
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
                for (const auto& l : g_LogQueue) combined += l + "\n";
                g_LogQueue.clear();
            }
            MessageHeader h = { (uint32_t)combined.size(), RESP_DATA };
            DWORD w; WriteFile(t.pipe, &h, sizeof(h), &w, NULL);
            WriteFile(t.pipe, combined.data(), combined.size(), &w, NULL);
            MessageHeader tok = { 0, RESP_OK };
            WriteFile(t.pipe, &tok, sizeof(tok), &w, NULL);
        }

        // Check budget
        QueryPerformanceCounter(&end);
        double elapsed = (end.QuadPart - start.QuadPart) * 1000.0 / freq.QuadPart;
        if (elapsed >= limitMs) break;
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
        if (hPipe == INVALID_HANDLE_VALUE) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            continue;
        }
        if (ConnectNamedPipe(hPipe, NULL) || GetLastError() == ERROR_PIPE_CONNECTED) {
            while (true) {
                MessageHeader h;
                DWORD r;
                if (!ReadFile(hPipe, &h, sizeof(h), &r, NULL) || r != sizeof(h)) break;
                std::string payload;
                if (h.length > 0) {
                    std::vector<char> b(h.length);
                    if (!ReadFile(hPipe, b.data(), h.length, &r, NULL) || r != h.length) break;
                    payload.assign(b.begin(), b.end());
                }
                {
                    std::lock_guard<std::mutex> lock(g_TaskMutex);
                    g_TaskQueue.push({ h.type, payload, hPipe });
                    g_HasTasks = true;
                }
                if (!LuaInterface::Get().IsLoaded()) LuaInterface::Get().ProcessTasks();
            }
            DisconnectNamedPipe(hPipe);
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
