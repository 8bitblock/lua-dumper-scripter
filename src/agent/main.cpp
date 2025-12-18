#include <windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <mutex>
#include <queue>
#include <atomic>
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
typedef int         (*luaL_loadbufferx_t)(lua_State *L, const char *buff, size_t sz, const char *name, const char *mode);
typedef int         (*luaL_loadstring_t)(lua_State *L, const char *s);
typedef int         (*lua_pcallk_t)(lua_State *L, int nargs, int nresults, int errfunc, long ctx, void* k);

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

    // Hooking
    void EnableHook();
    void DisableHook();
    bool ProcessTasks(); // Returns true if tasks were processed

    // Accessors
    void SetState(lua_State* L) { m_L = L; }
    lua_State* GetState() const { return m_L; }

private:
    LuaInterface() = default;
    void ResolveSymbols(HMODULE hMod);

    // State
    lua_State* m_L = nullptr;
    bool m_Loaded = false;
    HMODULE m_hLua = NULL;

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
    lua_pcallk_t    p_pcallk = nullptr;

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

    uint32_t now = GetTickCount();
    if (now - lua.m_LastTick > 100) {
        lua.DisableHook(); // Disable ALL hooks
        lua.ProcessTasks();
        lua.EnableHook();  // Re-enable ALL hooks
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
    int ret = lua.p_loadbufferx(L, buff, sz, name, mode);
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

// ----------------------------------------------------------------------------
// LuaInterface Implementation
// ----------------------------------------------------------------------------
void LuaInterface::Initialize() {
    std::cout << "[Agent] Scanning for Lua..." << std::endl;

    // 1. Try Common Names
    const char* names[] = { "lua54.dll", "lua5.4.dll", "lua53.dll", "lua.dll", "xlua.dll" };
    for (const char* name : names) {
        m_hLua = GetModuleHandleA(name);
        if (m_hLua) {
            std::cout << "[Agent] Found Lua: " << name << std::endl;
            break;
        }
    }

    // 2. Try Scanning All Modules
    if (!m_hLua) {
        std::cout << "[Agent] Scanning all modules..." << std::endl;
        HMODULE hMods[1024];
        DWORD cbNeeded;
        HANDLE hProcess = GetCurrentProcess();
        if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
            unsigned int numMods = cbNeeded / sizeof(HMODULE);
            if (numMods > 1024) numMods = 1024;
            for (unsigned int i = 0; i < numMods; i++) {
                if (GetProcAddress(hMods[i], "lua_gettop")) {
                     char modName[MAX_PATH];
                     if (GetModuleBaseNameA(hProcess, hMods[i], modName, sizeof(modName))) {
                         std::cout << "[Agent] Found Lua symbols in: " << modName << std::endl;
                         m_hLua = hMods[i];
                         break;
                     }
                }
            }
        }
    }

    // 3. Try Main Executable (Fallback)
    if (!m_hLua) {
        m_hLua = GetModuleHandle(NULL);
        if (GetProcAddress(m_hLua, "lua_gettop")) {
            std::cout << "[Agent] Found Lua symbols in Main Executable." << std::endl;
        } else {
            m_hLua = NULL;
        }
    }

    if (!m_hLua) {
        std::cout << "[Agent] Failed to find Lua symbols." << std::endl;
        return;
    }

    ResolveSymbols(m_hLua);
}

void LuaInterface::ResolveSymbols(HMODULE hMod) {
    p_gettop = (lua_gettop_t)GetProcAddress(hMod, "lua_gettop");
    p_settop = (lua_settop_t)GetProcAddress(hMod, "lua_settop");
    p_pushvalue = (lua_pushvalue_t)GetProcAddress(hMod, "lua_pushvalue");
    p_next = (lua_next_t)GetProcAddress(hMod, "lua_next");
    p_pushnil = (lua_pushnil_t)GetProcAddress(hMod, "lua_pushnil");
    p_tolstring = (lua_tolstring_t)GetProcAddress(hMod, "lua_tolstring");
    p_type = (lua_type_t)GetProcAddress(hMod, "lua_type");
    p_typename = (lua_typename_t)GetProcAddress(hMod, "lua_typename");
    p_tonumber = (lua_tonumber_t)GetProcAddress(hMod, "lua_tonumber");
    p_toboolean = (lua_toboolean_t)GetProcAddress(hMod, "lua_toboolean");
    p_topointer = (lua_topointer_t)GetProcAddress(hMod, "lua_topointer");

    // Pcall variants
    p_pcallk = (lua_pcallk_t)GetProcAddress(hMod, "lua_pcallk");
    if (!p_pcallk) p_pcallk = (lua_pcallk_t)GetProcAddress(hMod, "lua_pcall");

    // Loaders
    p_loadbufferx = (luaL_loadbufferx_t)GetProcAddress(hMod, "luaL_loadbufferx");
    p_loadstring = (luaL_loadstring_t)GetProcAddress(hMod, "luaL_loadstring");

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

    if (p_pcallk) AddHook((void*)p_pcallk, (void*)MyLuaPcallK, "lua_pcallk");
    else if (GetProcAddress(hMod, "lua_pcall")) AddHook((void*)GetProcAddress(hMod, "lua_pcall"), (void*)MyLuaPcall, "lua_pcall");

    if (p_settop) AddHook((void*)p_settop, (void*)MyLuaSetTop, "lua_settop");

    if (p_loadbufferx) AddHook((void*)p_loadbufferx, (void*)MyLuaLoadBufferX, "luaL_loadbufferx");
    if (p_loadstring) AddHook((void*)p_loadstring, (void*)MyLuaLoadString, "luaL_loadstring");

    if (!m_Hooks.empty()) {
        EnableHook();
        m_Loaded = true;
        std::cout << "[Agent] Hooks Installed: " << m_Hooks.size() << std::endl;
    } else {
        std::cout << "[Agent] Failed to find ANY function to hook." << std::endl;
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

    // Find _G
    typedef void (*lua_getglobal_t)(lua_State*, const char*);
    lua_getglobal_t p_getglobal = (lua_getglobal_t)GetProcAddress(m_hLua, "lua_getglobal");

    if (!p_getglobal) {
        std::string msg = "lua_getglobal not found.";
        MessageHeader h = { (uint32_t)msg.size(), RESP_ERROR };
        DWORD w; WriteFile(hPipe, &h, sizeof(h), &w, NULL);
        WriteFile(hPipe, msg.data(), msg.size(), &w, NULL);
        return;
    }

    std::string out;
    out.reserve(4096);

    // Initial Header
    out = "Globals Dump (Streaming):\n";

    p_getglobal(m_L, "_G");
    if (p_gettop(m_L) > 0) {
        p_pushnil(m_L);
        int count = 0;
        // Iterate _G
        while (p_next(m_L, -2) != 0) {
            // Check Progress
            count++;
            if (count % 50 == 0) {
                // Send Chunk if valid
                if (!out.empty()) {
                    MessageHeader h = { (uint32_t)out.size(), RESP_DATA };
                    DWORD w; WriteFile(hPipe, &h, sizeof(h), &w, NULL);
                    WriteFile(hPipe, out.data(), out.size(), &w, NULL);
                    out.clear();
                }

                // Send Progress
                std::string prog = "Dumped " + std::to_string(count) + " items...";
                MessageHeader h = { (uint32_t)prog.size(), RESP_PROGRESS };
                DWORD w; WriteFile(hPipe, &h, sizeof(h), &w, NULL);
                WriteFile(hPipe, prog.data(), prog.size(), &w, NULL);
            }

            if (count > 5000) { // Limit items
                out.append("... [Output Truncated > 5000] ...\n");
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
        out.append(" | Addr: ");

        // Get Pointer
        const void* ptr = p_topointer ? p_topointer(m_L, -1) : nullptr;
        char addrBuf[32];
        sprintf_s(addrBuf, "%p", ptr);
        out.append(addrBuf);
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

    p_pushvalue(m_L, registry_index); // Push Registry
    if (p_type(m_L, -1) != 5) {
        out = "Failed to push Registry (Invalid Index?).";
    } else {
        p_pushnil(m_L);
        int count = 0;
        while (p_next(m_L, -2) != 0) {
            if (count++ > 1000) {
                out.append("... Truncated ...\n");
                p_settop(m_L, -3);
                break;
            }
            // Key
            int kType = p_type(m_L, -2);
            if (kType == 3) out.append(std::to_string((int)p_tonumber(m_L, -2)));
            else if (kType == 4) out.append(p_tolstring(m_L, -2, NULL));
            else out.append(p_typename(m_L, kType));

            out.append(" = ");

            // Value
            int vType = p_type(m_L, -1);
            out.append(p_typename(m_L, vType));
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

    typedef void (*lua_getglobal_t)(lua_State*, const char*);
    lua_getglobal_t p_getglobal = (lua_getglobal_t)GetProcAddress(m_hLua, "lua_getglobal");

    typedef int (*lua_getinfo_t)(lua_State*, const char*, void*); // lua_Debug* is void* here
    lua_getinfo_t p_getinfo = (lua_getinfo_t)GetProcAddress(m_hLua, "lua_getinfo");

    if (!p_getglobal || !p_getinfo) return;

    std::string out = "Discovered Scripts (Functions in _G):\n";

    p_getglobal(m_L, "_G");
    p_pushnil(m_L);
    while (p_next(m_L, -2) != 0) {
        if (p_type(m_L, -1) == 6) { // LUA_TFUNCTION
             const char* key = p_tolstring(m_L, -2, NULL);
             out.append("Function: ");
             out.append(key ? key : "?");

             // Get Info
             // struct lua_Debug is large, let's allocate enough buffer
             char debugBuf[256];
             // We need to be careful with struct layout.
             // Safer to not use getinfo if we don't have the struct definition.
             // But we can try to push it on stack and check?
             // Actually, `lua_getinfo` writes to a struct. Without correct struct layout matching the DLL version, this will CRASH.
             // We cannot safely use lua_getinfo without the header definition matching the DLL.
             // SKIPPING DETAILED INFO for safety.

             out.append(" [Lua Function]\n");
        }
        p_settop(m_L, -2);
    }
    p_settop(m_L, -2);

    MessageHeader h = { (uint32_t)out.size(), RESP_DATA };
    DWORD w; WriteFile(hPipe, &h, sizeof(h), &w, NULL);
    WriteFile(hPipe, out.data(), out.size(), &w, NULL);
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
