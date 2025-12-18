#include <windows.h>
#include <iostream>
#include <thread>
#include <chrono>

// We don't link Lua here, we LoadLibrary it to simulate a game using lua54.dll
typedef struct lua_State lua_State;
typedef lua_State* (*luaL_newstate_t)();
typedef void (*luaL_openlibs_t)(lua_State*);
typedef int (*luaL_loadstring_t)(lua_State*, const char*);
typedef int (*lua_pcallk_t)(lua_State*, int, int, int, long, void*);
typedef void (*lua_close_t)(lua_State*);

int main() {
    HMODULE hLua = LoadLibraryA("lua54.dll");
    if (!hLua) {
        // Fallback name
        hLua = LoadLibraryA("lua5.4.dll");
    }

    if (!hLua) {
        std::cerr << "Could not load lua54.dll. Make sure it is in the same folder." << std::endl;
        return 1;
    }

    auto p_luaL_newstate = (luaL_newstate_t)GetProcAddress(hLua, "luaL_newstate");
    auto p_luaL_openlibs = (luaL_openlibs_t)GetProcAddress(hLua, "luaL_openlibs");
    auto p_luaL_loadstring = (luaL_loadstring_t)GetProcAddress(hLua, "luaL_loadstring");
    auto p_lua_pcallk = (lua_pcallk_t)GetProcAddress(hLua, "lua_pcallk");
    auto p_lua_close = (lua_close_t)GetProcAddress(hLua, "lua_close");

    if (!p_luaL_newstate) {
        std::cerr << "Missing symbols in lua dll." << std::endl;
        return 1;
    }

    lua_State* L = p_luaL_newstate();
    p_luaL_openlibs(L);

    // Setup Dummy Environment
    const char* init_script = R"(
        Players = {
            LocalPlayer = { Name = "PlayerOne", Addr = "0x123456" },
            OtherPlayer = { Name = "PlayerTwo", Addr = "0xABCDEF" }
        }
        _G.SecretFunction = function() print("I am hidden") end
    )";
    if (p_luaL_loadstring(L, init_script) == 0) p_lua_pcallk(L, 0, 0, 0, 0, NULL);

    std::cout << "Dummy Target (Windows) Running. PID: " << GetCurrentProcessId() << std::endl;

    while (true) {
        // Run a simple script every few seconds
        const char* script = "print('Target Tick: ' .. os.time())";
        if (p_luaL_loadstring(L, script) == 0) {
            p_lua_pcallk(L, 0, 0, 0, 0, NULL);
        }
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }

    p_lua_close(L);
    return 0;
}
