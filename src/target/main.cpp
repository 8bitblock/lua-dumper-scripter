#include <lua.hpp>
#include <iostream>
#include <thread>
#include <chrono>
#include <unistd.h>

lua_State* G_LuaState = nullptr;

extern "C" {
    // Export this symbol for the agent to find
    lua_State* GetGlobalState() {
        return G_LuaState;
    }
}

int main() {
    lua_State* L = luaL_newstate();
    G_LuaState = L; // Set global

    luaL_openlibs(L);

    // Define some dummy globals
    lua_pushinteger(L, 42);
    lua_setglobal(L, "Answer");

    lua_pushstring(L, "LuaTool Dummy");
    lua_setglobal(L, "AppName");

    // Define a function
    luaL_dostring(L, "function MyFunc(a, b) return a + b end");

    std::cout << "Dummy Target Running. PID: " << getpid() << std::endl;

    while (true) {
        luaL_dostring(L, "print('Tick: ' .. os.time())");
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }

    lua_close(L);
    return 0;
}
