#include <iostream>
#include <thread>
#include <vector>
#include <string>
#include <cstring>
#include <dlfcn.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include "ipc.h"

// Lua Headers (we just need the declarations)
// We are NOT linking to liblua. We will find symbols at runtime.
typedef struct lua_State lua_State;

typedef int (*lua_gettop_t)(lua_State *L);
typedef void (*lua_pushvalue_t)(lua_State *L, int idx);
typedef int (*lua_pcallk_t)(lua_State *L, int nargs, int nresults, int errfunc, long ctx, void* k);
typedef void (*lua_settop_t)(lua_State *L, int idx);
typedef int (*luaL_loadstring_t)(lua_State *L, const char *s);
typedef int (*luaL_loadbufferx_t)(lua_State *L, const char *buff, size_t sz, const char *name, const char *mode);
typedef void (*lua_pushnil_t)(lua_State *L);
typedef int (*lua_next_t)(lua_State *L, int idx);
typedef const char* (*lua_tolstring_t)(lua_State *L, int idx, size_t *len);

// Globals
lua_State* G_L = nullptr;
lua_gettop_t p_lua_gettop = nullptr;
lua_pushvalue_t p_lua_pushvalue = nullptr;
lua_pcallk_t p_lua_pcallk = nullptr;
lua_settop_t p_lua_settop = nullptr;
luaL_loadstring_t p_luaL_loadstring = nullptr;
luaL_loadbufferx_t p_luaL_loadbufferx = nullptr;
lua_pushnil_t p_lua_pushnil = nullptr;
lua_next_t p_lua_next = nullptr;
lua_tolstring_t p_lua_tolstring = nullptr;

// Helper wrapper for pcall (lua 5.2+)
int p_lua_pcall(lua_State *L, int nargs, int nresults, int errfunc) {
    if (p_lua_pcallk) return p_lua_pcallk(L, nargs, nresults, errfunc, 0, nullptr);
    return -1;
}

// Queue for thread safety
#include <mutex>
#include <queue>
#include <functional>

struct Task {
    MessageType type;
    std::string payload;
    int client_sock;
};

std::mutex task_mutex;
std::queue<Task> task_queue;

// Called from Main Thread of Target (via hook)
void ProcessTasks() {
    if (!G_L) return;

    std::lock_guard<std::mutex> lock(task_mutex);
    while (!task_queue.empty()) {
        Task t = task_queue.front();
        task_queue.pop();

        if (t.type == CMD_RUN_SCRIPT) {
             if (p_luaL_loadstring && p_luaL_loadstring(G_L, t.payload.c_str()) == 0) {
                 if (p_lua_pcall(G_L, 0, 0, 0) != 0) {
                     const char* err = p_lua_tolstring(G_L, -1, NULL);
                     std::string err_msg = "Error: ";
                     err_msg += (err ? err : "Unknown");
                     p_lua_settop(G_L, -2); // Pop error

                     MessageHeader resp{ (uint32_t)err_msg.size(), RESP_ERROR };
                     send(t.client_sock, &resp, sizeof(resp), 0);
                     send(t.client_sock, err_msg.data(), resp.length, 0);
                 } else {
                     MessageHeader resp{ 0, RESP_OK };
                     send(t.client_sock, &resp, sizeof(resp), 0);
                 }
            } else if (p_luaL_loadbufferx && p_luaL_loadbufferx(G_L, t.payload.c_str(), t.payload.size(), "script", NULL) == 0) {
                 if (p_lua_pcall(G_L, 0, 0, 0) != 0) {
                     const char* err = p_lua_tolstring(G_L, -1, NULL);
                     std::string err_msg = "Error: ";
                     err_msg += (err ? err : "Unknown");
                     p_lua_settop(G_L, -1);

                     MessageHeader resp{ (uint32_t)err_msg.size(), RESP_ERROR };
                     send(t.client_sock, &resp, sizeof(resp), 0);
                     send(t.client_sock, err_msg.data(), resp.length, 0);
                 } else {
                     MessageHeader resp{ 0, RESP_OK };
                     send(t.client_sock, &resp, sizeof(resp), 0);
                 }
            } else {
                const char* err = p_lua_tolstring ? p_lua_tolstring(G_L, -1, NULL) : "load error";
                std::string err_msg = "Load Error: ";
                err_msg += (err ? err : "Unknown");
                if (p_lua_settop) p_lua_settop(G_L, -2); // Pop error

                MessageHeader resp{ (uint32_t)err_msg.size(), RESP_ERROR };
                send(t.client_sock, &resp, sizeof(resp), 0);
                send(t.client_sock, err_msg.data(), resp.length, 0);
            }
        } else if (t.type == CMD_DUMP_GLOBALS) {
            std::string result = "Globals:\n";
            // Check for _G
            // lua_getglobal(L, "_G") is what we want, but we need the symbol.
            // dlsym("lua_getglobal") might work.
            // Or use lua_pushglobaltable (5.2+)

            // We'll try dlsym-ing lua_getglobal
            void* handle = dlopen(NULL, RTLD_LAZY);
            typedef void (*lua_getglobal_t)(lua_State*, const char*);
            lua_getglobal_t p_lua_getglobal = (lua_getglobal_t)dlsym(handle, "lua_getglobal");

            if (p_lua_getglobal && p_lua_pushnil && p_lua_next && p_lua_tolstring && p_lua_pushvalue) {
                p_lua_getglobal(G_L, "_G");
                if (p_lua_gettop(G_L) > 0) { // Ensure table is there
                    p_lua_pushnil(G_L);  /* first key */
                    while (p_lua_next(G_L, -2) != 0) {
                        /* uses 'key' (at index -2) and 'value' (at index -1) */

                        // Copy key to string to avoid confusing lua_next if key is number
                        p_lua_pushvalue(G_L, -2);
                        const char* key = p_lua_tolstring(G_L, -1, NULL);

                        if (key) {
                            result += key;
                            result += "\n";
                        }

                        p_lua_settop(G_L, -2); // Pop key copy

                        /* removes 'value'; keeps 'key' for next iteration */
                        p_lua_settop(G_L, -2);
                    }
                    p_lua_settop(G_L, -2); // Pop _G
                }
            } else {
                result += "Missing Lua symbols for iteration (lua_getglobal or lua_next).";
            }

            MessageHeader resp{ (uint32_t)result.size(), RESP_DATA };
            send(t.client_sock, &resp, sizeof(resp), 0);
            send(t.client_sock, result.data(), resp.length, 0);
        }
    }
}

// IPC
int server_sock = -1;

void HandleClient(int client_sock) {
    while (true) {
        MessageHeader header;
        ssize_t n = recv(client_sock, &header, sizeof(header), 0);
        if (n <= 0) break;

        std::vector<char> buffer(header.length);
        if (header.length > 0) {
            size_t total = 0;
            while(total < header.length) {
                ssize_t r = recv(client_sock, buffer.data() + total, header.length - total, 0);
                if(r <= 0) break;
                total += r;
            }
        }

        std::string payload(buffer.begin(), buffer.end());

        // Push to queue
        std::lock_guard<std::mutex> lock(task_mutex);
        task_queue.push({ header.type, payload, client_sock });
    }
}

void ServerThread() {
    std::string sock_path = "/tmp/luatool_" + std::to_string(getpid()) + ".sock";
    unlink(sock_path.c_str());

    server_sock = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sock_path.c_str(), sizeof(addr.sun_path) - 1);

    bind(server_sock, (struct sockaddr*)&addr, sizeof(addr));
    listen(server_sock, 5);

    std::cout << "[Agent] Listening on " << sock_path << std::endl;

    while (true) {
        int client = accept(server_sock, NULL, NULL);
        if (client >= 0) {
            std::thread(HandleClient, client).detach();
        }
    }
}

// Find symbols and Lua State
void Setup() {
    // 1. Find Lua Symbols
    void* handle = dlopen(NULL, RTLD_LAZY); // Open main executable symbol table
    if (!handle) return;

    // Try finding symbols. Note: Names might vary by version (lua_pcall vs lua_pcallk)
    p_lua_gettop = (lua_gettop_t)dlsym(handle, "lua_gettop");
    p_luaL_loadstring = (luaL_loadstring_t)dlsym(handle, "luaL_loadstring");
    p_luaL_loadbufferx = (luaL_loadbufferx_t)dlsym(handle, "luaL_loadbufferx");
    p_lua_pcallk = (lua_pcallk_t)dlsym(handle, "lua_pcallk"); // 5.4 uses pcallk
    if (!p_lua_pcallk) p_lua_pcallk = (lua_pcallk_t)dlsym(handle, "lua_pcall"); // Fallback

    p_lua_settop = (lua_settop_t)dlsym(handle, "lua_settop");
    p_lua_tolstring = (lua_tolstring_t)dlsym(handle, "lua_tolstring");
    p_lua_pushnil = (lua_pushnil_t)dlsym(handle, "lua_pushnil");
    p_lua_next = (lua_next_t)dlsym(handle, "lua_next");

    if (p_luaL_loadstring || p_luaL_loadbufferx) {
        std::cout << "[Agent] Found Lua symbols!" << std::endl;
    } else {
        std::cerr << "[Agent] Failed to find Lua symbols." << std::endl;
    }
}

// We need to enable writing to code memory
#include <sys/mman.h>

// Helper to align to page
void* PageAlign(void* ptr) {
    return (void*)((uintptr_t)ptr & ~(sysconf(_SC_PAGESIZE) - 1));
}

uint8_t original_bytes[16];
void* target_func_addr = nullptr;

int MyLuaLoadString(lua_State* L, const char* s); // Forward
int MyLuaLoadBufferX(lua_State* L, const char *buff, size_t sz, const char *name, const char *mode); // Forward

void EnableHook() {
    if (!target_func_addr) return;
    uint8_t patch[12];
    patch[0] = 0x48; patch[1] = 0xB8;

    uintptr_t addr = 0;
    if (target_func_addr == (void*)p_luaL_loadbufferx) {
        addr = (uintptr_t)MyLuaLoadBufferX;
    } else {
        addr = (uintptr_t)MyLuaLoadString;
    }

    memcpy(&patch[2], &addr, 8);
    patch[10] = 0xFF; patch[11] = 0xE0;

    memcpy(target_func_addr, patch, 12);
}

void DisableHook() {
    if (!target_func_addr) return;
    memcpy(target_func_addr, original_bytes, 12);
}

int MyLuaLoadString(lua_State* L, const char* s) {
    if (!G_L) G_L = L;
    ProcessTasks();
    DisableHook();
    int ret = ((luaL_loadstring_t)target_func_addr)(L, s);
    EnableHook();
    return ret;
}

int MyLuaLoadBufferX(lua_State* L, const char *buff, size_t sz, const char *name, const char *mode) {
    if (!G_L) G_L = L;
    ProcessTasks();
    DisableHook();
    int ret = ((luaL_loadbufferx_t)target_func_addr)(L, buff, sz, name, mode);
    EnableHook();
    return ret;
}

__attribute__((constructor))
void AgentEntry() {
    std::cout << "[Agent] Injected!" << std::endl;

    // Setup in a thread
    std::thread([](){
        std::this_thread::sleep_for(std::chrono::seconds(1));

        void* handle = dlopen(NULL, RTLD_LAZY);
        // We look for a specific symbol I'll add to the dummy: "GetGlobalState"
        typedef lua_State* (*GetState_t)();
        GetState_t get_state = (GetState_t)dlsym(handle, "GetGlobalState");

        Setup(); // Find standard symbols

        if (get_state) {
            G_L = get_state();
            std::cout << "[Agent] Got Lua State from helper: " << G_L << std::endl;
        } else {
             lua_State** p_L = (lua_State**)dlsym(handle, "G_LuaState");
             if (p_L) {
                 G_L = *p_L;
                 std::cout << "[Agent] Got Lua State from global: " << G_L << std::endl;
             }
        }

        // Setup Hook
        if (p_luaL_loadbufferx) {
            target_func_addr = (void*)p_luaL_loadbufferx;
            mprotect(PageAlign(target_func_addr), sysconf(_SC_PAGESIZE) * 2, PROT_READ | PROT_WRITE | PROT_EXEC);
            memcpy(original_bytes, target_func_addr, 12);
            EnableHook();
            std::cout << "[Agent] Hooked luaL_loadbufferx at " << target_func_addr << std::endl;
        } else if (p_luaL_loadstring) {
            target_func_addr = (void*)p_luaL_loadstring;
            mprotect(PageAlign(target_func_addr), sysconf(_SC_PAGESIZE) * 2, PROT_READ | PROT_WRITE | PROT_EXEC);
            memcpy(original_bytes, target_func_addr, 12);
            EnableHook();
            std::cout << "[Agent] Hooked luaL_loadstring at " << target_func_addr << std::endl;
        } else {
            std::cerr << "[Agent] Could not find luaL_loadstring or luaL_loadbufferx to hook!" << std::endl;
        }

        ServerThread();
    }).detach();
}
