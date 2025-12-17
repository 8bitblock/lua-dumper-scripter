#include <imgui.h>
#include <imgui_impl_sdl2.h>
#include <imgui_impl_opengl3.h>
#include <SDL.h>
#include <GL/gl.h>
#include <iostream>
#include <vector>
#include <string>
#include <dirent.h>
#include <fstream>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include "ipc.h"

// Forward declare Injector
bool InjectLibrary(pid_t pid, const std::string& library_path);

struct ProcessInfo {
    int pid;
    std::string name;
};

std::vector<ProcessInfo> GetProcesses() {
    std::vector<ProcessInfo> list;
    DIR* dir = opendir("/proc");
    if (!dir) return list;

    struct dirent* ent;
    while ((ent = readdir(dir)) != NULL) {
        if (isdigit(ent->d_name[0])) {
            int pid = atoi(ent->d_name);
            std::string cmdpath = std::string("/proc/") + ent->d_name + "/comm";
            std::ifstream cmdfile(cmdpath);
            std::string name;
            if (std::getline(cmdfile, name)) {
                list.push_back({pid, name});
            }
        }
    }
    closedir(dir);
    return list;
}

int client_sock = -1;

bool ConnectToAgent(int pid) {
    if (client_sock != -1) close(client_sock);

    std::string sock_path = "/tmp/luatool_" + std::to_string(pid) + ".sock";

    // Retry a few times as the agent initializes
    for (int i = 0; i < 10; i++) {
        client_sock = socket(AF_UNIX, SOCK_STREAM, 0);
        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, sock_path.c_str(), sizeof(addr.sun_path) - 1);

        if (connect(client_sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            return true;
        }
        close(client_sock);
        client_sock = -1;
        usleep(500000); // 0.5s
    }
    return false;
}

void SendScript(const std::string& script) {
    if (client_sock == -1) return;

    MessageHeader header;
    header.type = CMD_RUN_SCRIPT;
    header.length = script.size();

    send(client_sock, &header, sizeof(header), 0);
    send(client_sock, script.data(), script.size(), 0);
}

void RequestDump() {
    if (client_sock == -1) return;

    MessageHeader header;
    header.type = CMD_DUMP_GLOBALS;
    header.length = 0;
    send(client_sock, &header, sizeof(header), 0);
}

// Global UI state
int selected_pid = -1;
std::string status_msg = "Idle";
std::string output_log = "";
char script_buffer[1024 * 16] = "print('Hello from LuaTool!')\nprint('Answer is ' .. (Answer or 'nil'))";

void ProcessIPC() {
    if (client_sock == -1) return;

    // Check for data without blocking
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(client_sock, &readfds);
    struct timeval tv = {0, 0};

    if (select(client_sock + 1, &readfds, NULL, NULL, &tv) > 0) {
        MessageHeader header;
        ssize_t n = recv(client_sock, &header, sizeof(header), MSG_PEEK); // peek header
        if (n == 0) {
             // Closed
             close(client_sock);
             client_sock = -1;
             status_msg = "Disconnected";
             return;
        }

        if (n >= sizeof(header)) {
             recv(client_sock, &header, sizeof(header), 0); // consume header

             std::vector<char> buffer(header.length);
             if (header.length > 0) {
                 // Loop to ensure full read
                 size_t total = 0;
                 while(total < header.length) {
                     ssize_t r = recv(client_sock, buffer.data() + total, header.length - total, 0);
                     if(r <= 0) break;
                     total += r;
                 }
             }

             std::string payload(buffer.begin(), buffer.end());

             if (header.type == RESP_OK) {
                 output_log += "[OK] Script executed successfully.\n";
             } else if (header.type == RESP_ERROR) {
                 output_log += "[ERROR] " + payload + "\n";
             } else if (header.type == RESP_DATA) {
                 output_log += "[DATA] " + payload + "\n";
             }
        }
    }
}

int main(int, char**) {
    if (SDL_Init(SDL_INIT_VIDEO | SDL_INIT_TIMER | SDL_INIT_GAMECONTROLLER) != 0) {
        printf("Error: %s\n", SDL_GetError());
        return -1;
    }

    const char* glsl_version = "#version 130";
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_FLAGS, 0);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_PROFILE_MASK, SDL_GL_CONTEXT_PROFILE_CORE);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MAJOR_VERSION, 3);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MINOR_VERSION, 0);

    SDL_WindowFlags window_flags = (SDL_WindowFlags)(SDL_WINDOW_OPENGL | SDL_WINDOW_RESIZABLE | SDL_WINDOW_ALLOW_HIGHDPI);
    SDL_Window* window = SDL_CreateWindow("LuaTool", SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED, 1280, 720, window_flags);

    SDL_GLContext gl_context = SDL_GL_CreateContext(window);
    SDL_GL_MakeCurrent(window, gl_context);
    SDL_GL_SetSwapInterval(1); // Enable vsync

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO(); (void)io;

    ImGui::StyleColorsDark();

    ImGui_ImplSDL2_InitForOpenGL(window, gl_context);
    ImGui_ImplOpenGL3_Init(glsl_version);

    bool done = false;
    std::vector<ProcessInfo> processes;

    // Build path to agent library
    char path_buf[1024];
    readlink("/proc/self/exe", path_buf, sizeof(path_buf));
    std::string exe_path(path_buf);
    std::string bin_dir = exe_path.substr(0, exe_path.find_last_of('/'));
    // Usually we are in build/src/gui/luatool. Agent is in build/src/agent/libagent.so
    // Let's assume standard cmake build layout relative to executable.
    std::string agent_path = bin_dir + "/../agent/libagent.so";

    // Verify agent path
    if (access(agent_path.c_str(), F_OK) == -1) {
        // Try fallback
        agent_path = bin_dir + "/libagent.so";
    }

    while (!done) {
        SDL_Event event;
        while (SDL_PollEvent(&event)) {
            ImGui_ImplSDL2_ProcessEvent(&event);
            if (event.type == SDL_QUIT)
                done = true;
            if (event.type == SDL_WINDOWEVENT && event.window.event == SDL_WINDOWEVENT_CLOSE && event.window.windowID == SDL_GetWindowID(window))
                done = true;
        }

        ProcessIPC();

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplSDL2_NewFrame();
        ImGui::NewFrame();

        {
            ImGui::Begin("Lua Process Injector");

            if (ImGui::Button("Refresh Processes")) {
                processes = GetProcesses();
            }

            ImGui::SameLine();
            ImGui::Text("Status: %s", status_msg.c_str());

            ImGui::BeginChild("ProcessList", ImVec2(0, 200), true);
            for (const auto& p : processes) {
                std::string label = std::to_string(p.pid) + " - " + p.name;
                if (ImGui::Selectable(label.c_str(), selected_pid == p.pid)) {
                    selected_pid = p.pid;
                }
            }
            ImGui::EndChild();

            if (ImGui::Button("Attach & Inject")) {
                if (selected_pid > 0) {
                    status_msg = "Injecting...";
                    if (InjectLibrary(selected_pid, agent_path)) {
                        status_msg = "Injected. Connecting...";
                        if (ConnectToAgent(selected_pid)) {
                            status_msg = "Connected!";
                        } else {
                            status_msg = "Injected, but connection failed.";
                        }
                    } else {
                        status_msg = "Injection Failed.";
                    }
                }
            }

            ImGui::Separator();

            if (client_sock != -1) {
                ImGui::Text("Scripting");
                ImGui::InputTextMultiline("##source", script_buffer, IM_ARRAYSIZE(script_buffer), ImVec2(-FLT_MIN, ImGui::GetTextLineHeight() * 10));

                if (ImGui::Button("Run Script")) {
                     SendScript(script_buffer);
                }
                ImGui::SameLine();
                if (ImGui::Button("Dump Globals")) {
                     RequestDump();
                }

                ImGui::Text("Output Log:");
                ImGui::BeginChild("Log", ImVec2(0, 0), true);
                ImGui::TextUnformatted(output_log.c_str());
                if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY())
                    ImGui::SetScrollHereY(1.0f);
                ImGui::EndChild();
            } else {
                ImGui::TextDisabled("Attach to a process to enable scripting.");
            }

            ImGui::End();
        }

        ImGui::Render();
        glViewport(0, 0, (int)io.DisplaySize.x, (int)io.DisplaySize.y);
        glClearColor(0.45f, 0.55f, 0.60f, 1.00f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        SDL_GL_SwapWindow(window);
    }

    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplSDL2_Shutdown();
    ImGui::DestroyContext();

    SDL_GL_DeleteContext(gl_context);
    SDL_DestroyWindow(window);
    SDL_Quit();

    return 0;
}
