#include <imgui.h>
#include <imgui_impl_sdl2.h>
#include <imgui_impl_opengl3.h>
#include <SDL.h>
#include <SDL_opengl.h>
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <vector>
#include <string>
#include <queue>
#include <mutex>
#include <atomic>
#include <thread>
#include <fstream>
#include <algorithm>
#include <cctype>
#include "ipc.h"

// Forward declare Injector
bool InjectLibrary(DWORD pid, const std::string& library_path);

struct ProcessInfo {
    DWORD pid;
    std::string name;
};

std::vector<ProcessInfo> GetProcesses() {
    std::vector<ProcessInfo> list;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return list;

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hSnap, &pe32)) {
        do {
            #ifdef UNICODE
            char name[MAX_PATH];
            size_t c;
            wcstombs_s(&c, name, MAX_PATH, pe32.szExeFile, MAX_PATH);
            list.push_back({ pe32.th32ProcessID, std::string(name) });
            #else
            list.push_back({ pe32.th32ProcessID, std::string(pe32.szExeFile) });
            #endif
        } while (Process32Next(hSnap, &pe32));
    }
    CloseHandle(hSnap);
    return list;
}

// ----------------------------------------------------------------------------
// Remote Agent Class (IPC Wrapper)
// ----------------------------------------------------------------------------
class RemoteAgent {
public:
    struct Command {
        DWORD pid;
        MessageType type;
        std::string payload;
    };

    static RemoteAgent& Get() {
        static RemoteAgent instance;
        return instance;
    }

    void Start() {
        if (m_Running) return;
        m_Running = true;
        m_Worker = std::thread(&RemoteAgent::WorkerLoop, this);
        m_Worker.detach();
    }

    void Send(DWORD pid, MessageType type, const std::string& payload) {
        std::lock_guard<std::mutex> lock(m_QueueMutex);
        m_Queue.push({ pid, type, payload });
    }

    std::vector<std::string> ConsumeLogs() {
        std::vector<std::string> logs;
        {
            std::lock_guard<std::mutex> lock(m_LogMutex);
            logs.swap(m_PendingLogs);
        }
        return logs;
    }

private:
    RemoteAgent() = default;

    void Log(const std::string& msg) {
        std::lock_guard<std::mutex> lock(m_LogMutex);
        m_PendingLogs.push_back(msg);
    }

    void WorkerLoop() {
        while (m_Running) {
            Command cmd;
            bool hasCmd = false;
            {
                std::lock_guard<std::mutex> lock(m_QueueMutex);
                if (!m_Queue.empty()) {
                    cmd = m_Queue.front();
                    m_Queue.pop();
                    hasCmd = true;
                }
            }

            if (hasCmd) {
                ProcessCommand(cmd);
            } else {
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
        }
    }

    void ProcessCommand(const Command& cmd) {
        char pipeName[256];
        sprintf_s(pipeName, "\\\\.\\pipe\\luatool_%lu", cmd.pid);

        if (!WaitNamedPipeA(pipeName, 2000)) {
            Log("[Error] Pipe not ready. Error: " + std::to_string(GetLastError()));
            return;
        }

        HANDLE hPipe = CreateFileA(pipeName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (hPipe == INVALID_HANDLE_VALUE) {
            Log("[Error] Failed to connect. Error: " + std::to_string(GetLastError()));
            return;
        }

        DWORD mode = PIPE_READMODE_MESSAGE;
        SetNamedPipeHandleState(hPipe, &mode, NULL, NULL);

        // Send Request
        MessageHeader header = { (uint32_t)cmd.payload.size(), cmd.type };
        DWORD w;
        if (!WriteFile(hPipe, &header, sizeof(header), &w, NULL)) {
            Log("[Error] Write Header Failed. Error: " + std::to_string(GetLastError()));
            CloseHandle(hPipe);
            return;
        }
        if (header.length > 0) {
            if (!WriteFile(hPipe, cmd.payload.data(), header.length, &w, NULL)) {
                Log("[Error] Write Payload Failed. Error: " + std::to_string(GetLastError()));
                CloseHandle(hPipe);
                return;
            }
        }

        // Stream Response
        while (true) {
            // Wait for data with timeout
            bool dataReady = false;
            for (int i = 0; i < 50; i++) { // 5 seconds timeout for *next packet*
                DWORD avail = 0;
                if (PeekNamedPipe(hPipe, NULL, 0, NULL, &avail, NULL) && avail > 0) {
                    dataReady = true;
                    break;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }

            if (!dataReady) {
                Log("[Timeout] Agent timed out waiting for next packet.");
                break;
            }

            MessageHeader resp;
            DWORD r;
            if (!ReadFile(hPipe, &resp, sizeof(resp), &r, NULL) || r != sizeof(resp)) {
                Log("[Error] Failed to read header.");
                break;
            }

            std::string body;
            if (resp.length > 0) {
                std::vector<char> buf(resp.length);
                if (ReadFile(hPipe, buf.data(), resp.length, &r, NULL) && r == resp.length) {
                    body.assign(buf.begin(), buf.end());
                } else {
                    Log("[Error] Failed to read body.");
                    break;
                }
            }

            if (resp.type == RESP_OK) {
                Log("[OK] Finished.");
                break;
            } else if (resp.type == RESP_ERROR) {
                Log("[Error] " + body);
                break;
            } else if (resp.type == RESP_DATA) {
                Log(body);
            } else if (resp.type == RESP_PROGRESS) {
                // Update progress text
                // We'll need to store this somewhere to show in GUI
                // For now log it to console to verify
                Log("[Progress] " + body);
            }
        }
        CloseHandle(hPipe);
    }

    std::mutex m_QueueMutex;
    std::queue<Command> m_Queue;

    std::mutex m_LogMutex;
    std::vector<std::string> m_PendingLogs;

    std::thread m_Worker;
    std::atomic<bool> m_Running = false;
};

// ----------------------------------------------------------------------------
// GUI Main
// ----------------------------------------------------------------------------
int selected_pid = -1;
std::string output_log;
char script_buffer[16384] = "print('Hello')";
char filter_buf[128] = "";

int main(int, char**) {
    if (SDL_Init(SDL_INIT_VIDEO | SDL_INIT_TIMER | SDL_INIT_GAMECONTROLLER) != 0) return -1;

    const char* glsl_version = "#version 130";
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_FLAGS, 0);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_PROFILE_MASK, SDL_GL_CONTEXT_PROFILE_CORE);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MAJOR_VERSION, 3);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MINOR_VERSION, 0);

    SDL_WindowFlags window_flags = (SDL_WindowFlags)(SDL_WINDOW_OPENGL | SDL_WINDOW_RESIZABLE | SDL_WINDOW_ALLOW_HIGHDPI);
    SDL_Window* window = SDL_CreateWindow("LuaTool v2", SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED, 1280, 720, window_flags);
    SDL_GLContext gl_context = SDL_GL_CreateContext(window);
    SDL_GL_MakeCurrent(window, gl_context);
    SDL_GL_SetSwapInterval(1);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO(); (void)io;

    // Deep Dark Theme
    ImGui::StyleColorsDark();
    ImGuiStyle& style = ImGui::GetStyle();
    style.Colors[ImGuiCol_WindowBg] = ImVec4(0.1f, 0.1f, 0.12f, 1.0f);
    style.Colors[ImGuiCol_ChildBg] = ImVec4(0.15f, 0.15f, 0.18f, 1.0f);
    style.Colors[ImGuiCol_Border] = ImVec4(0.3f, 0.3f, 0.35f, 1.0f);
    style.Colors[ImGuiCol_Header] = ImVec4(0.2f, 0.25f, 0.3f, 1.0f);
    style.Colors[ImGuiCol_HeaderHovered] = ImVec4(0.3f, 0.35f, 0.45f, 1.0f);
    style.Colors[ImGuiCol_HeaderActive] = ImVec4(0.4f, 0.45f, 0.55f, 1.0f);
    style.Colors[ImGuiCol_Button] = ImVec4(0.25f, 0.3f, 0.4f, 1.0f);
    style.Colors[ImGuiCol_ButtonHovered] = ImVec4(0.35f, 0.4f, 0.5f, 1.0f);
    style.Colors[ImGuiCol_ButtonActive] = ImVec4(0.45f, 0.5f, 0.6f, 1.0f);

    ImGui_ImplSDL2_InitForOpenGL(window, gl_context);
    ImGui_ImplOpenGL3_Init(glsl_version);

    // Start Worker
    RemoteAgent::Get().Start();

    // Get Agent Path
    char pathBuf[MAX_PATH];
    GetModuleFileNameA(NULL, pathBuf, MAX_PATH);
    std::string exePath = pathBuf;
    std::string binDir = exePath.substr(0, exePath.find_last_of('\\'));
    std::string agentPath = binDir + "\\agent.dll";

    std::vector<ProcessInfo> processes = GetProcesses();
    bool done = false;

    while (!done) {
        SDL_Event event;
        while (SDL_PollEvent(&event)) {
            ImGui_ImplSDL2_ProcessEvent(&event);
            if (event.type == SDL_QUIT) done = true;
            if (event.type == SDL_WINDOWEVENT && event.window.event == SDL_WINDOWEVENT_CLOSE && event.window.windowID == SDL_GetWindowID(window)) done = true;
        }

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplSDL2_NewFrame();
        ImGui::NewFrame();

        {
            ImGui::SetNextWindowPos(ImVec2(0, 0));
            ImGui::SetNextWindowSize(io.DisplaySize);
            ImGui::Begin("LuaTool", NULL, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoTitleBar);

            ImGui::Columns(2, "MainLayout", true);
            static bool initial_layout = true;
            if (initial_layout) {
                ImGui::SetColumnWidth(0, 250);
                initial_layout = false;
            }

            // Left Sidebar
            ImGui::Text("Processes");
            ImGui::Separator();

            if (ImGui::Button("Refresh", ImVec2(-1, 0))) processes = GetProcesses();
            ImGui::InputText("Filter", filter_buf, IM_ARRAYSIZE(filter_buf));

            ImGui::BeginChild("Procs", ImVec2(0, -40), true);
            for (const auto& p : processes) {
                std::string filterStr = filter_buf;
                std::string nameStr = p.name;

                // Case insensitive search
                auto it = std::search(
                    nameStr.begin(), nameStr.end(),
                    filterStr.begin(), filterStr.end(),
                    [](char c1, char c2) { return std::toupper(c1) == std::toupper(c2); }
                );
                bool nameMatch = (it != nameStr.end());
                bool pidMatch = std::to_string(p.pid).find(filterStr) != std::string::npos;

                if (filter_buf[0] && !nameMatch && !pidMatch) continue;

                std::string label = std::to_string(p.pid) + " - " + p.name;
                if (ImGui::Selectable(label.c_str(), selected_pid == (int)p.pid)) selected_pid = p.pid;
            }
            ImGui::EndChild();

            if (selected_pid > 0) {
                 if (ImGui::Button("Inject", ImVec2(-1, 0))) {
                    if (InjectLibrary(selected_pid, agentPath)) output_log += "[Sys] Injected.\n";
                    else output_log += "[Sys] Injection Failed.\n";
                }
            } else {
                 ImGui::PushStyleVar(ImGuiStyleVar_Alpha, 0.5f);
                 ImGui::Button("Inject", ImVec2(-1, 0));
                 ImGui::PopStyleVar();
            }

            ImGui::NextColumn();

            // Right Main Area
            ImGui::Text("Script Editor");
            ImGui::SameLine();
            if (ImGui::Button("Load")) {
                char filename[256] = "script.lua";
                // Simple load (ideally file dialog, but kept simple for now)
                std::ifstream t(filename);
                if (t.is_open()) {
                    std::string str((std::istreambuf_iterator<char>(t)), std::istreambuf_iterator<char>());
                    if (str.length() < IM_ARRAYSIZE(script_buffer)) {
                        strcpy_s(script_buffer, str.c_str());
                        output_log += "[Sys] Loaded script.lua\n";
                    } else {
                        output_log += "[Sys] Script too large for buffer.\n";
                    }
                } else {
                    output_log += "[Sys] Failed to open script.lua\n";
                }
            }
            ImGui::SameLine();
            if (ImGui::Button("Save")) {
                std::ofstream t("script.lua");
                if (t.is_open()) {
                    t << script_buffer;
                    output_log += "[Sys] Saved to script.lua\n";
                } else {
                    output_log += "[Sys] Failed to save script.lua\n";
                }
            }
            ImGui::SameLine(ImGui::GetWindowWidth() - 80);
            if (ImGui::Button("Clear Log")) { output_log.clear(); }

            ImGui::InputTextMultiline("##Script", script_buffer, IM_ARRAYSIZE(script_buffer), ImVec2(-FLT_MIN, 250));

            if (ImGui::Button("Run Script", ImVec2(100, 0)) && selected_pid > 0) {
                RemoteAgent::Get().Send(selected_pid, CMD_RUN_SCRIPT, script_buffer);
            }
            ImGui::SameLine();
            if (ImGui::Button("Dump Globals", ImVec2(100, 0)) && selected_pid > 0) {
                RemoteAgent::Get().Send(selected_pid, CMD_DUMP_GLOBALS, "");
            }

            // Progress Bar
            static float progress = 0.0f;
            static char progressText[128] = "";

            // Check logs for progress
            // In a real app we'd have a callback or event, but parsing logs works for this demo
            auto logs = RemoteAgent::Get().ConsumeLogs();
            for (const auto& l : logs) {
                output_log += l + "\n";
                if (l.find("[Progress]") != std::string::npos) {
                    // Extract info if needed, for now just animate
                    progress += 0.1f;
                    if (progress > 1.0f) progress = 0.0f;
                    strncpy(progressText, l.c_str(), 127);
                } else if (l.find("[OK] Finished") != std::string::npos) {
                    progress = 1.0f;
                    strncpy(progressText, "Done.", 127);
                }
            }

            if (progress > 0.0f && progress < 1.0f) {
                ImGui::ProgressBar(progress, ImVec2(0.0f, 0.0f), progressText);
                ImGui::SameLine();
                ImGui::Text("Working...");
            }

            ImGui::Separator();
            ImGui::Text("Logs");

            ImGui::BeginChild("Log", ImVec2(0, 0), true);
            ImGui::TextUnformatted(output_log.c_str());
            if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY()) ImGui::SetScrollHereY(1.0f);
            ImGui::EndChild();

            ImGui::End();
        }

        ImGui::Render();
        glViewport(0, 0, (int)io.DisplaySize.x, (int)io.DisplaySize.y);
        glClearColor(0.2f, 0.2f, 0.2f, 1.0f);
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
