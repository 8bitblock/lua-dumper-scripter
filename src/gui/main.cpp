#define SDL_MAIN_HANDLED
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
#include <filesystem>
#include "../common/lua_ipc.h"

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

    bool IsBusy() const { return m_IsBusy; }
    std::string GetStatusText() {
        std::lock_guard<std::mutex> lock(m_StatusMutex);
        return m_StatusText;
    }
    std::string GetLastResult() {
        std::lock_guard<std::mutex> lock(m_StatusMutex);
        return m_LastResult;
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
        m_IsBusy = true;
        {
            std::lock_guard<std::mutex> lock(m_StatusMutex);
            if (cmd.type == CMD_RUN_SCRIPT) m_StatusText = "Running Script...";
            else if (cmd.type == CMD_DUMP_GLOBALS) m_StatusText = "Dumping Globals...";
            else m_StatusText = "Processing...";
        }

        char pipeName[256];
        sprintf_s(pipeName, "\\\\.\\pipe\\luatool_%lu", cmd.pid);

        if (!WaitNamedPipeA(pipeName, 2000)) {
            Log("[Error] Pipe not ready. Error: " + std::to_string(GetLastError()));
            m_IsBusy = false;
            return;
        }

        HANDLE hPipe = CreateFileA(pipeName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (hPipe == INVALID_HANDLE_VALUE) {
            Log("[Error] Failed to connect. Error: " + std::to_string(GetLastError()));
            m_IsBusy = false;
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
            m_IsBusy = false;
            return;
        }
        if (header.length > 0) {
            if (!WriteFile(hPipe, cmd.payload.data(), header.length, &w, NULL)) {
                Log("[Error] Write Payload Failed. Error: " + std::to_string(GetLastError()));
                CloseHandle(hPipe);
                m_IsBusy = false;
                return;
            }
        }

        // Stream Response
        while (true) {
            MessageHeader resp;
            DWORD r;
            if (!ReadFile(hPipe, &resp, sizeof(resp), &r, NULL) || r != sizeof(resp)) {
                Log("[Error] Failed to read header (Pipe Closed or Error).");
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
                std::lock_guard<std::mutex> lock(m_StatusMutex);
                m_LastResult = "Done.";
                break;
            } else if (resp.type == RESP_ERROR) {
                Log("[Error] " + body);
                std::lock_guard<std::mutex> lock(m_StatusMutex);
                m_LastResult = "Error: " + body;
                break;
            } else if (resp.type == RESP_DATA) {
                Log(body);
            } else if (resp.type == RESP_PROGRESS) {
                std::lock_guard<std::mutex> lock(m_StatusMutex);
                m_StatusText = body;
                // Also log progress to the console
                Log("[Progress] " + body);
            }
        }
        CloseHandle(hPipe);
        m_IsBusy = false;
    }

    std::mutex m_QueueMutex;
    std::queue<Command> m_Queue;

    std::mutex m_LogMutex;
    std::vector<std::string> m_PendingLogs;

    std::thread m_Worker;
    std::atomic<bool> m_Running = false;

    std::atomic<bool> m_IsBusy{false};
    std::mutex m_StatusMutex;
    std::string m_StatusText;
    std::string m_LastResult = "Ready";
};

// ----------------------------------------------------------------------------
// GUI Main
// ----------------------------------------------------------------------------
int selected_pid = -1;
std::string output_log;
char script_buffer[16384] = "print('Hello')";
char filter_buf[128] = "";

// Data Caches
std::vector<std::string> player_list;
std::vector<std::string> registry_list;
std::vector<std::string> inspector_list;
std::vector<std::string> script_list;
std::string current_script_source;
std::string console_log;

// Helper to parse | separated strings
std::vector<std::string> ParseRow(const std::string& row) {
    std::vector<std::string> cols;
    size_t start = 0;
    size_t end = row.find('|');
    while (end != std::string::npos) {
        cols.push_back(row.substr(start, end - start));
        start = end + 1;
        end = row.find('|', start);
    }
    cols.push_back(row.substr(start));
    return cols;
}

int main(int argc, char* argv[]) {
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

            if (ImGui::BeginTabBar("MainTabs")) {
                // Shared state for navigation
                static bool requestInspectorFocus = false;
                static std::string inspectorKey = "";

                if (ImGui::BeginTabItem("Connection")) {
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
                    ImGui::EndTabItem();
                }

                if (ImGui::BeginTabItem("Players")) {
                    if (ImGui::Button("Scan Players") && selected_pid > 0) {
                        RemoteAgent::Get().Send(selected_pid, CMD_SCAN_PLAYERS, "");
                    }
                    ImGui::Separator();

                    static char pFilter[64] = "";
                    ImGui::InputText("Filter##P", pFilter, 64);

                    static std::vector<int> pIndices;
                    pIndices.clear();
                    pIndices.reserve(player_list.size());
                    for (int i = 0; i < (int)player_list.size(); ++i) {
                        if (!pFilter[0] || player_list[i].find(pFilter) != std::string::npos) pIndices.push_back(i);
                    }

                    if (ImGui::BeginTable("PlayersTable", 3, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable)) {
                        ImGui::TableSetupColumn("Name");
                        ImGui::TableSetupColumn("Address");
                        ImGui::TableSetupColumn("Position");
                        ImGui::TableHeadersRow();

                        ImGuiListClipper clipper;
                        clipper.Begin((int)pIndices.size());
                        while (clipper.Step()) {
                            for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; i++) {
                                int idx = pIndices[i];
                                auto cols = ParseRow(player_list[idx]);
                                if (cols.size() >= 1) {
                                    ImGui::TableNextRow();
                                    ImGui::TableSetColumnIndex(0); ImGui::TextUnformatted(cols[0].c_str());
                                    if (cols.size() >= 2) { ImGui::TableSetColumnIndex(1); ImGui::TextUnformatted(cols[1].c_str()); }
                                    if (cols.size() >= 3) { ImGui::TableSetColumnIndex(2); ImGui::TextUnformatted(cols[2].c_str()); }
                                }
                            }
                        }
                        ImGui::EndTable();
                    }
                    ImGui::EndTabItem();
                }

                if (ImGui::BeginTabItem("Registry")) {
                    if (ImGui::Button("Dump Registry") && selected_pid > 0) {
                        RemoteAgent::Get().Send(selected_pid, CMD_DUMP_REGISTRY, "");
                    }
                    ImGui::Separator();

                    static char rFilter[64] = "";
                    ImGui::InputText("Filter##R", rFilter, 64);

                    static std::vector<int> rIndices;
                    rIndices.clear();
                    rIndices.reserve(registry_list.size());
                    for (int i = 0; i < (int)registry_list.size(); ++i) {
                        if (!rFilter[0] || registry_list[i].find(rFilter) != std::string::npos) rIndices.push_back(i);
                    }

                    // Selection state
                    static int selectedRegistryRow = -1;

                    if (ImGui::BeginTable("RegistryTable", 3, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY)) {
                        ImGui::TableSetupColumn("Key");
                        ImGui::TableSetupColumn("Type");
                        ImGui::TableSetupColumn("Value");
                        ImGui::TableHeadersRow();

                        ImGuiListClipper clipper;
                        clipper.Begin((int)rIndices.size());
                        while (clipper.Step()) {
                            for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; i++) {
                                int idx = rIndices[i];
                                auto cols = ParseRow(registry_list[idx]);
                                if (cols.size() >= 3) {
                                    ImGui::TableNextRow();

                                    // Selectable Row
                                    bool isSelected = (selectedRegistryRow == idx);
                                    ImGui::TableSetColumnIndex(0);
                                    if (ImGui::Selectable(cols[0].c_str(), isSelected, ImGuiSelectableFlags_SpanAllColumns)) {
                                        selectedRegistryRow = idx;
                                    }
                                    // Context Menu
                                    if (ImGui::BeginPopupContextItem()) {
                                        if (cols[1].find("table") != std::string::npos || cols[1].find("userdata") != std::string::npos) {
                                             if (ImGui::Selectable("Inspect")) {
                                                 inspectorKey = cols[0];
                                                 requestInspectorFocus = true;
                                                 if (selected_pid > 0) {
                                                     inspector_list.clear();
                                                     inspector_list.push_back("Loading...");
                                                     RemoteAgent::Get().Send(selected_pid, CMD_INSPECT_REGISTRY_ITEM, inspectorKey);
                                                 }
                                             }
                                        }
                                        ImGui::EndPopup();
                                    }

                                    ImGui::TableSetColumnIndex(1); ImGui::TextUnformatted(cols[1].c_str());
                                    ImGui::TableSetColumnIndex(2); ImGui::TextUnformatted(cols[2].c_str());
                                }
                            }
                        }
                        ImGui::EndTable();
                    }
                    ImGui::EndTabItem();
                }

                // Handle Focus Request
                ImGuiTabItemFlags inspectorFlags = 0;
                if (requestInspectorFocus) {
                    inspectorFlags |= ImGuiTabItemFlags_SetSelected;
                    requestInspectorFocus = false;
                }

                if (ImGui::BeginTabItem("Inspector", NULL, inspectorFlags)) {
                    ImGui::Text("Inspecting: %s", inspectorKey.empty() ? "(None)" : inspectorKey.c_str());
                    if (ImGui::Button("Refresh") && selected_pid > 0 && !inspectorKey.empty()) {
                        RemoteAgent::Get().Send(selected_pid, CMD_INSPECT_REGISTRY_ITEM, inspectorKey);
                    }
                    ImGui::Separator();

                    static char iFilter[64] = "";
                    ImGui::InputText("Filter##I", iFilter, 64);

                    if (ImGui::BeginTable("InspectorTable", 3, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY)) {
                        ImGui::TableSetupColumn("Key");
                        ImGui::TableSetupColumn("Type");
                        ImGui::TableSetupColumn("Value");
                        ImGui::TableHeadersRow();

                        for (const auto& row : inspector_list) {
                            if (row == "Loading...") {
                                ImGui::TableNextRow();
                                ImGui::TableSetColumnIndex(0); ImGui::Text("Loading...");
                                continue;
                            }
                            if (iFilter[0] && row.find(iFilter) == std::string::npos) continue;

                            auto cols = ParseRow(row);
                            if (cols.size() >= 3) {
                                 ImGui::TableNextRow();
                                 ImGui::TableSetColumnIndex(0); ImGui::TextUnformatted(cols[0].c_str());
                                 ImGui::TableSetColumnIndex(1); ImGui::TextUnformatted(cols[1].c_str());
                                 ImGui::TableSetColumnIndex(2); ImGui::TextUnformatted(cols[2].c_str());
                            } else if (cols.size() == 1) {
                                 // Header or message
                                 ImGui::TableNextRow();
                                 ImGui::TableSetColumnIndex(0); ImGui::TextUnformatted(cols[0].c_str());
                            }
                        }
                        ImGui::EndTable();
                    }
                    ImGui::EndTabItem();
                }

                if (ImGui::BeginTabItem("Scripts")) {
                    if (ImGui::Button("Scan Scripts") && selected_pid > 0) {
                        RemoteAgent::Get().Send(selected_pid, CMD_DUMP_SCRIPTS, "");
                    }
                    ImGui::Separator();

                    ImGui::BeginGroup();
                    static char sFilter[64] = "";
                    ImGui::InputText("Filter##S", sFilter, 64);

                    ImGui::BeginChild("ScriptList", ImVec2(250, 0), true);
                    static int selectedScript = -1;

                    static std::vector<int> sIndices;
                    sIndices.clear();
                    sIndices.reserve(script_list.size());
                    for (int i = 0; i < (int)script_list.size(); ++i) {
                        if (!sFilter[0] || script_list[i].find(sFilter) != std::string::npos) sIndices.push_back(i);
                    }

                    ImGuiListClipper clipper;
                    clipper.Begin((int)sIndices.size());
                    while (clipper.Step()) {
                        for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; i++) {
                            int idx = sIndices[i];
                            std::vector<std::string> cols = ParseRow(script_list[idx]);
                            std::string name = cols.empty() ? "?" : cols[0];
                            if (ImGui::Selectable(name.c_str(), selectedScript == idx)) {
                                selectedScript = idx;
                                current_script_source = "Loading...";
                                if (selected_pid > 0) {
                                    RemoteAgent::Get().Send(selected_pid, CMD_GET_SCRIPT_SOURCE, name);
                                }
                            }
                        }
                    }
                    ImGui::EndChild();
                    ImGui::EndGroup();

                    ImGui::SameLine();

                    ImGui::BeginGroup();
                    ImGui::BeginChild("ScriptSource", ImVec2(0, 0), true);
                    ImGui::TextUnformatted(current_script_source.c_str());
                    ImGui::EndChild();
                    ImGui::EndGroup();

                    ImGui::EndTabItem();
                }

                if (ImGui::BeginTabItem("Console")) {
                    if (ImGui::Button("Clear Console")) console_log.clear();
                    ImGui::BeginChild("ConsoleLog", ImVec2(0,0), true);
                    ImGui::TextUnformatted(console_log.c_str());
                    if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY()) ImGui::SetScrollHereY(1.0f);
                    ImGui::EndChild();
                    ImGui::EndTabItem();
                }

                if (ImGui::BeginTabItem("Executor")) {
                    ImGui::Columns(2, "ExecCols", true);

                    // Left Column: File Manager
                    ImGui::Text("Script Library");
                    ImGui::Separator();

                    // Ensure scripts dir exists
                    std::filesystem::create_directory("scripts");

                    static std::string selectedFile = "";
                    static char fileNameBuf[64] = "new_script.lua";

                    ImGui::BeginChild("FileList", ImVec2(0, 200), true);
                    if (ImGui::Button("Refresh List")) { /* directory_iterator will pick it up next frame */ }
                    ImGui::Separator();

                    for (const auto& entry : std::filesystem::directory_iterator("scripts")) {
                        if (entry.is_regular_file()) {
                            std::string filename = entry.path().filename().string();
                            if (ImGui::Selectable(filename.c_str(), selectedFile == filename)) {
                                selectedFile = filename;
                                strcpy_s(fileNameBuf, filename.c_str()); // Auto-fill filename input

                                // Instant Load
                                std::ifstream t("scripts/" + selectedFile);
                                if (t.is_open()) {
                                    std::string str((std::istreambuf_iterator<char>(t)), std::istreambuf_iterator<char>());
                                    if (str.length() < IM_ARRAYSIZE(script_buffer)) {
                                        strcpy_s(script_buffer, str.c_str());
                                        output_log += "[Sys] Loaded " + selectedFile + "\n";
                                    } else {
                                        output_log += "[Sys] Error: Script too large for buffer.\n";
                                    }
                                }
                            }
                        }
                    }
                    ImGui::EndChild();

                    ImGui::InputText("Filename", fileNameBuf, 64);

                    if (ImGui::Button("Save")) {
                        std::string fname = fileNameBuf;
                        if (fname.find(".lua") == std::string::npos) fname += ".lua";
                        std::ofstream t("scripts/" + fname);
                        if (t.is_open()) {
                            t << script_buffer;
                            output_log += "[Sys] Saved to " + fname + "\n";
                            selectedFile = fname; // Auto-select saved file
                        }
                    }
                    ImGui::SameLine();
                    if (ImGui::Button("Clear")) {
                        script_buffer[0] = 0;
                        selectedFile = "";
                        strcpy_s(fileNameBuf, "new_script.lua");
                    }

                    ImGui::NextColumn();

                    // Right Column: Editor
                    ImGui::Text("Script Editor");
                    ImGui::SameLine();
                    if (ImGui::Button("Run Script") && selected_pid > 0) {
                        RemoteAgent::Get().Send(selected_pid, CMD_RUN_SCRIPT, script_buffer);
                    }
                    ImGui::SameLine();
                    if (ImGui::Button("Clear Editor")) { script_buffer[0] = 0; }

                    // Adjust height to fill space, leaving room for override controls at bottom
                    float footerHeight = 80.0f;
                    ImGui::InputTextMultiline("##Script", script_buffer, IM_ARRAYSIZE(script_buffer), ImVec2(-FLT_MIN, -footerHeight));

                    ImGui::Separator();
                    ImGui::Text("Script Overrides");
                    static char overrideTarget[128] = "";
                    ImGui::InputText("Target Name", overrideTarget, 128);
                    ImGui::SameLine();
                    if (ImGui::Button("Set Override") && selected_pid > 0) {
                        if (strlen(overrideTarget) > 0) {
                            std::string payload = std::string(overrideTarget) + "\n" + std::string(script_buffer);
                            RemoteAgent::Get().Send(selected_pid, CMD_ADD_OVERRIDE, payload);
                            output_log += "[Sys] Override set for " + std::string(overrideTarget) + "\n";
                        }
                    }
                    ImGui::SameLine();
                    if (ImGui::Button("Reset All") && selected_pid > 0) {
                        RemoteAgent::Get().Send(selected_pid, CMD_RESET_OVERRIDES, "");
                        output_log += "[Sys] Overrides reset.\n";
                    }

                    ImGui::Columns(1);
                    ImGui::EndTabItem();
                }
                ImGui::EndTabBar();
            }

            // Process Logs and Data
            auto logs = RemoteAgent::Get().ConsumeLogs();
            for (const auto& l : logs) {
                if (l.find("Scan Players Results:") != std::string::npos) {
                    player_list.clear();
                    std::string data = l.substr(l.find('\n') + 1);
                    size_t pos = 0;
                    while ((pos = data.find('\n')) != std::string::npos) {
                        player_list.push_back(data.substr(0, pos));
                        data.erase(0, pos + 1);
                    }
                }
                else if (l.find("Inspection Results for:") != std::string::npos) {
                    inspector_list.clear();
                    std::string data = l.substr(l.find('\n') + 1);
                    size_t pos = 0;
                    while ((pos = data.find('\n')) != std::string::npos) {
                        inspector_list.push_back(data.substr(0, pos));
                        data.erase(0, pos + 1);
                    }
                }
                else if (l.find("Registry Dump:") != std::string::npos) {
                    registry_list.clear();
                    std::string data = l.substr(l.find('\n') + 1);
                    size_t pos = 0;
                    while ((pos = data.find('\n')) != std::string::npos) {
                        registry_list.push_back(data.substr(0, pos));
                        data.erase(0, pos + 1);
                    }
                }
                else if (l.find("Discovered Scripts") != std::string::npos) {
                    script_list.clear();
                    std::string data = l.substr(l.find('\n') + 1);
                    size_t pos = 0;
                    while ((pos = data.find('\n')) != std::string::npos) {
                        script_list.push_back(data.substr(0, pos));
                        data.erase(0, pos + 1);
                    }
                }
                else if (l.find("-- Source for") != std::string::npos || l.find("-- Override Found:") != std::string::npos) {
                    current_script_source = l;
                }
                else if (l.find("[LUA]") != std::string::npos) {
                    console_log += l + "\n";
                }
                else {
                    output_log += l + "\n";
                }
            }

            // Status Bar with Animation
            ImGui::Separator();
            if (RemoteAgent::Get().IsBusy()) {
                std::string status = RemoteAgent::Get().GetStatusText();

                // Dot animation
                double time = ImGui::GetTime();
                int dots = (int)(time * 2.0) % 4;
                if (dots == 1) status += ".";
                else if (dots == 2) status += "..";
                else if (dots == 3) status += "...";

                ImGui::TextColored(ImVec4(1.0f, 1.0f, 0.0f, 1.0f), "%s", status.c_str());
            } else {
                std::string result = RemoteAgent::Get().GetLastResult();
                ImGui::TextColored(ImVec4(0.0f, 1.0f, 0.0f, 1.0f), "%s", result.c_str());
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
