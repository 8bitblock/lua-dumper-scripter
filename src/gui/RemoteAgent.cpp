#include "RemoteAgent.h"
#include <iostream>
#include <chrono>

RemoteAgent& RemoteAgent::Get() {
    static RemoteAgent instance;
    return instance;
}

RemoteAgent::RemoteAgent() {}

void RemoteAgent::Start() {
    if (m_Running) return;
    m_Running = true;
    m_Worker = std::thread(&RemoteAgent::WorkerLoop, this);
    m_Worker.detach();
}

void RemoteAgent::Send(DWORD pid, MessageType type, const std::string& payload) {
    std::lock_guard<std::mutex> lock(m_QueueMutex);
    m_Queue.push({ pid, type, payload });
}

std::vector<std::string> RemoteAgent::ConsumeLogs() {
    std::vector<std::string> logs;
    {
        std::lock_guard<std::mutex> lock(m_LogMutex);
        logs.swap(m_PendingLogs);
    }
    return logs;
}

std::string RemoteAgent::GetStatusText() {
    std::lock_guard<std::mutex> lock(m_StatusMutex);
    return m_StatusText;
}

std::string RemoteAgent::GetLastResult() {
    std::lock_guard<std::mutex> lock(m_StatusMutex);
    return m_LastResult;
}

void RemoteAgent::Log(const std::string& msg) {
    std::lock_guard<std::mutex> lock(m_LogMutex);
    m_PendingLogs.push_back(msg);
}

void RemoteAgent::WorkerLoop() {
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

void RemoteAgent::Disconnect() {
    if (m_hPipe != INVALID_HANDLE_VALUE) {
        CloseHandle(m_hPipe);
        m_hPipe = INVALID_HANDLE_VALUE;
    }
}

void RemoteAgent::ProcessCommand(const Command& cmd) {
    m_IsBusy = true;
    {
        std::lock_guard<std::mutex> lock(m_StatusMutex);
        if (cmd.type == CMD_RUN_SCRIPT) m_StatusText = "Running Script...";
        else if (cmd.type == CMD_DUMP_GLOBALS) m_StatusText = "Dumping Globals...";
        else m_StatusText = "Processing...";
    }

    // Ensure connection
    if (m_hPipe == INVALID_HANDLE_VALUE) {
        char pipeName[256];
        sprintf_s(pipeName, "\\\\.\\pipe\\luatool_%lu", cmd.pid);

        if (!WaitNamedPipeA(pipeName, 500)) { // Short wait
            // Log("[Error] Pipe not ready."); // Reduce spam
            Disconnect();
            m_IsBusy = false;
            return;
        }

        m_hPipe = CreateFileA(pipeName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (m_hPipe == INVALID_HANDLE_VALUE) {
            Log("[Error] Failed to connect. Error: " + std::to_string(GetLastError()));
            m_IsBusy = false;
            return;
        }

        DWORD mode = PIPE_READMODE_MESSAGE;
        SetNamedPipeHandleState(m_hPipe, &mode, NULL, NULL);
    }

    // Send Request
    MessageHeader header = { (uint32_t)cmd.payload.size(), cmd.type };
    DWORD w;
    if (!WriteFile(m_hPipe, &header, sizeof(header), &w, NULL)) {
        Log("[Error] Write Header Failed. Reconnecting...");
        Disconnect();
        m_IsBusy = false;
        return;
    }
    if (header.length > 0) {
        if (!WriteFile(m_hPipe, cmd.payload.data(), header.length, &w, NULL)) {
            Log("[Error] Write Payload Failed.");
            Disconnect();
            m_IsBusy = false;
            return;
        }
    }

    // Stream Response
    while (true) {
        MessageHeader resp;
        DWORD r;
        if (!ReadFile(m_hPipe, &resp, sizeof(resp), &r, NULL) || r != sizeof(resp)) {
            Log("[Error] Failed to read header. Disconnecting.");
            Disconnect();
            break;
        }

        std::string body;
        if (resp.length > 0) {
            std::vector<char> buf(resp.length);
            if (ReadFile(m_hPipe, buf.data(), resp.length, &r, NULL) && r == resp.length) {
                body.assign(buf.begin(), buf.end());
            } else {
                Log("[Error] Failed to read body.");
                Disconnect();
                break;
            }
        }

        if (resp.type == RESP_OK) {
            // Log("[OK] Finished."); // Reduce spam for polling
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
            Log("[Progress] " + body);
        }
    }
    m_IsBusy = false;
}
