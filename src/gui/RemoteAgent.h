#pragma once
#include <string>
#include <vector>
#include <queue>
#include <mutex>
#include <atomic>
#include <thread>
#include <windows.h>
#include "../common/lua_ipc.h"

class RemoteAgent {
public:
    struct Command {
        DWORD pid;
        MessageType type;
        std::string payload;
    };

    static RemoteAgent& Get();

    void Start();
    void Send(DWORD pid, MessageType type, const std::string& payload);
    std::vector<std::string> ConsumeLogs();

    bool IsBusy() const { return m_IsBusy; }
    std::string GetStatusText();
    std::string GetLastResult();

private:
    RemoteAgent();
    ~RemoteAgent() = default;

    void Log(const std::string& msg);
    void WorkerLoop();
    void ProcessCommand(const Command& cmd);
    void Disconnect();

    HANDLE m_hPipe = INVALID_HANDLE_VALUE;

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
