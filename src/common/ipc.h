#pragma once
#include <string>
#include <vector>
#include <cstdint>

enum MessageType : uint8_t {
    CMD_PING = 0,
    CMD_RUN_SCRIPT = 1,
    CMD_DUMP_GLOBALS = 2,
    RESP_OK = 10,
    RESP_ERROR = 11,
    RESP_DATA = 12,
    RESP_PROGRESS = 13
};

struct MessageHeader {
    uint32_t length;
    MessageType type;
};
