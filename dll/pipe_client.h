#pragma once

#include "json.h"

enum class ApiType {
    Unknown,
    WinHttpSend,
    WinHttpRead,
    WebSocketSend,
    WebSocketReceive,
    SslWrite,
    SchannelEncrypt,
    SchannelDecrypt
};

void PipeInitialize();
void PipeShutdown();
void PipeSendEvent(const CapturedEvent& event);
