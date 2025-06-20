#pragma once

#include "json.h"

// ApiType enum is defined in json.h

void PipeClientInit();
void PipeClientShutdown();
void PipeSendEvent(const CapturedEvent& event);
