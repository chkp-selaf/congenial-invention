#pragma once

#include "json.h"

// ApiType enum is defined in json.h

void PipeInitialize();
void PipeShutdown();
void PipeSendEvent(const CapturedEvent& event);
