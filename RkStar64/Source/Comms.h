#pragma once
#include "../Shared.h"
#include "Nt.hpp"

namespace Comms
{
    NTSTATUS HandleHandshake(
        _In_ WDFREQUEST Request,
        _In_ size_t InputBufferLength,
        _In_ size_t OutputBufferLength
    );

    NTSTATUS HandleRequest(
        _In_ WDFREQUEST Request,
        _In_ size_t InputBufferLength,
        _In_ size_t OutputBufferLength
    );

    NTSTATUS HandleReadMemory(_In_ const comms::RequestData* request, _Inout_ comms::RequestData* response);
    NTSTATUS HandleWriteMemory(_In_ const comms::RequestData* request);
    NTSTATUS HandleGetBaseAddress(_In_ const comms::RequestData* request, _Inout_ comms::RequestData* response);
}