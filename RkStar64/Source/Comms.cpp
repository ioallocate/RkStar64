#include "Comms.h"
#include "Utils.hpp"
#include "Nt.hpp"
#include "Entry.hpp"

extern "C" NTSYSAPI NTSTATUS ObOpenObjectByPointer(
	_In_ PVOID Object,
	_In_ ULONG HandleAttributes,
	_In_opt_ PACCESS_STATE PassedAccessState,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_TYPE ObjectType,
	_In_ KPROCESSOR_MODE AccessMode,
	_Out_ PHANDLE Handle
);
#define PROCESS_QUERY_INFORMATION 0x0400

typedef int BOOL;

static NTSTATUS ValidateUserMemoryRequest(
    _In_ const comms::RequestData* request,
    _Outptr_ PEPROCESS* out_target_process
)
{
    PAGED_CODE();

    if (!request || !out_target_process) {
        return STATUS_INVALID_PARAMETER;
    }

    *out_target_process = nullptr;

    if (request->size == 0 || request->size > 0x100000) { 
        return STATUS_INVALID_PARAMETER;
    }

    uintptr_t end_address_req, end_address_buf;
    NTSTATUS status = RtlULongPtrAdd(request->address, request->size, &end_address_req);
    if (!NT_SUCCESS(status)) {
        return STATUS_INTEGER_OVERFLOW;
    }
    status = RtlULongPtrAdd(request->buffer, request->size, &end_address_buf);
    if (!NT_SUCCESS(status)) {
        return STATUS_INTEGER_OVERFLOW;
    }

    if (request->address >= reinterpret_cast<uintptr_t>(MM_HIGHEST_USER_ADDRESS) ||
        end_address_req > reinterpret_cast<uintptr_t>(MM_HIGHEST_USER_ADDRESS) ||
        request->buffer >= reinterpret_cast<uintptr_t>(MM_HIGHEST_USER_ADDRESS) ||
        end_address_buf > reinterpret_cast<uintptr_t>(MM_HIGHEST_USER_ADDRESS)) {
        return STATUS_ACCESS_VIOLATION;
    }

    return Nt::g_Fns.pPsLookupProcessByProcessId(reinterpret_cast<HANDLE>(request->process_id), out_target_process);
}

NTSTATUS Comms::HandleHandshake(
	_In_ WDFREQUEST Request,
	_In_ size_t InputBufferLength,
	_In_ size_t OutputBufferLength
)
{
    UNREFERENCED_PARAMETER(InputBufferLength);
    PAGED_CODE();

    PDEVICE_CONTEXT context = GetDeviceContext(WdfIoQueueGetDevice(WdfRequestGetIoQueue(Request)));
    if (!context) {
        return STATUS_DEVICE_NOT_READY;
    }

    if (OutputBufferLength < sizeof(uint64_t)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    PVOID user_buffer = nullptr;
    size_t buffer_size = 0;
    NTSTATUS status = WdfRequestRetrieveOutputBuffer(Request, sizeof(uint64_t), &user_buffer, &buffer_size);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    uint64_t new_session_key = 0;
    status = Utils::Cryptography::GenerateRandomNumber(&new_session_key, sizeof(new_session_key));
    if (!NT_SUCCESS(status)) {
        return status;
    }

    InterlockedExchange64(&context->SessionKey, new_session_key);

    *static_cast<uint64_t *>(user_buffer) = new_session_key;

    WdfRequestSetInformation(
        Request,
        sizeof(uint64_t));

    return STATUS_SUCCESS;

	KdPrint(("[RkStar64 Telemetry] Handshake completed."));

    WdfRequestSetInformation(Request, sizeof(uint64_t));
    return STATUS_SUCCESS;
}

NTSTATUS Comms::HandleRequest(
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength
)
{
    PAGED_CODE();

    WDFDEVICE device = WdfIoQueueGetDevice(WdfRequestGetIoQueue(Request));
    PDEVICE_CONTEXT context = GetDeviceContext(device);
    if (!context)
    {
        return STATUS_DEVICE_NOT_READY;
    }

    comms::MaskedPacket *in_masked_packet = nullptr;
    comms::MaskedPacket *out_masked_packet = nullptr;

    NTSTATUS status = WdfRequestRetrieveInputBuffer(
        Request,
        sizeof(comms::MaskedPacket),
        (PVOID *)&in_masked_packet,
        nullptr
    );

    if (!NT_SUCCESS(status))
    {
        return status;
    }

    status = WdfRequestRetrieveOutputBuffer(
        Request,
        sizeof(comms::MaskedPacket),
        (PVOID *)&out_masked_packet,
        nullptr
    );

    if (!NT_SUCCESS(status))
    {
        return status;
    }

    comms::RequestData request_data;
    comms::CommunicationPacket *in_packet = &in_masked_packet->packet;

    __try
    {
        status = Utils::Cryptography::Decrypt(
            context->AesGcmAlgHandle,
            context->SessionKey,
            in_packet->session_key_iv,
            in_packet->data,
            sizeof(in_packet->data),
            reinterpret_cast<PUCHAR>(&request_data),
            sizeof(request_data)
        );
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return GetExceptionCode();
    }

    if (!NT_SUCCESS(status))
    {
        return status;
    }

    comms::RequestData response_data = request_data;

    switch (request_data.type)
    {
        case comms::RequestType::Read:
            status = HandleReadMemory(&request_data, &response_data);
            break;

        case comms::RequestType::Write:
            status = HandleWriteMemory(&request_data);
            break;

        case comms::RequestType::GetBaseAddress:
            status = HandleGetBaseAddress(&request_data, &response_data);
            break;

        default:
            status = STATUS_INVALID_PARAMETER;
            break;
    }

    if (!NT_SUCCESS(status))
    {
        return status;
    }

    response_data.type = request_data.type;

    __try
    {
        auto *out_packet = &out_masked_packet->packet;
        out_packet->session_key_iv = in_packet->session_key_iv;

        NTSTATUS crypto_status = Utils::Cryptography::Encrypt(
            context->AesGcmAlgHandle,
            context->SessionKey,
            out_packet->session_key_iv,
            reinterpret_cast<PUCHAR>(&response_data),
            sizeof(response_data),
            out_packet->data,
            sizeof(out_packet->data)
        );

        if (!NT_SUCCESS(crypto_status))
        {
            return crypto_status;
        }

        out_masked_packet->magic = comms::PACKET_MAGIC;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return GetExceptionCode();
    }

    WdfRequestSetInformation(Request, sizeof(comms::MaskedPacket));
    return STATUS_SUCCESS;
}

NTSTATUS Comms::HandleReadMemory(_In_ const comms::RequestData* request, _Inout_ comms::RequestData* response)
{
    PAGED_CODE();

    PEPROCESS target_process_ptr = nullptr;
    NTSTATUS status = ValidateUserMemoryRequest(request, &target_process_ptr);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    Utils::ProcessGuard target_process(target_process_ptr);
    SIZE_T bytes_copied = 0;

    __try {
        ProbeForWrite(reinterpret_cast<PVOID>(response->buffer), request->size, 1);
        status = Nt::g_Fns.pMmCopyVirtualMemory(
            target_process.get(),
            reinterpret_cast<PVOID>(request->address),
            PsGetCurrentProcess(),
            reinterpret_cast<PVOID>(response->buffer),
            request->size,
            KernelMode,
            &bytes_copied
        );
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    return status;
}

NTSTATUS Comms::HandleWriteMemory(_In_ const comms::RequestData* request)
{
    PAGED_CODE();

    PEPROCESS target_process_ptr = nullptr;
    NTSTATUS status = ValidateUserMemoryRequest(request, &target_process_ptr);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    Utils::ProcessGuard target_process(target_process_ptr);
    SIZE_T bytes_copied = 0;

    __try {
        ProbeForRead(reinterpret_cast<PVOID>(request->buffer), request->size, 1);
        status = Nt::g_Fns.pMmCopyVirtualMemory(
            PsGetCurrentProcess(),
            reinterpret_cast<PVOID>(request->buffer),
            target_process.get(),
            reinterpret_cast<PVOID>(request->address),
            request->size,
            KernelMode,
            &bytes_copied
        );
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    return status;
}

NTSTATUS Comms::HandleGetBaseAddress(_In_ const comms::RequestData* request, _Inout_ comms::RequestData* response)
{
    PAGED_CODE();
    if (!request || !response) return STATUS_INVALID_PARAMETER;

    PEPROCESS target_process_ptr = nullptr;
    NTSTATUS status = Nt::g_Fns.pPsLookupProcessByProcessId(
        reinterpret_cast<HANDLE>(request->process_id),
        &target_process_ptr
    );
    if (!NT_SUCCESS(status)) return status;

    Utils::ProcessGuard target_process(target_process_ptr);

    response->out_base_address = reinterpret_cast<uintptr_t>(Nt::g_Fns.pPsGetProcessSectionBaseAddress(target_process.get()));
    return STATUS_SUCCESS;
}