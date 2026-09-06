#include "Entry.hpp"
#include "Utils.hpp"
#include "../Shared.h"
#include "Comms.h"
#include <initguid.h> 
#include "Nt.hpp"

DEFINE_GUID(GUID_DEVINTERFACE_RKSTAR64,
    0x425240a, 0x989c, 0x415b, 0x8a, 0x76, 0x44, 0x2c, 0x41, 0x55, 0xc6, 0x44);

extern "C" NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    PAGED_CODE();

    DbgPrint("[RkStar64 Telemetry] DriverEntry called.\n");

    NTSTATUS status = Utils::ResolveDynamicImports();
    if (!NT_SUCCESS(status)) {
        DbgPrint("[RkStar64 Telemetry] Failed to resolve imports.\n");
        return status;
    }

    DbgPrint("[RkStar64 Telemetry] Imports Resolved.\n");

    WDF_DRIVER_CONFIG config;
    WDF_DRIVER_CONFIG_INIT(&config, EvtDriverDeviceAdd);

    status = WdfDriverCreate(DriverObject,
                            RegistryPath,
                            WDF_NO_OBJECT_ATTRIBUTES,
                            &config, WDF_NO_HANDLE);

    return status;
}

NTSTATUS EvtDriverDeviceAdd(
    _In_ WDFDRIVER Driver,
    _Inout_ PWDFDEVICE_INIT DeviceInit
)
{
    UNREFERENCED_PARAMETER(Driver);
    PAGED_CODE();

    NTSTATUS status;
    WDFDEVICE device;

    WDF_OBJECT_ATTRIBUTES deviceAttributes;
    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&deviceAttributes, DEVICE_CONTEXT);
    deviceAttributes.EvtCleanupCallback = EvtDeviceContextCleanup;

    status = WdfDeviceCreate(&DeviceInit, &deviceAttributes, &device);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    
    PDEVICE_CONTEXT deviceContext = GetDeviceContext(device);
    RtlZeroMemory(deviceContext, sizeof(DEVICE_CONTEXT));
    deviceContext->Device = device;
    deviceContext->PoolTag = Utils::Cryptography::GenerateRandomTag();

    DbgPrint("[RkStar64 Telemetry] Configured Device.\n");

    WDF_IO_QUEUE_CONFIG queueConfig;
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueConfig, WdfIoQueueDispatchParallel);
    queueConfig.EvtIoDeviceControl = EvtIoDeviceControl;

    WDFQUEUE queue;
    status = WdfIoQueueCreate(device, &queueConfig, WDF_NO_OBJECT_ATTRIBUTES, &queue);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = WdfDeviceCreateDeviceInterface(device, &GUID_DEVINTERFACE_RKSTAR64, NULL);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = Utils::Cryptography::Initialize(&deviceContext->AesGcmAlgHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[RkStar64 Telemetry] failure while setting up AesGcmAlgHandle buffer.\n");
        return status;
    }
    DbgPrint("[RkStar64 Telemetry] AesGcmAlgHandle Buffer has been Initialized.\n");

    DbgPrint("[RkStar64 Telemetry] Detouring to EvtDeviceIoControl\n");
    return STATUS_SUCCESS;
}

#include <hidclass.h>

VOID EvtIoDeviceControl(
    _In_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength,
    _In_ size_t InputBufferLength,
    _In_ ULONG IoControlCode
)
{
    UNREFERENCED_PARAMETER(Queue);

    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;

    if (IoControlCode == IOCTL_RKSTAR64_HANDSHAKE)
    {
            if (InputBufferLength < sizeof(uint64_t) ||
                OutputBufferLength < sizeof(uint64_t))
            {
                status = STATUS_BUFFER_TOO_SMALL;
                return;
            }

            uint64_t *magic = nullptr;

            status = WdfRequestRetrieveInputBuffer(
                Request,
                sizeof(uint64_t),
                reinterpret_cast<PVOID *>(&magic),
                nullptr
            );

            if (!NT_SUCCESS(status))
                return;

            if (*magic != comms::PACKET_MAGIC)
            {
                status = STATUS_INVALID_PARAMETER;
                return;
            }

            status = Comms::HandleHandshake(
                Request,
                InputBufferLength,
                OutputBufferLength
            );

    }
    else if (IoControlCode == IOCTL_RKSTAR64_REQUEST)
    {

            comms::MaskedPacket *packet = nullptr;

            status = WdfRequestRetrieveInputBuffer(
                Request,
                sizeof(comms::MaskedPacket),
                reinterpret_cast<PVOID *>(&packet),
                nullptr
            );

            if (!NT_SUCCESS(status))
                return;

            if (packet->magic != comms::PACKET_MAGIC)
            {
                status = STATUS_INVALID_PARAMETER;
                return;
            }

            status = Comms::HandleRequest(
                Request,
                InputBufferLength,
                OutputBufferLength
            );
    }

    if (status != STATUS_PENDING)
    {
        WdfRequestComplete(Request, status);
    }
}

VOID EvtDeviceContextCleanup(
    _In_ WDFOBJECT DeviceObject
)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    PAGED_CODE();
}

VOID EvtDriverContextCleanup(
    _In_ WDFOBJECT DriverObject
)
{
    UNREFERENCED_PARAMETER(DriverObject);
    PAGED_CODE();
}

VOID EvtDriverUnload(
    _In_ WDFDRIVER DriverObject
)
{
    UNREFERENCED_PARAMETER(DriverObject);
    PAGED_CODE();
}