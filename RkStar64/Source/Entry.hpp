#pragma once
#include "Nt.hpp"
#include <wdf.h>
#include <wdfrequest.h>
#include <wdmguid.h>

struct DEVICE_CONTEXT
{
    WDFDEVICE Device;
    BCRYPT_ALG_HANDLE AesGcmAlgHandle;
    volatile LONG64 SessionKey;
    ULONG PoolTag;
};
using PDEVICE_CONTEXT = DEVICE_CONTEXT*;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(DEVICE_CONTEXT, GetDeviceContext)

inline PDEVICE_CONTEXT GetDeviceContextFromRequest(WDFREQUEST Request)
{
    return GetDeviceContext(WdfIoQueueGetDevice(WdfRequestGetIoQueue(Request)));
}

extern "C" DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD EvtDriverDeviceAdd;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL EvtIoDeviceControl;
EVT_WDF_OBJECT_CONTEXT_CLEANUP EvtDeviceContextCleanup;
EVT_WDF_OBJECT_CONTEXT_CLEANUP EvtDriverContextCleanup;
EVT_WDF_DRIVER_UNLOAD EvtDriverUnload;