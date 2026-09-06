#pragma once
#include <ntddk.h>
#include <cstdint>
#include <guiddef.h>

#ifndef CTL_CODE
#define CTL_CODE(DeviceType, Function, Method, Access) (                 \
    ((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method) \
)
#endif

#ifndef FILE_DEVICE_UNKNOWN
#define FILE_DEVICE_UNKNOWN 0x00000022
#endif

#ifndef METHOD_BUFFERED
#define METHOD_BUFFERED 0
#endif

#ifndef FILE_ANY_ACCESS
#define FILE_ANY_ACCESS 0
#endif

#define IOCTL_RKSTAR64_HANDSHAKE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_RKSTAR64_REQUEST \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

#ifndef GUID_DEVINTERFACE_RKSTAR64_DEFINED
#define GUID_DEVINTERFACE_RKSTAR64_DEFINED
DEFINE_GUID(GUID_DEVINTERFACE_RKSTAR64,
    0x425240a, 0x989c, 0x415b, 0x8a, 0x76, 0x44, 0x2c, 0x41, 0x55, 0xc6, 0x44);
#endif

namespace comms
{

    enum class RequestType : uint64_t {
        None = 0,
        Read,
        Write,
        GetBaseAddress
    };

    struct alignas(8) RequestData {
        RequestType type;
        uint32_t process_id;
        uint32_t padding;
        uintptr_t address;
        uintptr_t buffer;
        size_t size;
        uintptr_t out_base_address;
    };

    constexpr size_t GCM_NONCE_SIZE = 12;
    constexpr size_t GCM_TAG_SIZE = 16;

    struct CommunicationPacket {
        uint64_t session_key_iv;
        unsigned char data[sizeof(RequestData) + GCM_TAG_SIZE];
    };

    constexpr uint64_t PACKET_MAGIC = 0xDEADBEEFCAFED0D0;
    struct MaskedPacket
    {
        uint64_t magic;
        CommunicationPacket packet;
    };
}