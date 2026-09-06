#include "RkStar64.h"
#include "Crypto.h"
#include <stdexcept>
#include <format>
#include <memory>
#include <thread>
#include <chrono>
#include <utility>
#include <windows.h>
#include <setupapi.h>
#include <hidsdi.h>
#include <cfgmgr32.h>
#include <iostream>

#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "hid.lib")
#pragma comment(lib, "cfgmgr32.lib")

#ifndef IOCTL_HID_GET_FEATURE
#define IOCTL_HID_GET_FEATURE 0xB0191
#endif

RkStar64::RkStar64()
    : m_device_handle(INVALID_HANDLE_VALUE)
    , m_session_key(0)
    , m_crypto(std::make_unique<CryptoProvider>())
    , m_initialized(false)
{}

RkStar64::~RkStar64()
{
    Cleanup();
}

RkStar64::RkStar64(RkStar64 &&other) noexcept
    : m_device_handle(other.m_device_handle)
    , m_session_key(other.m_session_key)
    , m_crypto(std::move(other.m_crypto))
    , m_initialized(other.m_initialized)
{
    other.m_device_handle = INVALID_HANDLE_VALUE;
    other.m_initialized = false;
    other.m_session_key = 0;
}

RkStar64 &RkStar64::operator=(RkStar64 &&other) noexcept
{
    if (this != &other)
    {
        Cleanup();

        m_device_handle = other.m_device_handle;
        m_session_key = other.m_session_key;
        m_crypto = std::move(other.m_crypto);
        m_initialized = other.m_initialized;

        other.m_device_handle = INVALID_HANDLE_VALUE;
        other.m_initialized = false;
        other.m_session_key = 0;
    }
    return *this;
}

bool RkStar64::Initialize()
{
    if (m_initialized) return true;

    for (int attempt = 0; attempt < 5; ++attempt)
    {
        if (attempt > 0)
        {
            std::this_thread::sleep_for(std::chrono::seconds(2));
        }

        if (TryInitialize())
        {
            m_initialized = true;
            return true;
        }
    }

    return false;
}

bool RkStar64::TryInitialize()
{
    GUID guid = GUID_DEVINTERFACE_RKSTAR64;
    HDEVINFO device_info = SetupDiGetClassDevs(&guid, nullptr, nullptr, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);

    if (device_info == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    SP_DEVICE_INTERFACE_DATA interface_data = {sizeof(SP_DEVICE_INTERFACE_DATA)};
    DWORD device_index = 0;
    bool device_found = false;

    while (SetupDiEnumDeviceInterfaces(device_info, nullptr, &guid, device_index, &interface_data))
    {
        DWORD required_size = 0;
        SetupDiGetDeviceInterfaceDetail(device_info, &interface_data, nullptr, 0, &required_size, nullptr);

        if (required_size > 0)
        {
            std::vector<BYTE> buffer(required_size);
            PSP_DEVICE_INTERFACE_DETAIL_DATA interface_detail = reinterpret_cast<PSP_DEVICE_INTERFACE_DETAIL_DATA>(buffer.data());
            interface_detail->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA);

            if (SetupDiGetDeviceInterfaceDetail(device_info, &interface_data, interface_detail, required_size, nullptr, nullptr))
            {
                m_device_handle = CreateFile(interface_detail->DevicePath,
                                            GENERIC_READ | GENERIC_WRITE,
                                            FILE_SHARE_READ | FILE_SHARE_WRITE,
                                            nullptr,
                                            OPEN_EXISTING,
                                            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
                                            nullptr);

                if (m_device_handle != INVALID_HANDLE_VALUE)
                {
                    if (Handshake())
                    {
                        device_found = true;
                        break;
                    }
                    CloseHandle(m_device_handle);
                    m_device_handle = INVALID_HANDLE_VALUE;
                }
            }
        }
        device_index++;
    }

    SetupDiDestroyDeviceInfoList(device_info);
    return device_found;
}

bool RkStar64::IsInitialized() const
{
    return m_initialized;
}

bool RkStar64::Handshake()
{
    if (m_device_handle == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    uint64_t magic = comms::PACKET_MAGIC;
    uint64_t response_key = 0;

    DWORD bytes_returned = 0;
    OVERLAPPED overlapped = {};

    BOOL success = DeviceIoControl(m_device_handle, IOCTL_RKSTAR64_HANDSHAKE,
                                  &magic, sizeof(magic),
                                  &response_key, sizeof(response_key),
                                  &bytes_returned, &overlapped);

    if (!success && GetLastError() == ERROR_IO_PENDING)
    {
        success = GetOverlappedResult(m_device_handle, &overlapped, &bytes_returned, TRUE);
    }

    if (!success || bytes_returned != sizeof(response_key))
    {
        return false;
    }

    m_session_key = response_key;
    return true;
}

bool RkStar64::SendRequest(const comms::RequestData &request, comms::RequestData &response)
{
    if (!m_initialized || m_device_handle == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    comms::MaskedPacket in_packet = {};
    comms::MaskedPacket out_packet = {};

    uint64_t iv = 0;
    NTSTATUS ntstatus = BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(&iv), sizeof(iv), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (!BCRYPT_SUCCESS(ntstatus))
    {
        iv = GetTickCount64();
    }

    if (!m_crypto->Encrypt(m_session_key,
        iv,
        reinterpret_cast<const uint8_t *>(&request),
        sizeof(request),
        in_packet.packet.data,
        sizeof(in_packet.packet.data)))
    {
        return false;
    }

    in_packet.magic = comms::PACKET_MAGIC;
    in_packet.packet.session_key_iv = iv;

    DWORD bytes_returned = 0;
    OVERLAPPED overlapped = {};

    BOOL success = DeviceIoControl(m_device_handle, IOCTL_RKSTAR64_REQUEST,
                                  &in_packet, sizeof(in_packet),
                                  &out_packet, sizeof(out_packet),
                                  &bytes_returned, &overlapped);

    if (!success && GetLastError() == ERROR_IO_PENDING)
    {
        success = GetOverlappedResult(m_device_handle, &overlapped, &bytes_returned, TRUE);
    }

    if (!success || bytes_returned != sizeof(out_packet) || out_packet.magic != comms::PACKET_MAGIC)
    {
        return false;
    }

    return m_crypto->Decrypt(m_session_key,
                            out_packet.packet.session_key_iv,
                            out_packet.packet.data,
                            sizeof(out_packet.packet.data),
                            reinterpret_cast<uint8_t *>(&response),
                            sizeof(response));
}

bool RkStar64::ReadMemory(uint32_t process_id, uintptr_t address, void *buffer, size_t size)
{
    comms::RequestData request = {};
    comms::RequestData response = {};

    request.type = comms::RequestType::Read;
    request.process_id = process_id;
    request.address = address;
    request.buffer = reinterpret_cast<uintptr_t>(buffer);
    request.size = size;

    if (!SendRequest(request, response))
    {
        return false;
    }

    return response.type == comms::RequestType::Read;
}

bool RkStar64::WriteMemory(uint32_t process_id, uintptr_t address, const void *buffer, size_t size)
{
    comms::RequestData request = {};
    comms::RequestData response = {};

    request.type = comms::RequestType::Write;
    request.process_id = process_id;
    request.address = address;
    request.buffer = reinterpret_cast<uintptr_t>(buffer);
    request.size = size;

    if (!SendRequest(request, response))
    {
        return false;
    }

    return response.type == comms::RequestType::Write;
}

uintptr_t RkStar64::GetBaseAddress(uint32_t process_id)
{
    comms::RequestData request = {};
    comms::RequestData response = {};

    request.type = comms::RequestType::GetBaseAddress;
    request.process_id = process_id;

    if (!SendRequest(request, response))
    {
        return 0;
    }

    return response.out_base_address;
}

void RkStar64::Cleanup()
{
    if (m_device_handle != INVALID_HANDLE_VALUE)
    {
        CloseHandle(m_device_handle);
        m_device_handle = INVALID_HANDLE_VALUE;
    }
    m_initialized = false;
}