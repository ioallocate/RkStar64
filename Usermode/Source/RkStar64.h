#pragma once
#include <windows.h>
#include <memory>
#include <vector>
#include <string>
#include "Shared.h"
#include "Crypto.h"

class RkStar64
{
public:
    RkStar64();
    ~RkStar64();

    RkStar64(RkStar64 &&other) noexcept;
    RkStar64 &operator=(RkStar64 &&other) noexcept;

    RkStar64(const RkStar64 &) = delete;
    RkStar64 &operator=(const RkStar64 &) = delete;

    bool Initialize();
    bool IsInitialized() const;

    bool ReadMemory(uint32_t process_id, uintptr_t address, void *buffer, size_t size);
    bool WriteMemory(uint32_t process_id, uintptr_t address, const void *buffer, size_t size);
    uintptr_t GetBaseAddress(uint32_t process_id);

private:
    bool SendRequest(const comms::RequestData &request, comms::RequestData &response);
    bool Handshake();
    void Cleanup();

    bool TryInitialize();

    HANDLE m_device_handle;
    uint64_t m_session_key;
    std::unique_ptr<CryptoProvider> m_crypto;
    bool m_initialized;
};