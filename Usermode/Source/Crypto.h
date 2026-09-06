#pragma once
#include <windows.h>
#include <bcrypt.h>
#include <vector>
#include <memory>
#include "Shared.h"

class CryptoProvider
{
public:
    CryptoProvider();
    ~CryptoProvider();

    bool Encrypt(uint64_t key, uint64_t iv, const uint8_t *plaintext, size_t plaintext_size, uint8_t *ciphertext, size_t ciphertext_size);
    bool Decrypt(uint64_t key, uint64_t iv, const uint8_t *ciphertext, size_t ciphertext_size, uint8_t *plaintext, size_t plaintext_size);

private:
    BCRYPT_ALG_HANDLE m_alg_handle;
    bool m_initialized;

    bool Initialize();
    void Cleanup();
};