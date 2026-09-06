#include "Crypto.h"
#include <stdexcept>
#include <cstring>
#include <algorithm>
#include <random>

#pragma comment(lib, "bcrypt.lib")

CryptoProvider::CryptoProvider() : m_alg_handle(nullptr), m_initialized(false)
{
    m_initialized = Initialize();
}

CryptoProvider::~CryptoProvider()
{
    Cleanup();
}

bool CryptoProvider::Initialize()
{
    NTSTATUS status = BCryptOpenAlgorithmProvider(&m_alg_handle, BCRYPT_AES_ALGORITHM, MS_PRIMITIVE_PROVIDER, 0);
    if (!BCRYPT_SUCCESS(status))
    {
        return false;
    }

    status = BCryptSetProperty(m_alg_handle, BCRYPT_CHAINING_MODE,
                              (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (!BCRYPT_SUCCESS(status))
    {
        Cleanup();
        return false;
    }

    return true;
}

bool CryptoProvider::Encrypt(uint64_t key, uint64_t iv, const uint8_t *plaintext, size_t plaintext_size,
                           uint8_t *ciphertext, size_t ciphertext_size)
{
    if (!m_initialized || !plaintext || !ciphertext) return false;

    if (ciphertext_size < (plaintext_size + comms::GCM_TAG_SIZE))
    {
        return false;
    }

    BCRYPT_KEY_HANDLE key_handle = nullptr;

    uint8_t aes_key[16]{};

    memcpy(aes_key, &key, sizeof(key));
    memcpy(aes_key + 8, &key, sizeof(key));

    NTSTATUS status = BCryptGenerateSymmetricKey(m_alg_handle, &key_handle, nullptr, 0,
                                                aes_key, sizeof(aes_key), 0);
    if (!BCRYPT_SUCCESS(status))
    {
        return false;
    }

    UCHAR nonce[comms::GCM_NONCE_SIZE];
    RtlCopyMemory(nonce, &iv, sizeof(iv));
    if constexpr (sizeof(nonce) > sizeof(iv))
    {
        RtlZeroMemory(nonce + sizeof(iv), sizeof(nonce) - sizeof(iv));
    }

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth_info;
    BCRYPT_INIT_AUTH_MODE_INFO(auth_info);
    auth_info.pbNonce = nonce;
    auth_info.cbNonce = sizeof(nonce);
    auth_info.pbTag = ciphertext + plaintext_size;
    auth_info.cbTag = comms::GCM_TAG_SIZE;

    ULONG bytes_done = 0;
    status = BCryptEncrypt(key_handle, (PUCHAR)plaintext, (ULONG)plaintext_size,
                          &auth_info, nullptr, 0, ciphertext, (ULONG)plaintext_size,
                          &bytes_done, 0);

    BCryptDestroyKey(key_handle);
    return BCRYPT_SUCCESS(status);
}

bool CryptoProvider::Decrypt(uint64_t key, uint64_t iv, const uint8_t *ciphertext, size_t ciphertext_size,
                           uint8_t *plaintext, size_t plaintext_size)
{
    if (!m_initialized || !plaintext || !ciphertext) return false;

    if (ciphertext_size < (plaintext_size + comms::GCM_TAG_SIZE))
    {
        return false;
    }

    BCRYPT_KEY_HANDLE key_handle = nullptr;

    uint8_t aes_key[16]{};

    memcpy(aes_key, &key, sizeof(key));
    memcpy(aes_key + 8, &key, sizeof(key));

    NTSTATUS status = BCryptGenerateSymmetricKey(m_alg_handle, &key_handle, nullptr, 0,
                                                aes_key, sizeof(aes_key), 0);
    if (!BCRYPT_SUCCESS(status))
    {
        return false;
    }

    UCHAR nonce[comms::GCM_NONCE_SIZE];
    RtlCopyMemory(nonce, &iv, sizeof(iv));
    if constexpr (sizeof(nonce) > sizeof(iv))
    {
        RtlZeroMemory(nonce + sizeof(iv), sizeof(nonce) - sizeof(iv));
    }

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth_info;
    BCRYPT_INIT_AUTH_MODE_INFO(auth_info);
    auth_info.pbNonce = nonce;
    auth_info.cbNonce = sizeof(nonce);
    auth_info.pbTag = (PUCHAR)ciphertext + plaintext_size;
    auth_info.cbTag = comms::GCM_TAG_SIZE;

    ULONG bytes_done = 0;
    status = BCryptDecrypt(key_handle, (PUCHAR)ciphertext, (ULONG)plaintext_size,
                          &auth_info, nullptr, 0, plaintext, (ULONG)plaintext_size,
                          &bytes_done, 0);

    BCryptDestroyKey(key_handle);
    return BCRYPT_SUCCESS(status);
}

void CryptoProvider::Cleanup()
{
    if (m_alg_handle)
    {
        BCryptCloseAlgorithmProvider(m_alg_handle, 0);
        m_alg_handle = nullptr;
    }
    m_initialized = false;
}