#include "Utils.hpp"
#include "../Shared.h"

#pragma warning(push)
#pragma warning(disable:4191)
NTSTATUS Utils::ResolveDynamicImports()
{
    PAGED_CODE();

    UNICODE_STRING name;

    RtlInitUnicodeString(&name, (L"PsLookupProcessByProcessId"));
    Nt::g_Fns.pPsLookupProcessByProcessId = (decltype(Nt::g_Fns.pPsLookupProcessByProcessId))MmGetSystemRoutineAddress(&name);
    if (!Nt::g_Fns.pPsLookupProcessByProcessId) return STATUS_NOT_FOUND;

    RtlInitUnicodeString(&name, (L"PsGetProcessSectionBaseAddress"));
    Nt::g_Fns.pPsGetProcessSectionBaseAddress = (decltype(Nt::g_Fns.pPsGetProcessSectionBaseAddress))MmGetSystemRoutineAddress(&name);
    if (!Nt::g_Fns.pPsGetProcessSectionBaseAddress) return STATUS_NOT_FOUND;

    RtlInitUnicodeString(&name, (L"MmCopyVirtualMemory"));
    Nt::g_Fns.pMmCopyVirtualMemory = (decltype(Nt::g_Fns.pMmCopyVirtualMemory))MmGetSystemRoutineAddress(&name);
    if (!Nt::g_Fns.pMmCopyVirtualMemory) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }
    return STATUS_SUCCESS;
}
#pragma warning(pop)

NTSTATUS Utils::Cryptography::GenerateRandomNumber(_Out_writes_bytes_(size) PVOID buffer, _In_ ULONG size)
{
    return BCryptGenRandom(nullptr, static_cast<PUCHAR>(buffer), size, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
}

ULONG Utils::Cryptography::GenerateRandomTag()
{
    ULONG tag = 0;
    GenerateRandomNumber(&tag, sizeof(tag));

    char* tag_chars = reinterpret_cast<char*>(&tag);
    for (int i = 0; i < 4; ++i) {
        if (tag_chars[i] < 32 || tag_chars[i] > 126) {
            tag_chars[i] = 'A' + (tag_chars[i] % 26);
        }
    }

    if (tag == 0) {
        tag = 'dflt';
    }
    return tag;
}

NTSTATUS Utils::Cryptography::Encrypt(
    _In_ BCRYPT_ALG_HANDLE alg_handle,
    _In_ uint64_t key,
    _In_ uint64_t iv,
    _In_reads_bytes_(plain_text_size) PUCHAR plain_text,
    _In_ ULONG plain_text_size,
    _Out_writes_bytes_(cipher_text_size) PUCHAR cipher_text,
    _In_ ULONG cipher_text_size
)
{
    if (cipher_text_size < (plain_text_size + comms::GCM_TAG_SIZE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    NTSTATUS status;
    BCRYPT_KEY_HANDLE key_handle = nullptr;

    uint8_t aes_key[16]{};

    memcpy(aes_key, &key, sizeof(key));
    memcpy(aes_key + 8, &key, sizeof(key));

    status = BCryptGenerateSymmetricKey(alg_handle, &key_handle, nullptr, 0, aes_key, sizeof(aes_key), 0);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    UCHAR nonce[comms::GCM_NONCE_SIZE];
    RtlCopyMemory(nonce, &iv, sizeof(iv));
    if constexpr (sizeof(nonce) > sizeof(iv)) {
        RtlZeroMemory(nonce + sizeof(iv), sizeof(nonce) - sizeof(iv));
    }

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth_info;
    BCRYPT_INIT_AUTH_MODE_INFO(auth_info);
    auth_info.pbNonce = nonce;
    auth_info.cbNonce = sizeof(nonce);
    auth_info.pbTag = cipher_text + plain_text_size;
    auth_info.cbTag = comms::GCM_TAG_SIZE;

    ULONG bytes_encrypted = 0;
    status = BCryptEncrypt(key_handle, plain_text, plain_text_size, &auth_info, nullptr, 0, cipher_text, plain_text_size, &bytes_encrypted, 0);

    BCryptDestroyKey(key_handle);
    return status;
}

NTSTATUS Utils::Cryptography::Decrypt(
    _In_ BCRYPT_ALG_HANDLE alg_handle,
    _In_ uint64_t key,
    _In_ uint64_t iv,
    _In_reads_bytes_(cipher_text_size) PUCHAR cipher_text,
    _In_ ULONG cipher_text_size,
    _Out_writes_bytes_(plain_text_size) PUCHAR plain_text,
    _In_ ULONG plain_text_size
)
{
    if (!alg_handle || !cipher_text || !plain_text)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (cipher_text_size < (plain_text_size + comms::GCM_TAG_SIZE))
    {
        return STATUS_BUFFER_TOO_SMALL;
    }

    BCRYPT_KEY_HANDLE key_handle = nullptr;

    uint8_t aes_key[16]{};

    RtlCopyMemory(aes_key, &key, sizeof(key));
    RtlCopyMemory(aes_key + sizeof(key), &key, sizeof(key));

    NTSTATUS status = BCryptGenerateSymmetricKey(
        alg_handle,
        &key_handle,
        nullptr,
        0,
        aes_key,
        sizeof(aes_key),
        0
    );

    if (!NT_SUCCESS(status))
    {
        return status;
    }

    UCHAR nonce[comms::GCM_NONCE_SIZE]{};

    RtlCopyMemory(nonce, &iv, sizeof(iv));

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth_info;
    BCRYPT_INIT_AUTH_MODE_INFO(auth_info);

    auth_info.pbNonce = nonce;
    auth_info.cbNonce = sizeof(nonce);
    auth_info.pbTag = cipher_text + plain_text_size;
    auth_info.cbTag = comms::GCM_TAG_SIZE;

    ULONG bytes_decrypted = 0;

    status = BCryptDecrypt(
        key_handle,
        cipher_text,
        plain_text_size,
        &auth_info,
        nullptr,
        0,
        plain_text,
        plain_text_size,
        &bytes_decrypted,
        0
    );

    BCryptDestroyKey(key_handle);
    return status;
}

NTSTATUS Utils::Cryptography::Initialize(_Out_ BCRYPT_ALG_HANDLE* alg_handle)
{
    PAGED_CODE();

    NTSTATUS status = BCryptOpenAlgorithmProvider(alg_handle, BCRYPT_AES_ALGORITHM, MS_PRIMITIVE_PROVIDER, 0);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = BCryptSetProperty(*alg_handle, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (!NT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(*alg_handle, 0);
        *alg_handle = nullptr;
    }

    return status;
}

VOID Utils::Cryptography::Cleanup(_In_ BCRYPT_ALG_HANDLE alg_handle)
{
    PAGED_CODE();
    if (alg_handle) {
        BCryptCloseAlgorithmProvider(alg_handle, 0);
    }
}