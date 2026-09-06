#pragma once
#include "nt.hpp"
#include <cstdint>

namespace Utils {

    class ProcessGuard
    {
    public:
        explicit ProcessGuard(PEPROCESS process = nullptr) : m_process(process) {}
        ~ProcessGuard() {
            if (m_process) {
                ObDereferenceObject(m_process);
            }
        }

        ProcessGuard(const ProcessGuard&) = delete;
        ProcessGuard& operator=(const ProcessGuard&) = delete;

        ProcessGuard(ProcessGuard&& other) noexcept : m_process(other.m_process) {
            other.m_process = nullptr;
        }
        ProcessGuard& operator=(ProcessGuard&& other) noexcept {
            if (this != &other) {
                if (m_process) ObDereferenceObject(m_process);
                m_process = other.m_process;
                other.m_process = nullptr;
            }
            return *this;
        }

        PEPROCESS get() const { return m_process; }
        operator bool() const { return m_process != nullptr; }
        PEPROCESS release() {
            PEPROCESS temp = m_process;
            m_process = nullptr;
            return temp;
        }

    private:
        PEPROCESS m_process;
    };

    namespace Cryptography {
        ULONG GenerateRandomTag();
        NTSTATUS GenerateRandomNumber(_Out_writes_bytes_(size) PVOID buffer, _In_ ULONG size);
        NTSTATUS Initialize(_Out_ BCRYPT_ALG_HANDLE* alg_handle);
        VOID Cleanup(_In_ BCRYPT_ALG_HANDLE alg_handle);

        NTSTATUS Encrypt(
            _In_ BCRYPT_ALG_HANDLE alg_handle,
            _In_ uint64_t key,
            _In_ uint64_t iv,
            _In_reads_bytes_(plain_text_size) PUCHAR plain_text,
            _In_ ULONG plain_text_size,
            _Out_writes_bytes_(cipher_text_size) PUCHAR cipher_text,
            _In_ ULONG cipher_text_size
        );

        NTSTATUS Decrypt(
            _In_ BCRYPT_ALG_HANDLE alg_handle,
            _In_ uint64_t key,
            _In_ uint64_t iv,
            _In_reads_bytes_(cipher_text_size) PUCHAR cipher_text,
            _In_ ULONG cipher_text_size,
            _Out_writes_bytes_(plain_text_size) PUCHAR plain_text,
            _In_ ULONG plain_text_size
        );

    }

	NTSTATUS ResolveDynamicImports();
}