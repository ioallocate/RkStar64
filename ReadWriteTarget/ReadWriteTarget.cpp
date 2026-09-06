#include <windows.h>
#include <iostream>

#include <Windows.h>
#include <cstdint>
#include <iomanip>
#include <iostream>

int main()
{
    volatile uint64_t testValue = 0x1122334455667788ULL;

    SetConsoleTitle(L"RkStar64 Hardware Uility Testing Application");

    std::cout << "PID: "
        << GetCurrentProcessId()
        << "\n";

    std::cout << "Address: 0x"
        << std::hex
        << reinterpret_cast<uintptr_t>(&testValue)
        << std::dec
        << "\n\n";

    std::cout << "Initial value: 0x"
        << std::hex
        << testValue
        << std::dec
        << "\n";

    std::cout << "Expected 8-byte read:\n";
    std::cout << "88 77 66 55 44 33 22 11\n\n";

    std::cout << "Suggested test write value:\n";
    std::cout << "0xAABBCCDDEEFF0011\n\n";

    std::cout << "After writing that value, expected read:\n";
    std::cout << "11 00 FF EE DD CC BB AA\n\n";

    std::cout << "Press ENTER after performing the write...\n";
    std::cin.get();

    std::cout << "\nCurrent value: 0x"
        << std::hex
        << testValue
        << std::dec
        << "\n";

    std::cout << "\nPress ENTER to exit...\n";
    std::cin.get();

    return 0;
}