#include <windows.h>
#include <winternl.h>
#include <initguid.h> 
#include <tlhelp32.h>
#include <psapi.h>
#include <iostream>
#include <memory>
#include <vector>
#include <string>
#include <format>
#include <chrono>
#include <thread>
#include <filesystem>
#include <SetupAPI.h>
#include <newdev.h>
#include "RkStar64.h"
#include <sstream>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "Setupapi.lib")
#pragma comment(lib, "Newdev.lib")

static constexpr wchar_t HardwareId[] = L"ROOT\\RkStar64";
static constexpr wchar_t InfFileName[] = L"RkStar64.inf";

static std::string GetTimestamp()
{
    using namespace std::chrono;
    auto now = system_clock::now();
    auto itt = system_clock::to_time_t(now);
    std::tm tm;
#ifdef _WIN32
    localtime_s(&tm, &itt);
#else
    localtime_r(&itt, &tm);
#endif
    char buf[64];
    std::snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d",
                  tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                  tm.tm_hour, tm.tm_min, tm.tm_sec);
    return std::string(buf);
}

static void LogInfo(const std::string &msg)
{
    std::cout << "[" << GetTimestamp() << "] [INFO] " << msg << "\n";
}
static void LogWarn(const std::string &msg)
{
    std::cout << "[" << GetTimestamp() << "] [WARN] " << msg << "\n";
}
static void LogError(const std::string &msg)
{
    std::cerr << "[" << GetTimestamp() << "] [ERROR] " << msg << "\n";
}

static std::string ToUtf8(const std::wstring &w)
{
    if (w.empty()) return {};
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), NULL, 0, NULL, NULL);
    if (size_needed <= 0) return {};
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}

static bool IsProcessElevated()
{
    BOOL isElev = FALSE;
    HANDLE token = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
    {
        TOKEN_ELEVATION elevation = {};
        DWORD retLen = 0;
        if (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &retLen))
        {
            isElev = elevation.TokenIsElevated;
        }
        CloseHandle(token);
    }
    return isElev == TRUE;
}

void PrintError(const std::string &context, DWORD errorCode)
{
    char *msgBuf = nullptr;
    DWORD msgLen = FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        errorCode,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPSTR)&msgBuf,
        0, NULL);

    if (msgLen > 0)
    {
        std::string message(msgBuf, msgBuf + msgLen);
        while (!message.empty() && (message.back() == '\r' || message.back() == '\n'))
        {
            message.pop_back();
        }
        std::ostringstream oss; oss << context << " failed. Win32 Error " << errorCode << ": " << message;
        LogError(oss.str());
        LocalFree(msgBuf);
    }
    else
    {
        std::ostringstream oss; oss << context << " failed. Win32 error code: " << errorCode;
        LogError(oss.str());
    }
}

void PrintNtError(const std::string &context, NTSTATUS status)
{
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    char *msgBuf = nullptr;
    DWORD msgLen = FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_IGNORE_INSERTS,
        ntdll,
        status,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPSTR)&msgBuf,
        0, NULL);

    if (msgLen > 0)
    {
        std::string message(msgBuf, msgBuf + msgLen);
        while (!message.empty() && (message.back() == '\r' || message.back() == '\n'))
        {
            message.pop_back();
        }
        std::ostringstream oss; oss << context << " failed. NTSTATUS 0x" << std::hex << (ULONG)status << std::dec << ": " << message;
        LogError(oss.str());
        LocalFree(msgBuf);
    }
    else
    {
        std::ostringstream oss; oss << context << " failed. NTSTATUS: 0x" << std::hex << (ULONG)status;
        LogError(oss.str());
    }
}

static bool CreateRootDevice()
{
    static const GUID SystemClassGuid =
    {
        0x4d36e97d, 0xe325, 0x11ce,
        { 0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18 }
    };

    HDEVINFO deviceInfoSet =
        SetupDiCreateDeviceInfoList(&SystemClassGuid, nullptr);

    if (deviceInfoSet == INVALID_HANDLE_VALUE)
    {
        PrintError("SetupDiCreateDeviceInfoList", GetLastError());
        return false;
    }

    SP_DEVINFO_DATA deviceInfo{};
    deviceInfo.cbSize = sizeof(deviceInfo);

    if (!SetupDiCreateDeviceInfoW(
        deviceInfoSet,
        L"RkStar64",
        &SystemClassGuid,
        L"RkStar64 Device",
        nullptr,
        DICD_GENERATE_ID,
        &deviceInfo))
    {
        PrintError("SetupDiCreateDeviceInfoW", GetLastError());
        SetupDiDestroyDeviceInfoList(deviceInfoSet);
        return false;
    }

    const wchar_t hardwareIds[] = L"ROOT\\RkStar64\0";

    if (!SetupDiSetDeviceRegistryPropertyW(
        deviceInfoSet,
        &deviceInfo,
        SPDRP_HARDWAREID,
        reinterpret_cast<const BYTE *>(hardwareIds),
        sizeof(hardwareIds)))
    {
        PrintError(
            "dgb1qn67zwq3w3x666vknfp5ynecqzzlglxsqmvrnva",
            GetLastError());

        SetupDiDestroyDeviceInfoList(deviceInfoSet);
        return false;
    }

    if (!SetupDiCallClassInstaller(
        DIF_REGISTERDEVICE,
        deviceInfoSet,
        &deviceInfo))
    {
        PrintError(
            "SetupDiCallClassInstaller(DIF_REGISTERDEVICE)",
            GetLastError());

        SetupDiDestroyDeviceInfoList(deviceInfoSet);
        return false;
    }

    SetupDiDestroyDeviceInfoList(deviceInfoSet);

    LogInfo("Created ROOT\\RkStar64 device instance.");
    return true;
}

bool LoadDriver()
{
    if (!IsProcessElevated())
    {
        LogError("Driver installation requires an elevated administrator process.");
        return false;
    }

    wchar_t exePathBuf[MAX_PATH]{};

    DWORD len = GetModuleFileNameW(
        nullptr,
        exePathBuf,
        static_cast<DWORD>(_countof(exePathBuf)));

    if (len == 0 || len >= _countof(exePathBuf))
    {
        PrintError("GetModuleFileNameW", GetLastError());
        return false;
    }

    const std::filesystem::path exeDir =
        std::filesystem::path(exePathBuf).parent_path();

    std::filesystem::path infPath = exeDir / InfFileName;

    if (!std::filesystem::exists(infPath))
    {
        LogError(
            std::string("INF not found: ") +
            ToUtf8(infPath.wstring()));

        return false;
    }

    LogInfo(
        std::string("Installing driver from: ") +
        ToUtf8(infPath.wstring()));

    BOOL rebootRequired = FALSE;

    BOOL result = UpdateDriverForPlugAndPlayDevicesW(
    nullptr,
    HardwareId,
    infPath.c_str(),
    INSTALLFLAG_FORCE,
    &rebootRequired);

    if (!result)
    {
        DWORD err = GetLastError();

        if (err == ERROR_NO_SUCH_DEVINST)
        {
            LogInfo("ROOT\\RkStar64 does not exist; creating device instance.");

            if (!CreateRootDevice())
                return false;

            rebootRequired = FALSE;

            result = UpdateDriverForPlugAndPlayDevicesW(
                nullptr,
                HardwareId,
                infPath.c_str(),
                INSTALLFLAG_FORCE,
                &rebootRequired);

            if (!result)
            {
                PrintError(
                    "UpdateDriverForPlugAndPlayDevicesW after CreateRootDevice",
                    GetLastError());

                return false;
            }
        }
        else
        {
            PrintError(
                "UpdateDriverForPlugAndPlayDevicesW",
                err);

            return false;
        }
    }

    LogInfo("RkStar64 driver installed successfully.");

    if (rebootRequired)
        LogWarn("Windows reports that a reboot is required.");

    return true;
}

bool UnloadDriver()
{
    if (!IsProcessElevated())
    {
        LogError("Driver removal requires an elevated administrator process.");
        return false;
    }

    HDEVINFO deviceInfo = SetupDiGetClassDevsW(
        nullptr,
        nullptr,
        nullptr,
        DIGCF_ALLCLASSES | DIGCF_PRESENT);

    if (deviceInfo == INVALID_HANDLE_VALUE)
    {
        PrintError("SetupDiGetClassDevsW", GetLastError());
        return false;
    }

    SP_DEVINFO_DATA deviceData{};
    deviceData.cbSize = sizeof(deviceData);

    bool found = false;
    bool success = false;

    for (DWORD index = 0;
         SetupDiEnumDeviceInfo(deviceInfo, index, &deviceData);
         ++index)
    {
        wchar_t hardwareIds[4096]{};

        DWORD requiredSize = 0;
        DWORD regType = 0;

        if (!SetupDiGetDeviceRegistryPropertyW(
            deviceInfo,
            &deviceData,
            SPDRP_HARDWAREID,
            &regType,
            reinterpret_cast<PBYTE>(hardwareIds),
            sizeof(hardwareIds),
            &requiredSize))
        {
            continue;
        }

        const wchar_t *current = hardwareIds;

        while (*current)
        {
            if (_wcsicmp(current, HardwareId) == 0)
            {
                found = true;

                LogInfo("Found ROOT\\RkStar64 device instance.");

                BOOL rebootRequired = FALSE;

                if (!DiUninstallDevice(
                    nullptr,
                    deviceInfo,
                    &deviceData,
                    0,
                    &rebootRequired))
                {
                    PrintError(
                        "DiUninstallDevice",
                        GetLastError());

                    SetupDiDestroyDeviceInfoList(deviceInfo);
                    return false;
                }

                LogInfo("RkStar64 device removed.");

                if (rebootRequired)
                    LogWarn("Windows reports that a reboot is required.");

                success = true;
                break;
            }

            current += wcslen(current) + 1;
        }

        if (success)
            break;
    }

    if (!found)
    {
        LogWarn(
            "ROOT\\RkStar64 was not found. "
            "The driver may already be unloaded.");
    }

    SetupDiDestroyDeviceInfoList(deviceInfo);

    return success || !found;
}

void PrintUsage()
{
    std::cout << "\RkStar64 Client Integration Test Application\n";
    std::cout << "Usage:\n";
    std::cout << "  l. Load driver using Device Manager\n";
    std::cout << "  u. Unload driver using Device Manager\n";
    std::cout << "  1. Test connection\n";
    std::cout << "  2. Get base address of process\n";
    std::cout << "  3. Read memory\n";
    std::cout << "  4. Write memory\n";
    std::cout << "  q. Quit\n";
}

uint32_t GetProcessIdByName(const std::wstring &processName)
{
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        return 0;
    }

    if (Process32FirstW(hSnapshot, &pe32))
    {
        do
        {
            if (_wcsicmp(pe32.szExeFile, processName.c_str()) == 0)
            {
                CloseHandle(hSnapshot);
                return pe32.th32ProcessID;
            }
        }
        while (Process32NextW(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return 0;
}

int main()
{
    try
    {
        std::cout << "[+] Initializing RkStar64 Client Integration...\n";

        RkStar64 client;
        client.Initialize();
        if (!client.IsInitialized())
        {
            std::cout << "[-] Client could not connect to driver (this is expected if driver is not loaded).\n";
            std::cout << "[!] Use option 'l' to load the driver first.\n";
        }
        else
        {
            std::cout << "[+] RkStar64 Client Integration initialized successfully!\n";
        }

        while (true)
        {
            PrintUsage();
            std::cout << "\nEnter choice: ";
            char choice;
            std::cin >> choice;

            switch (choice)
            {
                case 'l':
                case 'L':
                {
                    if (LoadDriver())
                    {
                        std::cout << "[+] Driver load command sent. Re-initializing client...\n";
                        std::this_thread::sleep_for(std::chrono::seconds(2));

                        client = RkStar64();

                        if (!client.Initialize())
                        {
                            std::cerr << "[-] Failed to initialize client after loading driver.\n";
                        }
                    }
                    break;
                }
                case 'u':
                case 'U':
                {
                    if (UnloadDriver())
                    {
                        std::cout << "[+] Driver unload command sent.\n";
                        client = RkStar64();
                    }
                    break;
                }
                case '1':
                {
                    if (client.IsInitialized())
                    {
                        std::cout << "[+] Connection test successful!\n";
                    }
                    else
                    {
                        std::cout << "[-] Client is not connected. Load the driver first.\n";
                    }
                    break;
                }

                case '2':
                {
                    if (!client.IsInitialized())
                    {
                        std::cout << "[-] Client not connected.\n"; break;
                    }
                    std::cout << "Enter process name (e.g., notepad.exe): ";
                    std::string processName;
                    std::cin >> processName;

                    std::wstring wProcessName(processName.begin(), processName.end());
                    uint32_t pid = GetProcessIdByName(wProcessName);

                    if (pid)
                    {
                        uintptr_t base = client.GetBaseAddress(pid);
                        if (base)
                        {
                            std::cout << std::format("[+] Base address of {}: 0x{:X}\n", processName, base);
                        }
                        else
                        {
                            std::cout << "[-] Failed to get base address\n";
                        }
                    }
                    else
                    {
                        std::cout << "[-] Process not found\n";
                    }
                    break;
                }

                case '3':
                {
                    if (!client.IsInitialized())
                    {
                        std::cout << "[-] Client not connected.\n"; break;
                    }
                    std::cout << "Enter process ID: ";
                    uint32_t pid;
                    std::cin >> pid;

                    std::cout << "Enter address (hex): ";
                    uintptr_t address;
                    std::cin >> std::hex >> address;

                    std::cout << "Enter size: ";
                    size_t size;
                    std::cin >> std::dec >> size;

                    if (size > 0 && size < 1024)
                    {
                        std::vector<uint8_t> buffer(size);
                        if (client.ReadMemory(pid, address, buffer.data(), size))
                        {
                            std::cout << "[+] Read successful! Data:\n";
                            for (size_t i = 0; i < size && i < 32; ++i)
                            {
                                std::cout << std::format("{:02X} ", buffer[i]);
                                if ((i + 1) % 16 == 0) std::cout << "\n";
                            }
                            std::cout << "\n";
                        }
                        else
                        {
                            std::cout << "[-] Read failed\n";
                        }
                    }
                    else
                    {
                        std::cout << "[-] Invalid size\n";
                    }
                    break;
                }

                case '4':
                {
                    if (!client.IsInitialized())
                    {
                        std::cout << "[-] Client not connected.\n";
                        break;
                    }

                    std::cout << "Enter process ID: ";
                    uint32_t pid;
                    std::cin >> pid;

                    std::cout << "Enter address (hex): ";
                    uintptr_t address;
                    std::cin >> std::hex >> address;

                    std::cout << "Enter 64-bit value (hex): ";
                    uint64_t value;
                    std::cin >> std::hex >> value;
                    std::cin >> std::dec;

                    if (client.WriteMemory(
                        pid,
                        address,
                        &value,
                        sizeof(value)))
                    {
                        std::cout << std::format(
                            "[+] Write successful: 0x{:016X}\n",
                            value);
                    }
                    else
                    {
                        std::cout << "[-] Write failed\n";
                    }

                    break;
                }

                case 'q':
                case 'Q':
                    return 0;

                default:
                    std::cout << "[-] Invalid choice\n";
                    break;
            }
        }

    }
    catch (const std::exception &e)
    {
        std::cerr << "[-] Exception: " << e.what() << "\n";
        return 1;
    }

    return 0;
}