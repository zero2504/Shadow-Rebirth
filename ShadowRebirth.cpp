// ShadowRebirth.cpp
#include "ShadowRebirth.h"
#include <tlhelp32.h>
#include <psapi.h>
#include <iostream>
#include <sstream>

// Typedef for NtUnmapViewOfSection
typedef LONG(NTAPI* pNtUnmapViewOfSection)(HANDLE ProcessHandle, PVOID BaseAddress);

// Global variable for saving the child process ID
DWORD child_pid = 0;

void SetColor(WORD color) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hConsole != INVALID_HANDLE_VALUE) {
        SetConsoleTextAttribute(hConsole, color);
    }
}

void ResetColor() {
    SetColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}

DWORD GetParentProcessID(DWORD pid) {
    DWORD ppid = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnapshot, &pe)) {
            do {
                if (pe.th32ProcessID == pid) {
                    ppid = pe.th32ParentProcessID;
                    break;
                }
            } while (Process32Next(hSnapshot, &pe));
        }
        CloseHandle(hSnapshot);
    }
    return ppid;
}

std::vector<HMODULE> GetProcessModules(DWORD processID) {
    std::vector<HMODULE> modules;
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);
    if (hProcess) {
        HMODULE hMods[1024];
        DWORD cbNeeded;
        if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
            for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
                modules.push_back(hMods[i]);
            }
        }
        CloseHandle(hProcess);
    }
    return modules;
}

// Function for determining the module name based on the handle
std::wstring GetModuleName(HMODULE hModule, DWORD processID) {
    wchar_t szModName[MAX_PATH];
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);
    if (hProcess) {
        if (GetModuleFileNameExW(hProcess, hModule, szModName, sizeof(szModName) / sizeof(wchar_t))) {
            std::wstring fullPath(szModName);
            size_t pos = fullPath.find_last_of(L"\\/");
            CloseHandle(hProcess);
            return (pos != std::wstring::npos) ? fullPath.substr(pos + 1) : fullPath;
        }
        CloseHandle(hProcess);
    }
    return L"";
}

// Function for checking whether a specific DLL is loaded
bool IsDLLLoaded(const std::vector<HMODULE>& modules, const std::wstring& dllName, DWORD processID) {
    for (const auto& mod : modules) {
        std::wstring modName = GetModuleName(mod, processID);
        if (_wcsicmp(modName.c_str(), dllName.c_str()) == 0) {
            return true;
        }
    }
    return false;
}

// Function for unloading the DLL using NtUnmapViewOfSection
bool UnmapDLLFunc(DWORD processID, const std::wstring& dllName) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
    if (!hProcess) {
        SetColor(FOREGROUND_RED);
        std::wcerr << L"[-] Error opening the process. Error code: " << GetLastError() << L"\n";
        ResetColor();
        return false;
    }

    std::vector<HMODULE> modules = GetProcessModules(processID);
    HMODULE hTargetDLL = nullptr;
    for (const auto& mod : modules) {
        if (_wcsicmp(GetModuleName(mod, processID).c_str(), dllName.c_str()) == 0) {
            hTargetDLL = mod;
            break;
        }
    }

    if (!hTargetDLL) {
        SetColor(FOREGROUND_GREEN);
        std::wcerr << L"[+] DLL " << dllName << L" was not found.\n";
        ResetColor();
        CloseHandle(hProcess);
        return false;
    }

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) {
        SetColor(FOREGROUND_RED);
        std::wcerr << L"[-] ntdll.dll is not loaded.\n";
        ResetColor();
        CloseHandle(hProcess);
        return false;
    }

    auto NtUnmapViewOfSection = (pNtUnmapViewOfSection)GetProcAddress(hNtdll, "NtUnmapViewOfSection");
    if (!NtUnmapViewOfSection) {
        SetColor(FOREGROUND_RED);
        std::wcerr << L"[-] NtUnmapViewOfSection was not found.\n";
        ResetColor();
        CloseHandle(hProcess);
        return false;
    }

    LONG status = NtUnmapViewOfSection(hProcess, (PVOID)hTargetDLL);
    if (status != 0) {
        SetColor(FOREGROUND_RED);
        std::wcerr << L"[-] Error when unmapping the DLL: " << status << L"\n";
        ResetColor();
        CloseHandle(hProcess);
        return false;
    }

    SetColor(FOREGROUND_GREEN);
    std::wcout << L"[+] DLL " << dllName << L" successfully unmapped.\n";
    ResetColor();

    CloseHandle(hProcess);
    return true;
}

// Function for determining the path of the current executable program
std::wstring GetExecutablePath() {
    wchar_t path[MAX_PATH];
    if (GetModuleFileNameW(NULL, path, MAX_PATH) == 0) {
        return L"";
    }
    return std::wstring(path);
}

// Function for starting a new instance of the process in the suspended state
bool StartSelfSuspended(DWORD currentPID, PROCESS_INFORMATION& pi) {
    std::wstring exePath = GetExecutablePath();
    if (exePath.empty()) {
        SetColor(FOREGROUND_RED);
        std::wcerr << L"[-] Could not determine the path of the executable program.\n";
        ResetColor();
        return false;
    }

    // Create the command line for the new process without special arguments
    std::wstringstream cmd;
    cmd << L"\"" << exePath << L"\"";
    std::wstring commandLine = cmd.str();

    // STARTUPINFOW initializing
    STARTUPINFOW si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);

    ZeroMemory(&pi, sizeof(pi));

    // Create the new process in suspended state
    BOOL success = CreateProcessW(
        NULL,
        const_cast<LPWSTR>(commandLine.c_str()),
        NULL,
        NULL,
        FALSE,
        CREATE_NEW_PROCESS_GROUP | CREATE_SUSPENDED | CREATE_NEW_CONSOLE,
        NULL,
        NULL,
        &si,
        &pi
    );

    if (!success) {
        SetColor(FOREGROUND_RED);
        std::wcerr << L"[-] Error when starting the new process in suspended state. Error code: " << GetLastError() << L"\n";
        ResetColor();
        return false;
    }

    SetColor(FOREGROUND_GREEN);
    std::wcout << L"[+] New process successfully started in suspended state. PID: " << pi.dwProcessId << L"\n";
    ResetColor();

    child_pid = pi.dwProcessId; // Save the child process ID
    std::wcout << L"[+] Child PID is " << child_pid << L"\n";

    return true;
}

// Function to resume the new process
bool ResumeProcess(PROCESS_INFORMATION& pi) {
    if (ResumeThread(pi.hThread) == (DWORD)-1) {
        SetColor(FOREGROUND_RED);
        std::wcerr << L"[-] Error when resuming the new process. Error code: " << GetLastError() << L"\n";
        ResetColor();
        return false;
    }

    SetColor(FOREGROUND_GREEN);
    std::wcout << L"[+] New process successfully resumed.\n";
    ResetColor();

    // Closing Handles
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return true;
}

// Function for initialising the anti-debugging measures
bool InitializeAntiDebugging(DWORD currentPID, DWORD parentPID, const std::wstring& targetDLL) {
    // List the modules in the parent process
    std::vector<HMODULE> parentModules = GetProcessModules(parentPID);
    bool dllLoaded = IsDLLLoaded(parentModules, targetDLL, parentPID);

    if (dllLoaded) {
        SetColor(FOREGROUND_RED);
        std::wcout << L"[+] DLL " << targetDLL << L" is loaded in the parent process. Initiate the anti-debugging measures.\n";
        ResetColor();

        PROCESS_INFORMATION pi;
        if (!StartSelfSuspended(currentPID, pi)) {
            SetColor(FOREGROUND_RED);
            std::wcerr << L"[-] Could not start the new process.\n";
            ResetColor();
            return false;
        }

        // Unloading the DLL from the parent process
        if (!UnmapDLLFunc(parentPID, targetDLL)) {
            SetColor(FOREGROUND_RED);
            std::wcerr << L"[-] Error when unmapping the DLL from the parent process.\n";
            ResetColor();
            // Terminate the new process if unmapping has failed
            TerminateProcess(pi.hProcess, 1);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return false;
        }

        // Resume process
        if (!ResumeProcess(pi)) {
            SetColor(FOREGROUND_RED);
            std::wcerr << L"[-] Error when resuming the new process.\n";
            ResetColor();
            return false;
        }

        // End the current process
        SetColor(FOREGROUND_GREEN);
        std::wcout << L"[+] Current process is terminated.\n";
        ResetColor();
        ExitProcess(0);
    }
    else {
        SetColor(FOREGROUND_GREEN);
        std::wcout << L"[+] DLL " << targetDLL << L" is not loaded in the parent process. No action required.\n";
        ResetColor();
    }

    return true;
}
