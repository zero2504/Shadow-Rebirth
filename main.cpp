//main.cpp
#include "ShadowRebirth.h"
#include <iostream>

#define XOR_KEY 0x5A // Key for XOR


int main(int argc, char* argv[]) {

    std::vector<unsigned char> encryptedHex = { 0x22, 0x6C, 0x6E, 0x3E, 0x38, 0x3D, 0x74, 0x3E, 0x36, 0x36 };

    // Cleartest string e.g x64dbg.dll or ida.dll
    std::wstring targetDLL;

    // Decryption
    for (auto hexChar : encryptedHex) {
        targetDLL += static_cast<wchar_t>(hexChar ^ XOR_KEY); // XOR-Operation for every byte
    }

    // Other option -> defining it directly (Caution: Could be detected in static analysis)
    //std::wstring targetDLL = L"x64dbg.dll";

    // Find current PID
    DWORD currentPID = GetCurrentProcessId();

    // Find parent PID -> Function is defined in ShadowRebirth.cpp
    DWORD parentPID = GetParentProcessID(currentPID);
    if (parentPID == 0) {
        SetColor(FOREGROUND_RED);
        std::cerr << "[-] No Parent found.\n";
        ResetColor();
        return 1;
    }

    SetColor(FOREGROUND_GREEN);
    std::wcout << L"[+] Parent Process ID: " << parentPID << L"\n";
    std::wcout << L"[+] Current Process ID: " << currentPID << L"\n";
    ResetColor();

    // Initialising the anti-debugging measures
    if (!InitializeAntiDebugging(currentPID, parentPID, targetDLL)) {
        SetColor(FOREGROUND_RED);
        std::wcerr << L"[-] Error when initialising the anti-debugging measures.\n";
        ResetColor();
        return 1;
    }

    // If the DLL was not loaded, the main logic is executed here
    SetColor(FOREGROUND_GREEN);
    std::wcout << L"[+] Start the main logic of the programm\n";
    ResetColor();

    // **Main-Logic:**
    // Example PPID Spoofing for another Evasion:
    // To-Do



    for (int i = 10; i > 0; --i) {
        std::wcout << L"Countdown: " << i << L"\n";
        Sleep(1000); // wait for 1 second
    }

    SetColor(FOREGROUND_GREEN);
    std::wcout << L"Main logic finished.\n";
    ResetColor();

    return 0;
}
