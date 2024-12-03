# Shadow-Rebirth
Shadow Rebirth - An Aggressive Outbreak Anti-Debugging Technique

---

## Introduction

Instead of merely hiding from the debugger, this method actively crashes it, then rises from the ashes to continue execution unimpeded.
The Shadow Rebirth technique works by detecting the presence of specific debugger DLLs, unmapping them to cause the debugger to crash, and then spawning a new instance of the process that carries on without the debugger's interference. This paper will pull back the cloak and reveal the secrets behind this technique, exploring how it works and why it's effective.

---

## Overview of the Shadow Rebirth Technique

The Shadow Rebirth technique operates in several key steps:

1. **Detection of Debugger DLLs**: The application checks if certain DLLs commonly used by debuggers (e.g., `x64dbg.dll`, `ida.dll`) are loaded in the parent process.
    
2. **Process Recreation**: Upon detecting these DLLs, the application creates a new instance of itself in a suspended state, ready to continue the mission without the debugger's watchful eye.
    
3. **DLL Unmapping**: The application then unmaps the debugger's DLLs from the parent process using the `NtUnmapViewOfSection` function, effectively pulling the rug out from under the debugger.
    
4. **Debugger Crash and Process Continuation**: Unmapping these critical DLLs causes the debugger to crash. Meanwhile, the new process instance resumes execution independently, like a shadow slipping away unnoticed.
    
5. **Termination of Original Process**: The original process exits gracefully (or not so gracefully, depending on your perspective), leaving the new process to continue its work unimpeded.
    

This method ensures that even though the new process is initially created under the debugger's control, it survives the debugger's untimely demise and continues execution autonomously.

---

## Video and Screenshot

Screenshot:

![Screen1](https://github.com/user-attachments/assets/db1a217a-7f9f-4df7-835c-2d9ef1a51186)


![Screen2](https://github.com/user-attachments/assets/c250e1ff-aa4f-4db1-adca-96aacaded22e)


![Screen3](https://github.com/user-attachments/assets/956dba81-4a1d-4c38-a504-ff19c2817a88)


![Screen4](https://github.com/user-attachments/assets/71c7e56b-aae1-41ff-a092-12e30992ae94)


Video:


![Anti-Debugging-Shadow-Rebirth](https://github.com/user-attachments/assets/4d2c1585-5a22-4731-9cb7-cfcf070d58c4)

---

## Detailed Code Analysis

1. The Main Function: Where the Magic Begins

```c++
int main(int argc, char* argv[]) {
    // Decrypt the target DLL name (e.g., x64dbg.dll)
    // ...

    // Get current and parent process IDs
    DWORD currentPID = GetCurrentProcessId();
    DWORD parentPID = GetParentProcessID(currentPID);

    // Initialize anti-debugging measures
    if (!InitializeAntiDebugging(currentPID, parentPID, targetDLL)) {
        // Handle initialization failure
        return 1;
    }

    // Main logic execution
    // For dramatic effect, a countdown
    for (int i = 10; i > 0; --i) {
        std::wcout << L"Countdown: " << i << L"\n";
        Sleep(1000);
    }

    std::wcout << L"Main logic finished.\n";
    return 0;
}

```

**Explanation**: The main function decrypts the name of the target DLL (the debugger's lifeline), retrieves the current and parent process IDs, and then calls `InitializeAntiDebugging` to start the Shadow Rebirth process.


2. Decrypting the Target DLL Name: Secrets Unveiled

```c++
#define XOR_KEY 0x5A // Encryption key

std::vector<unsigned char> encryptedHex = { 0x22, 0x6C, 0x6E, 0x3E, 0x38, 0x3D, 0x74, 0x3E, 0x36, 0x36 };

std::wstring targetDLL;

// Decrypt the DLL name
for (auto hexChar : encryptedHex) {
    targetDLL += static_cast<wchar_t>(hexChar ^ XOR_KEY);
}

```

**Explanation**: By using XOR encryption with a fixed key, the actual name of the DLL (e.g., `x64dbg.dll`) remains hidden from static analysis tools. Only at runtime does the shadow reveal its true form.


3. Scanning for Debugger DLLs: The Shadow's Vigil

```c++
std::vector<HMODULE> parentModules = GetProcessModules(parentPID); 
bool dllLoaded = IsDLLLoaded(parentModules, targetDLL, parentPID);
```

**Explanation**: The program scans the parent process for the presence of the target DLL. If the DLL is found, it means the debugger is present, and it's time for the Shadow Rebirth to commence.

4. Initializing Anti-Debugging Measures: The Rebirth Begins

```c++
bool InitializeAntiDebugging(DWORD currentPID, DWORD parentPID, const std::wstring& targetDLL) {
    // If the target DLL is loaded, proceed with the Shadow Rebirth
    if (dllLoaded) {
        PROCESS_INFORMATION pi;
        if (!StartSelfSuspended(currentPID, pi)) {
            // Handle failure
            return false;
        }

        if (!UnmapDLLFunc(parentPID, targetDLL)) {
            // Terminate the new process if unmapping fails
            TerminateProcess(pi.hProcess, 1);
            return false;
        }

        if (!ResumeProcess(pi)) {
            return false;
        }

        // Exit the original process, the shadow lives on
        ExitProcess(0);
    }
    return true;
}

```

**Explanation**: The `InitializeAntiDebugging` function orchestrates the key steps: creating a new process, unmapping the debugger's DLL, resuming the new process, and terminating the original one.

5. Unmapping the Debugger's DLL: Cutting the Strings

```c++
bool UnmapDLLFunc(DWORD processID, const std::wstring& dllName) {
    // Open the parent process
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);

    // Locate the target DLL in the parent process
    HMODULE hTargetDLL = /* ... */;

    // Get NtUnmapViewOfSection function
    auto NtUnmapViewOfSection = (pNtUnmapViewOfSection)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtUnmapViewOfSection");

    // Unmap the DLL
    LONG status = NtUnmapViewOfSection(hProcess, (PVOID)hTargetDLL);

    CloseHandle(hProcess);
    return status == 0;
}

```

**Explanation**: By unmapping the debugger's DLL from the parent process, we effectively pull the plug on the debugger. It's like turning off the lights and watching the intruder stumble.

6. Creating a New Process: The Shadow Emerges

```c++

bool StartSelfSuspended(DWORD currentPID, PROCESS_INFORMATION& pi) {
    std::wstring exePath = GetExecutablePath();
    std::wstringstream cmd;
    cmd << L"\"" << exePath << L"\"";
    std::wstring commandLine = cmd.str();

    STARTUPINFOW si = { sizeof(si) };
    BOOL success = CreateProcessW(
        NULL,
        const_cast<LPWSTR>(commandLine.c_str()),
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED | CREATE_NEW_CONSOLE,
        NULL,
        NULL,
        &si,
        &pi
    );

    return success;
}
```

**Explanation**: A new instance of the application is created in a suspended state. By specifying `CREATE_NEW_PROCESS_GROUP` and `CREATE_NEW_CONSOLE`, the new process is more independent, like a shadow detached from its source.

7. Resuming the New Process: The Rebirth Complete

```c++
bool ResumeProcess(PROCESS_INFORMATION& pi) {
    if (ResumeThread(pi.hThread) == (DWORD)-1) {
        return false;
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return true;
}
```

**Explanation**: The new process, initially suspended, is now resumed. With the debugger out of the picture, the shadow can move freely.

8. The Original Process Exits: Farewell, Old Friend

```c++
ExitProcess(0);
```

**Explanation**: The original process exits, leaving no traces behind. The shadow continues its mission, unimpeded.

---

## The Mechanics Behind the Shadow Rebirth

### How the New Process Survives the Debugger's Crash

When the debugger crashes due to its DLL being unmapped, one might expect all child processes to be terminated. However, the Shadow Rebirth technique ensures the new process survives:

1. **Process Isolation**: By using `CREATE_NEW_CONSOLE`, the new process is less tied to the parent process's environment.
    
2. **Suspended State Creation**: The new process is created in a suspended state before the debugger crashes.
    
3. **Debugger Crash After Creation**: Since the debugger crashes after the new process is created but before it's resumed, the new process isn't affected by the debugger's demise.
    
4. **Resuming Independently**: The new process resumes execution outside the debugger's control, like a shadow slipping away.


---

## Why Unmapping the DLL Causes the Debugger to Crash

- **Access Violations**: The debugger tries to access code or data in the unmapped DLL, leading to crashes.
- **Resource Unavailability**: Critical functions and resources become unavailable, destabilizing the debugger.

It's akin to pulling out the foundation from under a building—the structure collapses.

---

## Conclusion

The Shadow Rebirth technique exemplifies an advanced anti-debugging strategy that not only detects a debugger's presence but also actively disrupts it. By unmapping critical DLLs and spawning a new process that continues execution independently, the application ensures its operation remains uninterrupted.

This method highlights the lengths to which software can go to protect itself, using low-level system functions and clever process manipulation. While the technique is aggressive, causing the debugger to crash.

As shadows fade and return with the changing light, so too does the application emerge a new, reborn and free from prying eyes.

---

## References:

[1] https://maldevacademy.com/

[2] https://github.com/LordNoteworthy/al-khaser/tree/master

[3] https://learn.microsoft.com/

[4] https://www.codeproject.com/


If you have any suggestions for improvement I can add, please let me know.
