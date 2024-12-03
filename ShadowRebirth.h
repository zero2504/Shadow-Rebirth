// ShadowRebirth.h
#ifndef SHADOWREBIRTH_H
#define SHADOWREBIRTH_H

#include <windows.h>
#include <string>
#include <vector>

// Function for setting console color
void SetColor(WORD color);

// Function for resetting console color
void ResetColor();

// Get Parent PPID
DWORD GetParentProcessID(DWORD pid);

// Function for listing all modules in the specified process
std::vector<HMODULE> GetProcessModules(DWORD processID);

// Function for determining the module name based on the handle
std::wstring GetModuleName(HMODULE hModule, DWORD processID);

// Function for checking whether a specific DLL is loaded
bool IsDLLLoaded(const std::vector<HMODULE>& modules, const std::wstring& dllName, DWORD processID);

// Function for unloading the DLL using NtUnmapViewOfSection (Magic)
bool UnmapDLLFunc(DWORD processID, const std::wstring& dllName);

// Function for determining the path of the current executable program
std::wstring GetExecutablePath();

// Function for starting a new instance of the process in suspended state (Shadow Rebirth)
bool StartSelfSuspended(DWORD currentPID, PROCESS_INFORMATION& pi);

// Function for summarising the new process
bool ResumeProcess(PROCESS_INFORMATION& pi);

// Function for initialising the anti-debugging measures
bool InitializeAntiDebugging(DWORD currentPID, DWORD parentPID, const std::wstring& targetDLL);

#endif 
