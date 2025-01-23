#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <vector>
#include <iostream>
#include <iomanip>  // for std::setw
#include <sstream>

#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Version.lib")

//---------------------------------------------
// Print help information
//---------------------------------------------
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
        << L"  Query DLL usage count:\n"
        << L"    DllManager.exe query --pid <PID> --dll <DLLFileNameOrFullPath>\n"
        << L"    DllManager.exe query --pname <ProcessName> --dll <DLLFileNameOrFullPath>\n\n"
        << L"  List all DLLs:\n"
        << L"    DllManager.exe list --pid <PID>\n"
        << L"    DllManager.exe list --pname <ProcessName>\n\n"
        << L"  Check if a specific DLL is loaded in a process:\n"
        << L"    DllManager.exe check --pid <PID> --dll <DLLFileNameOrFullPath>\n"
        << L"    DllManager.exe check --pname <ProcessName> --dll <DLLFileNameOrFullPath>\n\n"
        << L"Examples:\n"
        << L"  DllManager.exe inject --pid 1234 --dll C:\\Test\\MyDll.dll\n"
        << L"  DllManager.exe unload --pname notepad.exe --dll MyDll.dll\n"
        << L"  DllManager.exe query --pid 1234 --dll MyDll.dll\n"
        << L"  DllManager.exe list --pid 1234\n"
        << L"  DllManager.exe check --pname notepad.exe --dll user32.dll\n"
        << std::endl;
}

//---------------------------------------------
// Convert a std::wstring to lowercase
//---------------------------------------------
std::wstring ToLower(const std::wstring& str)
{
    std::wstring result = str;
    for (auto& ch : result)
        ch = towlower(ch);
    return result;
}

//---------------------------------------------
// Get PID by process name (if multiple processes share the same name, 
// this example only returns the first match)
//---------------------------------------------
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

//---------------------------------------------
// A small helper to parse version info from file
//---------------------------------------------
bool GetFileVersionInfoStr(const std::wstring& filePath,
    std::wstring& outCompany,
    std::wstring& outDescription,
    std::wstring& outVersion)
{
    outCompany.clear();
    outDescription.clear();
    outVersion.clear();

    DWORD dummyHandle = 0;
    DWORD size = GetFileVersionInfoSizeW(filePath.c_str(), &dummyHandle);
    if (size == 0)
    {
        // possibly no version resource
        return false;
    }

    std::vector<BYTE> data(size);
    if (!GetFileVersionInfoW(filePath.c_str(), 0, size, data.data()))
    {
        return false;
    }

    // Typically use the "040904b0" (U.S. English + Unicode) block, 
    // but we can do a more robust approach enumerating languages if needed.
    struct LANGANDCODEPAGE {
        WORD wLanguage;
        WORD wCodePage;
    } *pLangInfo = NULL;
    UINT cbLang = 0;

    // Query a list of language-codepage pairs
    if (!VerQueryValueW(data.data(), L"\\VarFileInfo\\Translation", (LPVOID*)&pLangInfo, &cbLang))
    {
        // fallback: try the default en-US codepage = 040904b0
        pLangInfo = NULL;
    }

    // We make a small helper lambda to read a specific string
    auto queryStringValue = [&](const wchar_t* name, std::wstring& outVal)
        {
            outVal.clear();
            if (!pLangInfo || cbLang < sizeof(LANGANDCODEPAGE))
            {
                // Use fixed "040904b0"
                std::wstringstream ss;
                ss << L"\\StringFileInfo\\040904b0\\" << name;
                LPWSTR pBuf = NULL;
                UINT bufLen = 0;
                if (VerQueryValueW(data.data(), ss.str().c_str(), (LPVOID*)&pBuf, &bufLen) && pBuf)
                {
                    outVal.assign(pBuf, bufLen);
                }
            }
            else
            {
                // Use first language from the translation table
                LANGANDCODEPAGE lang = pLangInfo[0];
                wchar_t subBlock[50];
                swprintf_s(subBlock, L"\\StringFileInfo\\%04x%04x\\%s",
                    lang.wLanguage, lang.wCodePage, name);

                LPWSTR pBuf = NULL;
                UINT bufLen = 0;
                if (VerQueryValueW(data.data(), subBlock, (LPVOID*)&pBuf, &bufLen) && pBuf)
                {
                    outVal.assign(pBuf, bufLen);
                }
            }
        };

    // Query CompanyName
    queryStringValue(L"CompanyName", outCompany);

    // Query FileDescription
    queryStringValue(L"FileDescription", outDescription);

    // Query FileVersion or ProductVersion
    {
        std::wstring fileVer;
        queryStringValue(L"FileVersion", fileVer);

        std::wstring productVer;
        queryStringValue(L"ProductVersion", productVer);

        // 选一个非空的
        if (!fileVer.empty())
            outVersion = fileVer;
        else
            outVersion = productVer;
    }

    return true;
}

//---------------------------------------------
// Return the name or path matching
//---------------------------------------------
bool MatchModuleNameOrPath(const std::wstring& userInput, const std::wstring& modulePath)
{
    std::wstring userLower = ToLower(userInput);
    std::wstring modLower = ToLower(modulePath);

    // If userInput has path separators, do full path compare
    if (userLower.find(L'\\') != std::wstring::npos ||
        userLower.find(L'/') != std::wstring::npos ||
        userLower.find(L':') != std::wstring::npos)
    {
        return (userLower == modLower);
    }
    else
    {
        // Compare only the filename portion
        size_t pos = modLower.find_last_of(L'\\');
        if (pos == std::wstring::npos)
        {
            // No backslash in module path
            return (userLower == modLower);
        }
        else
        {
            std::wstring fileName = modLower.substr(pos + 1);
            return (userLower == fileName);
        }
    }
}

//---------------------------------------------
// Find the module base address in the target process that matches userDllString
//---------------------------------------------
HMODULE FindRemoteModule(DWORD pid, const std::wstring& userDllString)
{
    HMODULE hResult = NULL;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        return NULL;
    }

    MODULEENTRY32W me32 = { 0 };
    me32.dwSize = sizeof(me32);

    if (Module32FirstW(hSnapshot, &me32))
    {
        do
        {
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

//---------------------------------------------
// Check if a DLL exists in the target process
//---------------------------------------------
bool CheckDllExists(DWORD pid, const std::wstring& dllIdentifier)
{
    // If we can find a module handle, it "exists"
    HMODULE hm = FindRemoteModule(pid, dllIdentifier);
    return (hm != NULL);
}

//---------------------------------------------
// Inject DLL
//---------------------------------------------
bool InjectDLL(DWORD pid, const std::wstring& dllPath)
{
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess)
    {
        std::wcerr << L"[-] Unable to open process PID=" << pid
            << L", Error: " << GetLastError() << std::endl;
        return false;
    }

    size_t allocSize = (dllPath.size() + 1) * sizeof(wchar_t);
    LPVOID pRemoteBuf = VirtualAllocEx(hProcess, NULL, allocSize, MEM_COMMIT, PAGE_READWRITE);
    if (!pRemoteBuf)
    {
        std::wcerr << L"[-] VirtualAllocEx failed, Error: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return false;
    }

    if (!WriteProcessMemory(hProcess, pRemoteBuf, dllPath.c_str(), allocSize, NULL))
    {
        std::wcerr << L"[-] WriteProcessMemory failed, Error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

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

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)pLoadLibraryW, pRemoteBuf, 0, NULL);
    if (!hThread)
    {
        std::wcerr << L"[-] CreateRemoteThread failed, Error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    WaitForSingleObject(hThread, INFINITE);

    CloseHandle(hThread);
    VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    std::wcout << L"[+] Injection attempt finished, checking result..." << std::endl;
    // Re-check if injection is successful
    if (CheckDllExists(pid, dllPath))
    {
        std::wcout << L"[+] Successfully injected DLL: " << dllPath << std::endl;
        return true;
    }
    else
    {
        std::wcerr << L"[-] Injection might have failed: " << dllPath << L" not found in target process." << std::endl;
        return false;
    }
}

//---------------------------------------------
// Unload a DLL
//---------------------------------------------
bool UnloadDLL(DWORD pid, const std::wstring& dllIdentifier)
{
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess)
    {
        std::wcerr << L"[-] Unable to open process PID=" << pid
            << L", Error: " << GetLastError() << std::endl;
        return false;
    }

    // find module
    HMODULE hModuleToUnload = FindRemoteModule(pid, dllIdentifier);
    if (!hModuleToUnload)
    {
        std::wcerr << L"[-] Could not find DLL module: " << dllIdentifier << std::endl;
        CloseHandle(hProcess);
        return false;
    }

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

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)pFreeLibrary, (LPVOID)hModuleToUnload, 0, NULL);
    if (!hThread)
    {
        std::wcerr << L"[-] CreateRemoteThread failed, Error code: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return false;
    }

    WaitForSingleObject(hThread, INFINITE);

    CloseHandle(hThread);
    CloseHandle(hProcess);

    // Re-check if unload is successful
    if (!CheckDllExists(pid, dllIdentifier))
    {
        std::wcout << L"[+] Successfully unloaded DLL: " << dllIdentifier << std::endl;
        return true;
    }
    else
    {
        std::wcerr << L"[-] DLL still exists after unload attempt: " << dllIdentifier << std::endl;
        return false;
    }
}

//---------------------------------------------
// Query the usage count of a DLL in a given process
//---------------------------------------------
bool QueryDllUsageCount(DWORD pid, const std::wstring& dllIdentifier)
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        std::wcerr << L"[-] CreateToolhelp32Snapshot failed, Error code: "
            << GetLastError() << std::endl;
        return false;
    }

    MODULEENTRY32W me32 = { 0 };
    me32.dwSize = sizeof(me32);

    bool found = false;

    if (Module32FirstW(hSnapshot, &me32))
    {
        do
        {
            if (MatchModuleNameOrPath(dllIdentifier, me32.szExePath))
            {
                found = true;
                std::wcout << L"[+] DLL found: " << me32.szExePath << std::endl;
                std::wcout << L"    -> ProccntUsage: " << me32.ProccntUsage << std::endl;
                std::wcout << L"    -> GlblcntUsage: " << me32.GlblcntUsage << std::endl;
                break;
            }
        } while (Module32NextW(hSnapshot, &me32));
    }

    CloseHandle(hSnapshot);

    if (!found)
    {
        std::wcerr << L"[-] Could not find the specified DLL in the process: " << dllIdentifier << std::endl;
        return false;
    }

    return true;
}

//---------------------------------------------
// List all DLLs in the target process, 
// with extended info: Name, Address, Size, Path, 
// Description, Company, Version
//---------------------------------------------
bool ListAllDlls(DWORD pid)
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        std::wcerr << L"[-] CreateToolhelp32Snapshot failed, Error: " << GetLastError() << std::endl;
        return false;
    }

    MODULEENTRY32W me32 = { 0 };
    me32.dwSize = sizeof(me32);

    std::vector<MODULEENTRY32W> modules;

    if (Module32FirstW(hSnapshot, &me32))
    {
        do
        {
            modules.push_back(me32);
        } while (Module32NextW(hSnapshot, &me32));
    }
    CloseHandle(hSnapshot);

    // We prepare a struct to hold final info
    struct DllInfo
    {
        std::wstring moduleName;
        std::wstring baseAddress;
        std::wstring size;
        std::wstring path;
        std::wstring description;
        std::wstring company;
        std::wstring version;
    };

    std::vector<DllInfo> infoList;
    infoList.reserve(modules.size());

    for (auto& m : modules)
    {
        DllInfo di;
        di.moduleName = m.szModule;

        // Address & size as hex + decimal
        {
            std::wstringstream ssBase;
            ssBase << L"0x" << std::hex << (DWORD_PTR)m.modBaseAddr;
            di.baseAddress = ssBase.str();
        }
        {
            std::wstringstream ssSize;
            ssSize << m.modBaseSize << L" (0x" << std::hex << m.modBaseSize << L")";
            di.size = ssSize.str();
        }

        di.path = m.szExePath;

        // Description, Company, Version from resource
        std::wstring desc, comp, vers;
        if (GetFileVersionInfoStr(m.szExePath, comp, desc, vers))
        {
            di.description = desc;
            di.company = comp;
            di.version = vers;
        }
        else
        {
            di.description = L"";
            di.company = L"";
            di.version = L"";
        }

        infoList.push_back(di);
    }

    printf_s("[+] Total modules found: %zu\n", infoList.size());

    // Print as a table
    // We'll do a basic approach with setw
    const int colWidth1 = 20;  // moduleName
    const int colWidth2 = 12;  // baseAddress
    const int colWidth3 = 16;  // size
    const int colWidth4 = 40;  // path
    const int colWidth5 = 20;  // description
    const int colWidth6 = 20;  // company
    const int colWidth7 = 16;  // version

    std::wcout << std::left
        << std::setw(colWidth1) << L"ModuleName"
        << std::setw(colWidth2) << L"Address"
        << std::setw(colWidth3) << L"Size"
        << std::setw(colWidth4) << L"Path"
        << std::setw(colWidth5) << L"Description"
        << std::setw(colWidth6) << L"Company"
        << std::setw(colWidth7) << L"Version"
        << std::endl;

    std::wcout << std::wstring(150, L'-') << std::endl;

    for (auto& di : infoList)
    {
        printf_s("%ls | %ls | %ls | %ls | %ls | %ls | %ls\n",
            di.moduleName.c_str(),
            di.baseAddress.c_str(),
            di.size.c_str(),
            di.path.c_str(),
            di.description.c_str(),
            di.company.c_str(),
            di.version.c_str());
    }

    return true;
}

//---------------------------------------------
// Command line parsing
//---------------------------------------------
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

    // The first argument => inject, unload, query, list, check
    std::wstring action = ToLower(args[0]);
    if (action != L"inject" &&
        action != L"unload" &&
        action != L"query" &&
        action != L"list" &&
        action != L"check")
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
            // Other unrecognized parameters
            std::wcerr << L"[!] Unrecognized parameter: " << args[i] << std::endl;
        }
    }

    // If we need a PID but not provided, check pname
    if (!usePid && pname.empty())
    {
        if (action != L"list")
        {
            // list 可以只使用 --pid 或 --pname ，两者必须有其一
            std::wcerr << L"[-] You must specify --pid <pid> or --pname <processName>" << std::endl;
            PrintHelp();
            return -1;
        }
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
        if (dllPathOrName.empty())
        {
            std::wcerr << L"[-] You must specify --dll <PathToDLL> for injection" << std::endl;
            return -1;
        }
        result = InjectDLL(pid, dllPathOrName);
    }
    else if (action == L"unload")
    {
        if (dllPathOrName.empty())
        {
            std::wcerr << L"[-] You must specify --dll <DLLFileNameOrFullPath> for unload" << std::endl;
            return -1;
        }
        result = UnloadDLL(pid, dllPathOrName);
    }
    else if (action == L"query")
    {
        if (dllPathOrName.empty())
        {
            std::wcerr << L"[-] You must specify --dll <DLLFileNameOrFullPath> for query" << std::endl;
            return -1;
        }
        result = QueryDllUsageCount(pid, dllPathOrName);
    }
    else if (action == L"list")
    {
        // List all DLLs in the process
        result = ListAllDlls(pid);
    }
    else if (action == L"check")
    {
        if (dllPathOrName.empty())
        {
            std::wcerr << L"[-] You must specify --dll <DLLFileNameOrFullPath> for check" << std::endl;
            return -1;
        }
        bool exists = CheckDllExists(pid, dllPathOrName);
        if (exists)
        {
            std::wcout << L"[+] The DLL [" << dllPathOrName << L"] is loaded in PID=" << pid << std::endl;
            result = true;
        }
        else
        {
            std::wcerr << L"[-] The DLL [" << dllPathOrName << L"] is NOT loaded in PID=" << pid << std::endl;
            result = false;
        }
    }

    return result ? 0 : -1;
}
