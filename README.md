# DllManager

```bash
Usage:
  Show help:
    DllManager.exe help
    DllManager.exe -help
    DllManager.exe --help
    DllManager.exe -h

  Inject DLL:
    DllManager.exe inject --pid <PID> --dll <PathToDLL>
    DllManager.exe inject --pname <ProcessName> --dll <PathToDLL>

  Unload DLL:
    DllManager.exe unload --pid <PID> --dll <DLLFileNameOrFullPath>
    DllManager.exe unload --pname <ProcessName> --dll <DLLFileNameOrFullPath>

Examples:
  DllManager.exe inject --pid 1234 --dll C:\Test\MyDll.dll
  DllManager.exe unload --pname notepad.exe --dll MyDll.dll
```
