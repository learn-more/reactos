/*
 * PROJECT:     ReactOS System File Checker
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     Commandline handling
 * COPYRIGHT:   Copyright 2020 Mark Jansen (mark.jansen@reactos.org)
 */

#include <stdarg.h>
#include <ndk/umtypes.h>
//#include <ndk/umfuncs.h>
#include <windef.h>
#include <winbase.h>
#include <winreg.h>
#include <winuser.h>
#include <wchar.h>
#include <sfc.h>
typedef LONG NTSTATUS;
//#include <ntstatus.h>

#include <conutils.h>
#include <strsafe.h>
#include "resource.h"


void PrintUsage(void)
{
    ConResPuts(StdOut, IDS_USAGE);
}

static NTSTATUS (WINAPI* g_pfnSfcInitProt)(DWORD dwUnk0, DWORD dwUnk1, DWORD dwUnk2, DWORD dwQuota, DWORD dwUnk4, DWORD dwUnk5, DWORD dwUnk6);
static VOID (WINAPI* g_pfnSfcTerminateWatcherThread)();

void InitializeSfc()
{
    LoadLibraryW(L"R:\\build\\dev\\devenv\\dll\\win32\\sfc_os\\Debug\\sfc_os.dll");
    LoadLibraryW(L"R:\\build\\dev\\devenv\\dll\\win32\\sfcfiles\\Debug\\sfcfiles.dll");

    HMODULE mod = LoadLibraryW(L"R:\\build\\dev\\devenv\\dll\\win32\\sfc\\Debug\\sfc.dll");

    if (mod)
    {
        g_pfnSfcInitProt = (PVOID)GetProcAddress(mod, MAKEINTRESOURCEA(1));
        g_pfnSfcTerminateWatcherThread = GetProcAddress(mod, MAKEINTRESOURCEA(2));

        if (g_pfnSfcInitProt && g_pfnSfcTerminateWatcherThread)
        {
            g_pfnSfcInitProt(0, 0, 0, SFC_QUOTA_DEFAULT, 0, 0, 0);
            Sleep(10000);
            g_pfnSfcTerminateWatcherThread();
        }

    }
}



int wmain(int argc, WCHAR *argv[])
{
    ConInitStdStreams();

    for (int n = 1; n < argc; ++n)
    {
        PCWSTR arg = argv[n];
        if (arg[0] == '/' || arg[0] == '-')
        {
            /*if (!_wcsicmp(arg + 1, L"ScanNow"))
            {
                g_fRepair = TRUE;
            }
            else if (!_wcsicmp(arg + 1, L"VerifyOnly"))
            {
                g_fRepair = FALSE;
            }
            else if (!_wcsicmp(arg + 1, L"ScanFile"))
            {
                g_fRepair = TRUE;

            }
            else if (!_wcsicmp(arg + 1, L"VerifyFile"))
            {
                g_fRepair = FALSE;
            }
            else */if (!_wcsicmp(arg + 1, L"Test"))
            {
                InitializeSfc();
                return;
            }
        }
    }

    PrintUsage();

    return 0;
}
