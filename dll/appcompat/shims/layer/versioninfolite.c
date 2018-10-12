/*
 * PROJECT:     ReactOS 'Layers' Shim library
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     Always pass a VerifyVersionInfo check
 * COPYRIGHT:   Copyright 2018,2019 Mark Jansen (mark.jansen@reactos.org)
 */

#define WIN32_NO_STATUS
#include <windef.h>
#include <winbase.h>
#include <shimlib.h>


#define SHIM_NS         VerifyVersionInfoLite
#include <setup_shim.inl>

BOOL WINAPI SHIM_OBJ_NAME(VerifyVersionInfoAW)(IN LPOSVERSIONINFOEXW lpVersionInformation,
                                               IN DWORD dwTypeMask,
                                               IN DWORDLONG dwlConditionMask)
{
    return TRUE;
}

#define SHIM_NUM_HOOKS  2
#define SHIM_SETUP_HOOKS \
    SHIM_HOOK(0, "KERNEL32.DLL", "VerifyVersionInfoA", SHIM_OBJ_NAME(VerifyVersionInfoAW)) \
    SHIM_HOOK(1, "KERNEL32.DLL", "VerifyVersionInfoW", SHIM_OBJ_NAME(VerifyVersionInfoAW))

#include <implement_shim.inl>
