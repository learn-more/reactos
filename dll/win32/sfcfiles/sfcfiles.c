/*
 * PROJECT:     ReactOS System File Checker
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     List of files to protect
 * COPYRIGHT:   Copyright 2020 Mark Jansen (mark.jansen@reactos.org)
 */

#include <ndk/sfc.h>

#define NDEBUG
#include <debug.h>


NTSTATUS WINAPI SfcGetFiles(PSFC_PROTECT_FILE_ENTRY* ProtFileData, PULONG FileCount)
{
    UNIMPLEMENTED;

    return STATUS_NOT_IMPLEMENTED;
}
