#ifndef _NDK_SFC_H
#define _NDK_SFC_H

#include <umtypes.h>


typedef struct _SFC_PROTECT_FILE_ENTRY
{
    PWSTR SourceFileName;
    PWSTR FileName;
    PWSTR InfName;
} SFC_PROTECT_FILE_ENTRY, *PSFC_PROTECT_FILE_ENTRY;


#endif // _NDK_SFC_H
