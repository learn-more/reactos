#include "../advapi32.h"

#include <winuser.h>
#include <wine/debug.h>
#include <wine/unicode.h>

WINE_DEFAULT_DEBUG_CHANNEL(reg);

#if 0
// Non-recursive RegDeleteTreeW implementation by Thomas, however it needs bugfixing
static NTSTATUS
RegpDeleteTree(IN HKEY hKey)
{
    typedef struct
    {
        LIST_ENTRY ListEntry;
        HANDLE KeyHandle;
    } REGP_DEL_KEYS, *PREG_DEL_KEYS;

    LIST_ENTRY delQueueHead;
    PREG_DEL_KEYS delKeys, newDelKeys;
    HANDLE ProcessHeap;
    ULONG BufferSize;
    PKEY_BASIC_INFORMATION BasicInfo;
    PREG_DEL_KEYS KeyDelRoot;
    NTSTATUS Status = STATUS_SUCCESS;
    NTSTATUS Status2 = STATUS_SUCCESS;

    InitializeListHead(&delQueueHead);

    ProcessHeap = RtlGetProcessHeap();

    /* NOTE: no need to allocate enough memory for an additional KEY_BASIC_INFORMATION
             structure for the root key, we only do that for subkeys as we need to
             allocate REGP_DEL_KEYS structures anyway! */
    KeyDelRoot = RtlAllocateHeap(ProcessHeap,
                                 0,
                                 sizeof(REGP_DEL_KEYS));
    if (KeyDelRoot != NULL)
    {
        KeyDelRoot->KeyHandle = hKey;
        InsertTailList(&delQueueHead,
                       &KeyDelRoot->ListEntry);

        do
        {
            delKeys = CONTAINING_RECORD(delQueueHead.Flink,
                                        REGP_DEL_KEYS,
                                        ListEntry);

            BufferSize = 0;
            BasicInfo = NULL;
            newDelKeys = NULL;

ReadFirstSubKey:
            /* check if this key contains subkeys and delete them first by queuing
               them at the head of the list */
            Status2 = NtEnumerateKey(delKeys->KeyHandle,
                                     0,
                                     KeyBasicInformation,
                                     BasicInfo,
                                     BufferSize,
                                     &BufferSize);

            if (NT_SUCCESS(Status2))
            {
                OBJECT_ATTRIBUTES ObjectAttributes;
                UNICODE_STRING SubKeyName;

                ASSERT(newDelKeys != NULL);
                ASSERT(BasicInfo != NULL);

                /* don't use RtlInitUnicodeString as the string is not NULL-terminated! */
                SubKeyName.Length = BasicInfo->NameLength;
                SubKeyName.MaximumLength = BasicInfo->NameLength;
                SubKeyName.Buffer = BasicInfo->Name;

                InitializeObjectAttributes(&ObjectAttributes,
                                           &SubKeyName,
                                           OBJ_CASE_INSENSITIVE,
                                           delKeys->KeyHandle,
                                           NULL);

                /* open the subkey */
                Status2 = NtOpenKey(&newDelKeys->KeyHandle,
                                    DELETE | KEY_ENUMERATE_SUB_KEYS,
                                    &ObjectAttributes);
                if (!NT_SUCCESS(Status2))
                {
                    goto SubKeyFailure;
                }

                /* enqueue this key to the head of the deletion queue */
                InsertHeadList(&delQueueHead,
                               &newDelKeys->ListEntry);

                /* try again from the head of the list */
                continue;
            }
            else
            {
                if (Status2 == STATUS_BUFFER_TOO_SMALL)
                {
                    newDelKeys = RtlAllocateHeap(ProcessHeap,
                                                 0,
                                                 BufferSize + sizeof(REGP_DEL_KEYS));
                    if (newDelKeys != NULL)
                    {
                        BasicInfo = (PKEY_BASIC_INFORMATION)(newDelKeys + 1);

                        /* try again */
                        goto ReadFirstSubKey;
                    }
                    else
                    {
                        /* don't break, let's try to delete as many keys as possible */
                        Status2 = STATUS_INSUFFICIENT_RESOURCES;
                        goto SubKeyFailureNoFree;
                    }
                }
                else if (Status2 == STATUS_BUFFER_OVERFLOW)
                {
                    PREG_DEL_KEYS newDelKeys2;

                    ASSERT(newDelKeys != NULL);

                    /* we need more memory to query the key name */
                    newDelKeys2 = RtlReAllocateHeap(ProcessHeap,
                                                    0,
                                                    newDelKeys,
                                                    BufferSize + sizeof(REGP_DEL_KEYS));
                    if (newDelKeys2 != NULL)
                    {
                        newDelKeys = newDelKeys2;
                        BasicInfo = (PKEY_BASIC_INFORMATION)(newDelKeys + 1);

                        /* try again */
                        goto ReadFirstSubKey;
                    }
                    else
                    {
                        /* don't break, let's try to delete as many keys as possible */
                        Status2 = STATUS_INSUFFICIENT_RESOURCES;
                    }
                }
                else if (Status2 == STATUS_NO_MORE_ENTRIES)
                {
                    /* in some race conditions where another thread would delete
                       the same tree at the same time, newDelKeys could actually
                       be != NULL! */
                    if (newDelKeys != NULL)
                    {
                        RtlFreeHeap(ProcessHeap,
                                    0,
                                    newDelKeys);
                    }
                    break;
                }

SubKeyFailure:
                /* newDelKeys can be NULL here when NtEnumerateKey returned an
                   error other than STATUS_BUFFER_TOO_SMALL or STATUS_BUFFER_OVERFLOW! */
                if (newDelKeys != NULL)
                {
                    RtlFreeHeap(ProcessHeap,
                                0,
                                newDelKeys);
                }

SubKeyFailureNoFree:
                /* don't break, let's try to delete as many keys as possible */
                if (NT_SUCCESS(Status))
                {
                    Status = Status2;
                }
            }

            Status2 = NtDeleteKey(delKeys->KeyHandle);

            /* NOTE: do NOT close the handle anymore, it's invalid already! */

            if (!NT_SUCCESS(Status2))
            {
                /* close the key handle so we don't leak handles for keys we were
                   unable to delete. But only do this for handles not supplied
                   by the caller! */

                if (delKeys->KeyHandle != hKey)
                {
                    NtClose(delKeys->KeyHandle);
                }

                if (NT_SUCCESS(Status))
                {
                    /* don't break, let's try to delete as many keys as possible */
                    Status = Status2;
                }
            }

            /* remove the entry from the list */
            RemoveEntryList(&delKeys->ListEntry);

            RtlFreeHeap(ProcessHeap,
                        0,
                        delKeys);
        } while (!IsListEmpty(&delQueueHead));
    }
    else
        Status = STATUS_INSUFFICIENT_RESOURCES;

    return Status;
}


/************************************************************************
 *  RegDeleteTreeW
 *
 * @implemented
 */
LONG WINAPI
RegDeleteTreeW(IN HKEY hKey,
               IN LPCWSTR lpSubKey  OPTIONAL)
{
    HANDLE KeyHandle, CurKey, SubKeyHandle = NULL;
    NTSTATUS Status;

    Status = MapDefaultKey(&KeyHandle,
                           hKey);
    if (!NT_SUCCESS(Status))
    {
        return RtlNtStatusToDosError(Status);
    }

    if (lpSubKey != NULL)
    {
        OBJECT_ATTRIBUTES ObjectAttributes;
        UNICODE_STRING SubKeyName;

        RtlInitUnicodeString(&SubKeyName,
                             (LPWSTR)lpSubKey);

        InitializeObjectAttributes(&ObjectAttributes,
                                   &SubKeyName,
                                   OBJ_CASE_INSENSITIVE,
                                   KeyHandle,
                                   NULL);

        Status = NtOpenKey(&SubKeyHandle,
                           DELETE | KEY_ENUMERATE_SUB_KEYS,
                           &ObjectAttributes);
        if (!NT_SUCCESS(Status))
        {
            goto Cleanup;
        }

        CurKey = SubKeyHandle;
    }
    else
        CurKey = KeyHandle;

    Status = RegpDeleteTree(CurKey);

    if (NT_SUCCESS(Status))
    {
        /* make sure we only close hKey (KeyHandle) when the caller specified a
           subkey, because the handle would be invalid already! */
        if (CurKey != KeyHandle)
        {
            ClosePredefKey(KeyHandle);
        }

        return ERROR_SUCCESS;
    }
    else
    {
        /* make sure we close all handles we created! */
        if (SubKeyHandle != NULL)
        {
            NtClose(SubKeyHandle);
        }

Cleanup:
        ClosePredefKey(KeyHandle);

        return RtlNtStatusToDosError(Status);
    }
}
#endif


/************************************************************************
 *  RegDeleteTreeW
 *
 * @implemented
 */
LSTATUS
WINAPI
RegDeleteTreeW(HKEY hKey,
               LPCWSTR lpszSubKey)
{
    LONG ret;
    DWORD dwMaxSubkeyLen, dwMaxValueLen;
    DWORD dwMaxLen, dwSize;
    NTSTATUS Status;
    HANDLE KeyHandle;
    HKEY hSubKey;
    WCHAR szNameBuf[MAX_PATH], *lpszName = szNameBuf;

    TRACE("(hkey=%p,%p %s)\n", hKey, lpszSubKey, debugstr_w(lpszSubKey));

    Status = MapDefaultKey(&KeyHandle,
                           hKey);
    if (!NT_SUCCESS(Status))
    {
        return RtlNtStatusToDosError(Status);
    }

    hSubKey = KeyHandle;

    if(lpszSubKey)
    {
        ret = RegOpenKeyExW(KeyHandle, lpszSubKey, 0, KEY_READ, &hSubKey);
        if (ret)
        {
            ClosePredefKey(KeyHandle);
            return ret;
        }
    }

    /* Get highest length for keys, values */
    ret = RegQueryInfoKeyW(hSubKey, NULL, NULL, NULL, NULL,
            &dwMaxSubkeyLen, NULL, NULL, &dwMaxValueLen, NULL, NULL, NULL);
    if (ret) goto cleanup;

    dwMaxSubkeyLen++;
    dwMaxValueLen++;
    dwMaxLen = max(dwMaxSubkeyLen, dwMaxValueLen);
    if (dwMaxLen > sizeof(szNameBuf)/sizeof(WCHAR))
    {
        /* Name too big: alloc a buffer for it */
        if (!(lpszName = RtlAllocateHeap( RtlGetProcessHeap(), 0, dwMaxLen*sizeof(WCHAR))))
        {
            ret = ERROR_NOT_ENOUGH_MEMORY;
            goto cleanup;
        }
    }


    /* Recursively delete all the subkeys */
    while (TRUE)
    {
        dwSize = dwMaxLen;
        if (RegEnumKeyExW(hSubKey, 0, lpszName, &dwSize, NULL,
                          NULL, NULL, NULL)) break;

        ret = RegDeleteTreeW(hSubKey, lpszName);
        if (ret) goto cleanup;
    }

    if (lpszSubKey)
        ret = RegDeleteKeyW(KeyHandle, lpszSubKey);
    else
        while (TRUE)
        {
            dwSize = dwMaxLen;
            if (RegEnumValueW(KeyHandle, 0, lpszName, &dwSize,
                  NULL, NULL, NULL, NULL)) break;

            ret = RegDeleteValueW(KeyHandle, lpszName);
            if (ret) goto cleanup;
        }

cleanup:
    /* Free buffer if allocated */
    if (lpszName != szNameBuf)
        RtlFreeHeap( RtlGetProcessHeap(), 0, lpszName);
    if(lpszSubKey)
        RegCloseKey(hSubKey);

    ClosePredefKey(KeyHandle);

    return ret;
}


/************************************************************************
 *  RegDeleteTreeA
 *
 * @implemented
 */
LONG WINAPI
RegDeleteTreeA(IN HKEY hKey,
               IN LPCSTR lpSubKey  OPTIONAL)
{
    UNICODE_STRING SubKeyName = { 0, 0, NULL };
    LONG Ret;

    if (lpSubKey != NULL &&
        !RtlCreateUnicodeStringFromAsciiz(&SubKeyName,
                                          (LPSTR)lpSubKey))
    {
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    Ret = RegDeleteTreeW(hKey,
                         SubKeyName.Buffer);

    RtlFreeUnicodeString(&SubKeyName);

    return Ret;
}
