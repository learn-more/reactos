#include "../advapi32.h"

#include <winuser.h>
//#include <wine/debug.h>
//#include <wine/unicode.h>

//WINE_DEFAULT_DEBUG_CHANNEL(reg);

/************************************************************************
 *  RegSetKeyValueW
 *
 * @implemented
 */
LONG WINAPI
RegSetKeyValueW(IN HKEY hKey,
                IN LPCWSTR lpSubKey  OPTIONAL,
                IN LPCWSTR lpValueName  OPTIONAL,
                IN DWORD dwType,
                IN LPCVOID lpData  OPTIONAL,
                IN DWORD cbData)
{
#if 0
    HANDLE KeyHandle, CurKey, SubKeyHandle = NULL;
    NTSTATUS Status;
    LONG Ret;

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
                           KEY_SET_VALUE,
                           &ObjectAttributes);
        if (!NT_SUCCESS(Status))
        {
            Ret = RtlNtStatusToDosError(Status);
            goto Cleanup;
        }

        CurKey = SubKeyHandle;
    }
    else
        CurKey = KeyHandle;

    Ret = RegSetValueExW(CurKey,
                         lpValueName,
                         0,
                         dwType,
                         lpData,
                         cbData);

    if (SubKeyHandle != NULL)
    {
        NtClose(SubKeyHandle);
    }

Cleanup:
    ClosePredefKey(KeyHandle);

    return Ret;
#else
    HKEY hSubKey = NULL;
    DWORD ret;

    //TRACE("(%p,%s,%s,%d,%p,%d)\n", hKey, debugstr_w(lpSubKey), debugstr_w(lpValueName), dwType, lpData, cbData );

    if (lpSubKey && lpSubKey[0]) /* need to create the subkey */
    {
        if ((ret = RegCreateKeyW(hKey, lpSubKey, &hSubKey)) != ERROR_SUCCESS)
            return ret;
        hKey = hSubKey;
    }

    ret = RegSetValueExW(hKey, lpValueName, 0, dwType, (const BYTE *)lpData, cbData);
    if (hSubKey)
        RegCloseKey(hSubKey);
    return ret;
#endif
}


/************************************************************************
 *  RegSetKeyValueA
 *
 * @implemented
 */
LONG WINAPI
RegSetKeyValueA(IN HKEY hKey,
                IN LPCSTR lpSubKey OPTIONAL,
                IN LPCSTR lpValueName OPTIONAL,
                IN DWORD dwType,
                IN LPCVOID lpData OPTIONAL,
                IN DWORD cbData)
{
#if 0
    HANDLE KeyHandle, CurKey, SubKeyHandle = NULL;
    NTSTATUS Status;
    LONG Ret;

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

        if (!RtlCreateUnicodeStringFromAsciiz(&SubKeyName,
                                              (LPSTR)lpSubKey))
        {
            Ret = ERROR_NOT_ENOUGH_MEMORY;
            goto Cleanup;
        }

        InitializeObjectAttributes(&ObjectAttributes,
                                   &SubKeyName,
                                   OBJ_CASE_INSENSITIVE,
                                   KeyHandle,
                                   NULL);

        Status = NtOpenKey(&SubKeyHandle,
                           KEY_SET_VALUE,
                           &ObjectAttributes);

        RtlFreeUnicodeString(&SubKeyName);

        if (!NT_SUCCESS(Status))
        {
            Ret = RtlNtStatusToDosError(Status);
            goto Cleanup;
        }

        CurKey = SubKeyHandle;
    }
    else
        CurKey = KeyHandle;

    Ret = RegSetValueExA(CurKey,
                         lpValueName,
                         0,
                         dwType,
                         lpData,
                         cbData);

    if (SubKeyHandle != NULL)
    {
        NtClose(SubKeyHandle);
    }

Cleanup:
    ClosePredefKey(KeyHandle);

    return Ret;
#else
    HKEY hSubKey = NULL;
    DWORD ret;

    //TRACE("(%p,%s,%s,%d,%p,%d)\n", hKey, debugstr_a(lpSubKey), debugstr_a(lpValueName), dwType, lpData, cbData );

    if (lpSubKey && lpSubKey[0]) /* need to create the subkey */
    {
        if ((ret = RegCreateKeyA(hKey, lpSubKey, &hSubKey)) != ERROR_SUCCESS)
            return ret;
        hKey = hSubKey;
    }

    ret = RegSetValueExA(hKey, lpValueName, 0, dwType, (const BYTE *)lpData, cbData);
    if (hSubKey)
        RegCloseKey(hSubKey);
    return ret;
#endif
}
