/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     Test for Imagelist behavior when called from multiple versions
 * COPYRIGHT:   Copyright 2018 Mark Jansen (mark.jansen@reactos.org)
 */

#include "wine/test.h"
#include <stdio.h>
#include <windows.h>
#include <commctrl.h>
#include <shlwapi.h>

extern IMAGE_DOS_HEADER __ImageBase;

typedef HIMAGELIST (WINAPI *CreateFn)(INT cx, INT cy, UINT flags, INT cInitial, INT cGrow);
typedef int (WINAPI *AddFn)(HIMAGELIST himl, HBITMAP hbmImage, HBITMAP hbmMask);
typedef BOOL (WINAPI *DrawIndirectFn)(IMAGELISTDRAWPARAMS *pimldp);
typedef BOOL (WINAPI *DestroyFn)(HIMAGELIST himl);

static int module_version(HMODULE mod)
{
    DLLVERSIONINFO info = { sizeof(info) };
    HRESULT (WINAPI *DllGetVersion)(DLLVERSIONINFO *pdvi);
    HRESULT hr;

    if (!mod)
        return -2;

    DllGetVersion = (void*)GetProcAddress(mod, "DllGetVersion");
    if (DllGetVersion == NULL)
        return -1;

    hr = DllGetVersion(&info);
    if (!SUCCEEDED(hr))
        return hr;

    return info.dwMajorVersion;
}

CreateFn createV5, createV6;
AddFn addV5, addV6;
DrawIndirectFn drawV5, drawV6;
DestroyFn destroyV5, destroyV6;

static void mix_versions(void)
{
    HIMAGELIST iml5 = createV5(16, 16, ILC_COLOR, 0, 5);
    HIMAGELIST iml6 = createV6(16, 16, ILC_COLOR, 0, 5);
    IMAGELISTDRAWPARAMS ildp = {0};
    BOOL Result;
    int index;

    ok(iml5 != NULL, "ImageList_Create failed\n");
    ok(iml6 != NULL, "ImageList_Create failed\n");

    /* Calling v6 add on v5 list is no problem */
    index = addV6(iml5, LoadBitmap((HMODULE)&__ImageBase, MAKEINTRESOURCE(6)), NULL);
    ok(index == 0, "ImageList_Add failed: %lu\n", GetLastError());
    
    /* Calling v5 add on v6 list is no problem */
    index = addV5(iml6, LoadBitmap((HMODULE)&__ImageBase, MAKEINTRESOURCE(6)), NULL);
    ok(index == 0, "ImageList_Add failed: %lu\n", GetLastError());

    if (iml5 && iml6)
    {
        /* First run all tests with himl being a V5 list. */
        ildp.cbSize = IMAGELISTDRAWPARAMS_V3_SIZE;
        ildp.himl = iml5;
        ildp.hdcDst = CreateCompatibleDC(NULL);

        Result = drawV5(&ildp);
        ok(Result, "ImageList_DrawIndirect failed: %lu\n", GetLastError());

        Result = drawV6(&ildp);
        ok(Result, "ImageList_DrawIndirect failed: %lu\n", GetLastError());

        ildp.cbSize = sizeof(ildp);

        Result = drawV5(&ildp);
        ok(Result, "ImageList_DrawIndirect failed: %lu\n", GetLastError());

        Result = drawV6(&ildp);
        ok(Result, "ImageList_DrawIndirect failed: %lu\n", GetLastError());

        /* Now Re-run all tests against a V6 list */
        ildp.cbSize = IMAGELISTDRAWPARAMS_V3_SIZE;
        ildp.himl = iml6;

        Result = drawV5(&ildp);
        ok(Result, "ImageList_DrawIndirect failed: %lu\n", GetLastError());

        Result = drawV6(&ildp);
        ok(Result, "ImageList_DrawIndirect failed: %lu\n", GetLastError());

        ildp.cbSize = sizeof(ildp);

        Result = drawV5(&ildp);
        ok(Result, "ImageList_DrawIndirect failed: %lu\n", GetLastError());

        Result = drawV6(&ildp);
        ok(Result, "ImageList_DrawIndirect failed: %lu\n", GetLastError());

        /* Show that a v5 function can destroy a v6 list */
        Result = destroyV5(iml6);
        ok(Result != FALSE, "Expected imagelist to be destroyed!\n");
        if (Result)
            iml6 = NULL;

        /* Show that a v6 function can destroy a v5 list */
        Result = destroyV6(iml5);
        ok(Result != FALSE, "Expected imagelist to be destroyed!\n");
        if (Result)
            iml5 = NULL;

        DeleteDC(ildp.hdcDst);
    }
    if (iml5)
    {
        ok(0, "Cleanup needed\n");
        destroyV5(iml5);
    }
    if (iml6)
    {
        ok(0, "Cleanup needed\n");
        destroyV6(iml6);
    }
}


static void imagelist_versionedtests(HANDLE hActv5, HANDLE hActv6)
{
    HMODULE v5, v6, mod;
    CreateFn Create;
    ULONG_PTR ulCookie5, ulCookie6;
    BOOL fOK;
    int ver;

    /* Enable v5 manifest */
    fOK = ActivateActCtx(hActv5, &ulCookie5);

    ok(fOK != FALSE, "ActivateActCtx failed: %lu\n", GetLastError());
    v5 = LoadLibraryA("comctl32.dll");
    ok(v5 != 0, "LoadLibraryA failed: %lu\n", GetLastError());

    ver = module_version(v5);
    ok_int(ver, 5);

    createV5 = (CreateFn)GetProcAddress(v5, "ImageList_Create");
    ok(createV5 != 0, "GetProcAddress failed: %lu\n", GetLastError());

    addV5 = (AddFn)GetProcAddress(v5, "ImageList_Add");
    ok(addV5 != 0, "GetProcAddress failed: %lu\n", GetLastError());

    drawV5 = (DrawIndirectFn)GetProcAddress(v5, "ImageList_DrawIndirect");
    ok(drawV5 != 0, "GetProcAddress failed: %lu\n", GetLastError());

    destroyV5 = (DestroyFn)GetProcAddress(v5, "ImageList_Destroy");
    ok(destroyV5 != 0, "GetProcAddress failed: %lu\n", GetLastError());

    //mix_versions(createV5, drawV5, destroyV5, NULL, NULL);

    mod = GetModuleHandleA("comctl32.dll");
    ok(v5 == mod, "GetModuleHandleA failed: %lu\n", GetLastError());

    Create = (CreateFn)GetProcAddress(mod, "ImageList_Create");
    ok(Create == createV5, "GetProcAddress got %p instead of %p: %lu\n", Create, createV5, GetLastError());

    /* Enable v6 manifest */
    fOK = ActivateActCtx(hActv6, &ulCookie6);

    ok(fOK != FALSE, "ActivateActCtx failed: %lu\n", GetLastError());
    v6 = LoadLibraryA("comctl32.dll");
    ok(v6 != 0, "LoadLibraryA failed: %lu\n", GetLastError());

    ver = module_version(v6);
    ok_int(ver, 6);

    ok(v5 != v6, "Expected different modules\n");

    createV6 = (CreateFn)GetProcAddress(v6, "ImageList_Create");
    ok(createV6 != 0, "GetProcAddress failed: %lu\n", GetLastError());

    addV6 = (AddFn)GetProcAddress(v6, "ImageList_Add");
    ok(addV6 != 0, "GetProcAddress failed: %lu\n", GetLastError());

    drawV6 = (DrawIndirectFn)GetProcAddress(v6, "ImageList_DrawIndirect");
    ok(drawV6 != 0, "GetProcAddress failed: %lu\n", GetLastError());

    destroyV6 = (DestroyFn)GetProcAddress(v6, "ImageList_Destroy");
    ok(destroyV6 != 0, "GetProcAddress failed: %lu\n", GetLastError());

    ok(createV5 != createV6, "Expected different functions\n");
    ok(addV5 != addV6, "Expected different functions\n");
    ok(drawV5 != drawV6, "Expected different functions\n");
    ok(destroyV5 != destroyV6, "Expected different functions\n");

    /* Run tests under v6 context */
    mix_versions();

    mod = GetModuleHandleA("comctl32.dll");
    ok(v6 == mod, "GetModuleHandleA failed: %lu\n", GetLastError());

    Create = (CreateFn)GetProcAddress(mod, "ImageList_Create");
    ok(Create == createV6, "GetProcAddress got %p instead of %p: %lu\n", Create, createV6, GetLastError());

    Create = (CreateFn)GetProcAddress(v5, "ImageList_Create");
    ok(Create == createV5, "GetProcAddress got %p instead of %p: %lu\n", Create, createV5, GetLastError());

    /* Deactivate v6 */
    DeactivateActCtx(0, ulCookie6);

    mod = GetModuleHandleA("comctl32.dll");
    ok(v5 == mod, "GetModuleHandleA failed: %lu\n", GetLastError());

    Create = (CreateFn)GetProcAddress(mod, "ImageList_Create");
    ok(Create == createV5, "GetProcAddress got %p instead of %p: %lu\n", Create, createV5, GetLastError());

    /* Run tests under v5 context */
    mix_versions();

    /* Deactivate v5 */
    DeactivateActCtx(0, ulCookie5);

    /* Run tests under default context */
    mix_versions();
}


START_TEST(imagelist)
{
    ACTCTXW actctx = { sizeof(actctx) };
    WCHAR Buffer[MAX_PATH];
    HANDLE hActv5, hActv6;

    GetModuleFileNameW(NULL, Buffer, _countof(Buffer));

    actctx.dwFlags = ACTCTX_FLAG_RESOURCE_NAME_VALID;
    actctx.lpSource = Buffer;
    actctx.lpResourceName = MAKEINTRESOURCEW(9911);
    hActv5 = CreateActCtxW(&actctx);
    ok(hActv5 != INVALID_HANDLE_VALUE, "CreateActCtxA failed: %lu\n", GetLastError());

    actctx.lpResourceName = MAKEINTRESOURCEW(9912);
    hActv6 = CreateActCtxW(&actctx);
    ok(hActv6 != INVALID_HANDLE_VALUE, "CreateActCtxA failed: %lu\n", GetLastError());

    if (hActv5 != INVALID_HANDLE_VALUE && hActv6 != INVALID_HANDLE_VALUE)
        imagelist_versionedtests(hActv5, hActv6);
    else
        skip("Manifest not created\n");

    if (hActv6 != INVALID_HANDLE_VALUE)
        ReleaseActCtx(hActv6);
    if (hActv5 != INVALID_HANDLE_VALUE)
        ReleaseActCtx(hActv5);
}
