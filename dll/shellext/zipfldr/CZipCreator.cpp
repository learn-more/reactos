/*
 * PROJECT:     ReactOS Zip Shell Extension
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     Create a zip file
 * COPYRIGHT:   Copyright 2019 Mark Jansen (mark.jansen@reactos.org)
 */


#include "precomp.h"
#include "minizip/zip.h"


class CZipCreatorImpl :
    public CZipCreator
{
    virtual void AddFile(CStringW& File) override
    {

    }


    void run()
    {
        zipFile zf;

        const void* pathName = NULL;
        zf = zipOpen2_64(pathName, APPEND_STATUS_CREATE, NULL, &g_FFunc);

        for (UINT n = 0; n < 100; ++n)
        {
            int err, zip64;
            unsigned long crcFile = 0;
            zip_fileinfo zi = {0};
            int opt_compress_level = Z_DEFAULT_COMPRESSION;
            const char* password = NULL;

            const char* relativeFileInZip = "some/file";
            const char* originalFileName = "c:\\some_\\file";

            filetime(originalFileName, &zi.tmz_date, &zi.dosDate);

            zip64 = isLargeFile(originalFileName);
            if (password)
                err = getFileCrc(originalFileName, buf, size_buf, &crcFile);

            err = zipOpenNewFileInZip3_64(zf, relativeFileInZip,&zi,
                                          NULL,0,NULL,0,NULL /* comment*/,
                                          (opt_compress_level != 0) ? Z_DEFLATED : 0,
                                          opt_compress_level,0,
                                          -MAX_WBITS, DEF_MEM_LEVEL, Z_DEFAULT_STRATEGY,
                                          password, crcFile, zip64);

            //https://github.com/madler/zlib/blob/master/contrib/minizip/minizip.c
        }

        Sleep(10000);

    }

public:
    CZipCreatorImpl()
    {

    }

    static DWORD WINAPI s_run(LPVOID lpArg)
    {
        CZipCreatorImpl* impl = (CZipCreatorImpl*)lpArg;
        impl->run();
        delete impl;
        return 0;
    }
};


CZipCreator::CZipCreator()
{
    InterlockedIncrement(&g_ModuleRefCnt);
}

CZipCreator::~CZipCreator()
{
    InterlockedDecrement(&g_ModuleRefCnt);
}


CZipCreator* CZipCreator::create()
{
    return new CZipCreatorImpl();
}

void CZipCreator::runThread(CZipCreator* instance)
{
    HANDLE hThread = CreateThread(NULL, 0, CZipCreatorImpl::s_run, instance, 0, NULL);
    if (hThread)
    {
        CloseHandle(hThread);
    }
    else
    {
        delete instance;
    }
}

