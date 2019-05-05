/*
 * PROJECT:     ReactOS Zip Shell Extension
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     Create a zip file
 * COPYRIGHT:   Copyright 2019 Mark Jansen (mark.jansen@reactos.org)
 */

class CZipCreator
{
protected:
    CZipCreator();
public:
    virtual ~CZipCreator();
    virtual void AddFile(CStringW& File) = 0;

    static CZipCreator* create();
    static void runThread(CZipCreator* instance);
};

