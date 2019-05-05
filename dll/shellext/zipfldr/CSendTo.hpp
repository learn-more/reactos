/*
 * PROJECT:     ReactOS Zip Shell Extension
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     SendTo handler
 * COPYRIGHT:   Copyright 2019 Mark Jansen (mark.jansen@reactos.org)
 */


#define CSENDTO_SUPPORTED_OPERATIONS    (DROPEFFECT_COPY)

class CSendTo:
    public CComCoClass<CSendTo, &CLSID_ZipFolderSendTo>,
    public CComObjectRootEx<CComMultiThreadModelNoCS>,
    public IDropTarget,
    public IPersistFile
{
    CComPtr<IDataObject> m_pDataObject;
    DWORD m_grfKeyState;
    bool m_fCanDragDrop;
    DWORD m_dwEffect;

public:
    CSendTo()
        :m_grfKeyState(0)
        ,m_fCanDragDrop(false)
        ,m_dwEffect(0)
    {
        InterlockedIncrement(&g_ModuleRefCnt);
    }

    ~CSendTo()
    {
        InterlockedDecrement(&g_ModuleRefCnt);
    }


    // *** IShellFolder2 methods ***
    STDMETHODIMP DragEnter(IDataObject *pDataObj, DWORD grfKeyState, POINTL pt, DWORD *pdwEffect)
    {
        m_pDataObject = pDataObj;
        m_grfKeyState = grfKeyState;

        FORMATETC etc = { CF_HDROP, NULL, DVASPECT_CONTENT, -1, TYMED_HGLOBAL };
        if (SUCCEEDED(pDataObj->QueryGetData(&etc)))
        {
            m_fCanDragDrop = true;
        }
        if (pdwEffect)
        {
            if (m_fCanDragDrop)
                m_dwEffect = *pdwEffect & CSENDTO_SUPPORTED_OPERATIONS;

            *pdwEffect = m_dwEffect;
        }

        return S_OK;
    }

    STDMETHODIMP DragOver(DWORD grfKeyState, POINTL pt, DWORD *pdwEffect)
    {
        if (m_grfKeyState != grfKeyState)
        {
            if (pdwEffect)
                m_dwEffect = *pdwEffect & CSENDTO_SUPPORTED_OPERATIONS;

            m_grfKeyState = grfKeyState;
        }
        if (pdwEffect)
            *pdwEffect = m_dwEffect;
        return S_OK;
    }

    STDMETHODIMP DragLeave()
    {
        m_pDataObject.Release();
        return S_OK;
    }

    void DragQuery(HDROP hDrop, UINT Index, CStringW& File)
    {
        UINT Count = ::DragQueryFileW(hDrop, Index, NULL, 0);
        PWSTR pszBuffer = File.GetBuffer(Count);
        Count = ::DragQueryFileW(hDrop, Index, pszBuffer, Count);
        File.ReleaseBufferSetLength(Count);
    }

    STDMETHODIMP Drop(IDataObject *pDataObj, DWORD grfKeyState, POINTL pt, DWORD *pdwEffect)
    {
        HRESULT hr = S_OK;
        m_pDataObject = pDataObj;

        *pdwEffect &= CSENDTO_SUPPORTED_OPERATIONS;
        if (m_fCanDragDrop && *pdwEffect)
        {
            FORMATETC etc = { CF_HDROP, NULL, DVASPECT_CONTENT, -1, TYMED_HGLOBAL };
            STGMEDIUM stg;
            hr = pDataObj->GetData(&etc, &stg);
            if (SUCCEEDED(hr))
            {
                UINT Count = ::DragQueryFileW((HDROP)stg.hGlobal, -1, NULL, 0);

                CZipCreator* zip = CZipCreator::create();

                for (UINT n = 0; n < Count; ++n)
                {
                    CStringW File;
                    DragQuery((HDROP)stg.hGlobal, n, File);
                    zip->AddFile(File);
                }

                ::ReleaseStgMedium(&stg);

                CZipCreator::runThread(zip);
            }
        }
        else
        {
            *pdwEffect = 0;
        }

        DragLeave();
        return hr;
    }



    // *** IPersistFile methods ***
    STDMETHODIMP IsDirty()
    {
        return S_FALSE;
    }
    STDMETHODIMP Load(LPCOLESTR pszFileName, DWORD dwMode)
    {
        return S_OK;
    }
    STDMETHODIMP Save(LPCOLESTR pszFileName, BOOL fRemember)
    {
        return E_FAIL;
    }
    STDMETHODIMP SaveCompleted(LPCOLESTR pszFileName)
    {
        return E_FAIL;
    }
    STDMETHODIMP GetCurFile(LPOLESTR *ppszFileName)
    {
        return E_FAIL;
    }
    // *** IPersist methods ***
    STDMETHODIMP GetClassID(CLSID *pclsid)
    {
        return E_FAIL;
    }


public:
    DECLARE_NO_REGISTRY()   // Handled manually
    DECLARE_NOT_AGGREGATABLE(CSendTo)

    DECLARE_PROTECT_FINAL_CONSTRUCT()

    BEGIN_COM_MAP(CSendTo)
        COM_INTERFACE_ENTRY_IID(IID_IDropTarget, IDropTarget)
        COM_INTERFACE_ENTRY_IID(IID_IPersistFile, IPersistFile)
        COM_INTERFACE_ENTRY_IID(IID_IPersist, IPersist)
    END_COM_MAP()
};

