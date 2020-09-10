1 stdcall -noname SfcInitProt() sfc_os.SfcInitProt
2 stdcall -noname SfcTerminateWatcherThread() sfc_os.SfcTerminateWatcherThread
3 stdcall -noname SfcConnectToServer(long) sfc_os.SfcConnectToServer
4 stdcall -noname SfcClose() sfc_os.SfcClose
5 stdcall -noname SfcFileException(long ptr long) sfc_os.SfcFileException
6 stdcall -noname SfcInitiateScan() sfc_os.SfcInitiateScan
7 stdcall -noname SfcInstallProtectedFiles() sfc_os.SfcInstallProtectedFiles
8 stdcall -noname SfpInstallCatalog()
9 stdcall -noname SfpDeleteCatalog()
@ stdcall SRSetRestorePoint(ptr ptr) SRSetRestorePointA
@ stdcall SRSetRestorePointA(ptr ptr)
@ stdcall SRSetRestorePointW(ptr ptr)
@ stdcall SfcGetNextProtectedFile(ptr ptr) sfc_os.SfcGetNextProtectedFile
@ stdcall SfcIsFileProtected(ptr wstr) sfc_os.SfcIsFileProtected
@ stdcall SfcWLEventLogoff(ptr) sfc_os.SfcWLEventLogoff
@ stdcall SfcWLEventLogon(ptr) sfc_os.SfcWLEventLogon
@ stdcall SfpVerifyFile(str str long)
