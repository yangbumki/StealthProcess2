// dllmain.cpp : DLL 애플리케이션의 진입점을 정의합니다.
#include "pch.h"

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    STARTUPINFOA si = { 0, };
    PROCESS_INFORMATION pi = { 0, };

    switch (ul_reason_for_call)
    {
        si.cb = sizeof(STARTUPINFOA);

    case DLL_PROCESS_ATTACH:
        CreateProcessA(NULL, (LPSTR)"procexp64.exe", NULL, NULL, TRUE, NULL, NULL, NULL, &si, &pi);
        Sleep(10000);
        TerminateProcess(pi.hProcess, 0);
       
        break;

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        break;
    }
    return TRUE;
}

