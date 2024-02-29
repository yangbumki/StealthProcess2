// dllmain.cpp : DLL 애플리케이션의 진입점을 정의합니다.
#include "pch.h"

#define JMP_BUFFER		6
#define HOOKING_BUFFER	14 //JMP_BUFFER + DWORD64

void ErrorMessage(const char* msg);
void Hooking(const char* dllName, const char* procName, const BYTE* buffer, const int bufferSize, BYTE* oriBuffer = NULL);
BOOL NewCreateProcessA(LPCSTR appName, LPSTR cmdLine, LPSECURITY_ATTRIBUTES procAttributes, LPSECURITY_ATTRIBUTES threadAttributes, BOOL inHeritHandle, DWORD flags, LPVOID env, LPCSTR currentDir, LPSTARTUPINFOA startupInfo, LPPROCESS_INFORMATION procInfo);
BOOL WINAPI NewCreateProcessW(_In_opt_ LPCWSTR appName, _Inout_opt_ LPWSTR cmdLine, _In_opt_ LPSECURITY_ATTRIBUTES procAttributes, _In_opt_ LPSECURITY_ATTRIBUTES threadAttributes, _In_ BOOL inHeritHandle, _In_ DWORD flags, _In_opt_ LPVOID env, _In_opt_ LPCWSTR currentDir, _In_ LPSTARTUPINFOW startupInfo, _Out_ LPPROCESS_INFORMATION procInfo);

typedef BOOL(WINAPI* procA)(LPCSTR appName, LPSTR cmdLine, LPSECURITY_ATTRIBUTES procAttributes, LPSECURITY_ATTRIBUTES threadAttributes, BOOL inHeritHandle, DWORD flags, LPVOID env, LPCSTR currentDir, LPSTARTUPINFOA startupInfo, LPPROCESS_INFORMATION procInfo);

typedef BOOL(WINAPI* procW)(_In_opt_ LPCWSTR appName, _Inout_opt_ LPWSTR cmdLine, _In_opt_ LPSECURITY_ATTRIBUTES procAttributes, _In_opt_ LPSECURITY_ATTRIBUTES threadAttributes, _In_ BOOL inHeritHandle, _In_ DWORD flags, _In_opt_ LPVOID env, _In_opt_ LPCWSTR currentDir, _In_ LPSTARTUPINFOW startupInfo, _Out_ LPPROCESS_INFORMATION procInfo);

TCHAR* DLL_PATH = (TCHAR*)L"C:\\Users\\bgyang\\Desktop\\sourcecode\\StealthProcess2\\StealthProcess2.dll";

const char* dllName = "kernelbase";
const char* procName = "CreateProcessA";
DWORD64 procAddr = (DWORD64)NewCreateProcessA;

const BYTE jmpCode[JMP_BUFFER] = { 0xff, 0x25, 0, };
BYTE originBuffer[HOOKING_BUFFER] = { 0, };
BYTE hookingCode[HOOKING_BUFFER] = { 0, };

INJECTOR* ijt = nullptr;

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        memcpy_s(hookingCode, JMP_BUFFER, jmpCode, JMP_BUFFER);
        memcpy_s(&hookingCode[JMP_BUFFER], sizeof(DWORD64), &procAddr, sizeof(DWORD64));

		Hooking(dllName, procName, hookingCode, HOOKING_BUFFER, originBuffer);
		break;

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

void ErrorMessage(const char* msg) {
	MessageBoxA(NULL, msg, "ERROR", NULL);
	exit(1);
};


void Hooking(const char* dllName, const char* procName, const BYTE* buffer, const int bufferSize, BYTE* oriBuffer) {
	HMODULE oriDll = NULL;
	void* oriFunc = NULL;
	DWORD oldProtect = 0;

	oriDll = GetModuleHandleA(dllName);
	if (oriDll == NULL) ErrorMessage("oriDll");

	oriFunc = GetProcAddress(oriDll, procName);
	if (oriFunc == NULL) ErrorMessage("oriFunc");


	if (!VirtualProtect(oriFunc, bufferSize, PAGE_EXECUTE_READWRITE, &oldProtect)) ErrorMessage("VirtualProtect");

	if (oriBuffer != NULL) memcpy_s(oriBuffer, bufferSize, oriFunc, bufferSize);
	memcpy_s(oriFunc, bufferSize, buffer, bufferSize);

	if (!VirtualProtect(oriFunc, bufferSize, oldProtect, &oldProtect));
};

BOOL NewCreateProcessA(LPCSTR appName, LPSTR cmdLine, LPSECURITY_ATTRIBUTES procAttributes, LPSECURITY_ATTRIBUTES threadAttributes, BOOL inHeritHandle, DWORD flags, LPVOID env, LPCSTR currentDir, LPSTARTUPINFOA startupInfo, LPPROCESS_INFORMATION procInfo) {
	Hooking(dllName, procName, originBuffer, HOOKING_BUFFER);
	auto result = CreateProcessA(appName, cmdLine, procAttributes, threadAttributes, inHeritHandle, flags, env, currentDir, startupInfo, procInfo);
	Hooking(dllName, procName, hookingCode, HOOKING_BUFFER);

	if (!result) return FALSE;

	ijt = new INJECTOR(procInfo->dwProcessId, PROCESS_ID);
	if (ijt == nullptr) ErrorMessage("Injector");

	ijt->SetDLLPath(DLL_PATH);
	ijt->Injection();

	return TRUE;
};

BOOL WINAPI NewCreateProcessW(_In_opt_ LPCWSTR appName, _Inout_opt_ LPWSTR cmdLine, _In_opt_ LPSECURITY_ATTRIBUTES procAttributes, _In_opt_ LPSECURITY_ATTRIBUTES threadAttributes, _In_ BOOL inHeritHandle, _In_ DWORD flags, _In_opt_ LPVOID env, _In_opt_ LPCWSTR currentDir, _In_ LPSTARTUPINFOW startupInfo, _Out_ LPPROCESS_INFORMATION procInfo) {
	
	Hooking(dllName, procName, originBuffer, HOOKING_BUFFER);
	auto result = CreateProcessW(appName, cmdLine, procAttributes, threadAttributes, inHeritHandle, flags, env, currentDir, startupInfo, procInfo);
	Hooking(dllName, procName, hookingCode, HOOKING_BUFFER);

	if (!result) return FALSE;

	ijt = new INJECTOR(procInfo->dwProcessId, PROCESS_ID);
	if (ijt == nullptr) ErrorMessage("Injector");

	ijt->SetDLLPath(DLL_PATH);
	ijt->Injection();

	return TRUE;
};
