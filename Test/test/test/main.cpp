#include <Windows.h>
#include <conio.h>
#include <iostream>
#include <filesystem>
#include <TlHelp32.h>

#include "Injector.hpp"


#define SETNTOPENPROCESS		1
//#define STEALTHPROCESS		1
#define NTVIRTUALALLOCEXDEBUG	1

void ErrorMessage(const char* msg);
void Hooking(const char* dllName, const char* procName, const BYTE* buffer, const int bufferSize, BYTE* oriBuffer = NULL);
BOOL NewCreateProcessA(LPCSTR appName, LPSTR cmdLine, LPSECURITY_ATTRIBUTES procAttributes, LPSECURITY_ATTRIBUTES threadAttributes, BOOL inHeritHandle, DWORD flags, LPVOID env, LPCSTR currentDir, LPSTARTUPINFOA startupInfo, LPPROCESS_INFORMATION procInfo);
BOOL WINAPI NewCreateProcessW(_In_opt_ LPCWSTR appName, _Inout_opt_ LPWSTR cmdLine, _In_opt_ LPSECURITY_ATTRIBUTES procAttributes, _In_opt_ LPSECURITY_ATTRIBUTES threadAttributes, _In_ BOOL inHeritHandle, _In_ DWORD flags, _In_opt_ LPVOID env, _In_opt_ LPCWSTR currentDir, _In_ LPSTARTUPINFOW startupInfo, _Out_ LPPROCESS_INFORMATION procInfo);



typedef BOOL(WINAPI* procA)(LPCSTR appName, LPSTR cmdLine, LPSECURITY_ATTRIBUTES procAttributes, LPSECURITY_ATTRIBUTES threadAttributes, BOOL inHeritHandle, DWORD flags, LPVOID env, LPCSTR currentDir, LPSTARTUPINFOA startupInfo, LPPROCESS_INFORMATION procInfo);

typedef BOOL(WINAPI* procW)(_In_opt_ LPCWSTR appName, _Inout_opt_ LPWSTR cmdLine, _In_opt_ LPSECURITY_ATTRIBUTES procAttributes, _In_opt_ LPSECURITY_ATTRIBUTES threadAttributes, _In_ BOOL inHeritHandle, _In_ DWORD flags, _In_opt_ LPVOID env, _In_opt_ LPCWSTR currentDir, _In_ LPSTARTUPINFOW startupInfo, _Out_ LPPROCESS_INFORMATION procInfo);

__kernel_entry NTSTATUS NewNtVirtualAllocEx(
	_In_        HANDLE    ProcessHandle,
	_In_ _Out_	PVOID* BaseAddress,
	_In_        ULONG_PTR ZeroBits,
	_In_ _Out_  PSIZE_T   RegionSize,
	_In_        ULONG     AllocationType,
	_In_        ULONG     Protect
);

#define JMP_BUFFER		6
#define HOOKING_BUFFER	14 //JMP_BUFFER + DWORD64

TCHAR* DLL_PATH = (TCHAR*)L"C:\\Users\\bgyang\\Desktop\\sourcecode\\StealthProcess2\\StealthProcess2.dll";

const char* dllName = "ntdll";
const char* procName = "NtAllocateVirtualMemory";
DWORD64 procAddr = (DWORD64)NewNtVirtualAllocEx;

BYTE originBuffer[HOOKING_BUFFER] = { 0, };

INJECTOR* ijt = nullptr;


#ifdef NTVIRTUALALLOCEXDEBUG
typedef __kernel_entry NTSYSCALLAPI NTSTATUS (*pNtVirtualAllocEx)(
	_In_       HANDLE    ProcessHandle,
	_In_ _Out_ PVOID* BaseAddress,
	_In_       ULONG_PTR ZeroBits,
	_In_ _Out_  PSIZE_T   RegionSize,
	_In_       ULONG     AllocationType,
	_In_       ULONG     Protect
);
__kernel_entry NTSTATUS NewNtVirtualAllocEx(
	_In_        HANDLE    ProcessHandle,
	_In_ _Out_	PVOID* BaseAddress,
	_In_        ULONG_PTR ZeroBits,
	_In_ _Out_  PSIZE_T   RegionSize,
	_In_        ULONG     AllocationType,
	_In_        ULONG     Protect
	) {
	Hooking(dllName, procName, originBuffer, HOOKING_BUFFER);
	auto proc = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory");
	auto result = ((pNtVirtualAllocEx)proc)(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
	return result;

};
#endif

#ifdef STEALTHPROCESS
#define JMP_COMMAND_PADDING				6
#define SYSTEM_PROCESS_INFORMATION		0x05
#define STATUS_SEVERITY_SUCCESS			0x0

typedef BYTE	SYSTEM_INFORMATION_CLASS;

typedef NTSTATUS(*NewQsi)(_In_ BYTE SYSTEM_INFORMATION_CLASS, _In_ _Out_ void* sysInfo, _In_ ULONG sysInfoLen, _Out_ ULONG* retLen);


void* gProcAddr;
const wchar_t* oriProcName = L"notepad.exe";
BYTE* gOriBuffer = NULL, * gBuffer = NULL;
int gOriSize = 0, gBufferSize = 0;

#endif

#ifdef SETNTOPENPROCESS
typedef struct _OBJECT_ATTRIBUTES64 {
	ULONG Length;
	ULONG64 RootDirectory;
	ULONG64 ObjectName;
	ULONG Attributes;
	ULONG64 SecurityDescriptor;
	ULONG64 SecurityQualityOfService;
} OBJECT_ATTRIBUTES64;
typedef OBJECT_ATTRIBUTES64* POBJECT_ATTRIBUTES64;
typedef CONST OBJECT_ATTRIBUTES64* PCOBJECT_ATTRIBUTES64;

typedef struct _CLIENT_ID
{
	PVOID UniqueProcess;
	PVOID UniqueThread;
} CLIENT_ID, * PCLIENT_ID;


typedef __kernel_entry NTSYSAPI NTSTATUS(*poriNtOpenProcess)(_Out_ PHANDLE processHandle, _In_ ACCESS_MASK accessMask, _In_ PCOBJECT_ATTRIBUTES64 obaPoint, _In_ PCLIENT_ID cidPoint);

__kernel_entry  NTSTATUS NewNtOpenProcess(_Out_ PHANDLE processHandle, _In_ ACCESS_MASK accessMask, _In_ PCOBJECT_ATTRIBUTES64 obaPoint, _In_ PCLIENT_ID cidPoint) {
	return TRUE;
};

BOOL SetPrivileage(HANDLE hToken, const wchar_t* privilegeName, BOOL enable);
#endif

int main(void) {
	const BYTE jmpCode[JMP_BUFFER] = { 0xff, 0x25, 0, };
	BYTE hookingCode[HOOKING_BUFFER] = { 0, };

	memcpy_s(hookingCode, JMP_BUFFER, jmpCode, JMP_BUFFER);
	memcpy_s(&hookingCode[JMP_BUFFER], sizeof(DWORD64), &procAddr, sizeof(DWORD64));

	//Hooking(dllName, procName, hookingCode, HOOKING_BUFFER, originBuffer);

	STARTUPINFOA startInfo;
	PROCESS_INFORMATION pi;
	char exeName[MAX_PATH] = { 0, };

	memset(&startInfo, 0, sizeof(STARTUPINFOA));
	memset(&pi, 0, sizeof(PROCESS_INFORMATION));
	GetModuleFileNameA(GetModuleHandleA(NULL), exeName, MAX_PATH);

	//CreateProcessA(exeName, NULL, NULL, NULL, TRUE, NULL, NULL, NULL, &startInfo, &pi);


#ifdef	SETNTOPENPROCESS
	//NT Test
		//OpenProcess(PROCESS_ALL_ACCESS, FALSE, 19300);
	auto ntdll = GetModuleHandleA("ntdll.dll");
	if (ntdll == NULL) exit(1);

	auto pNtOpenProcess = GetProcAddress(ntdll, "NtOpenProcess");
	if (pNtOpenProcess == NULL) exit(1);

	//const BYTE jmpCode[JMP_BUFFER] = { 0xff, 0x25, 0, };
	BYTE ntOPHookingCode[HOOKING_BUFFER] = { 0, };
	BYTE ntOPOriginCode[HOOKING_BUFFER] = { 0, };
	DWORD64 pNtOPAddr = (DWORD64)&NewNtOpenProcess;

	memcpy_s(ntOPHookingCode, JMP_BUFFER, jmpCode, JMP_BUFFER);
	memcpy_s(&ntOPHookingCode[JMP_BUFFER], sizeof(DWORD64), &pNtOPAddr, sizeof(DWORD64));


	//Hooking("ntdll.dll", "NtOpenProcess", ntOPHookingCode, HOOKING_BUFFER, ntOPOriginCode);

	HANDLE token = NULL;
	if(!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &token))ErrorMessage("OpenProcessToken");;
	if (!SetPrivileage(token, SE_DEBUG_NAME, TRUE)) ErrorMessage("SetPrivilege");

	//auto tmrHandle = OpenProcess(PROCESS_ALL_ACCESS, NULL, 3604);
	auto tmrHandle = OpenProcess(PROCESS_ALL_ACCESS, NULL, 16704);
	Hooking(dllName, procName, hookingCode, HOOKING_BUFFER, originBuffer);
	auto result= VirtualAllocEx(tmrHandle, NULL, 512, MEM_COMMIT, PAGE_READWRITE);
	printf_s("result : %p \n", result);
#ifdef STEALTHPROCESS
	DWORD64 offsetAddr = (DWORD64)NewQuerySystemInformation;
	int totalSize = gBufferSize = JMP_COMMAND_PADDING + sizeof(offsetAddr);
	gBuffer = new BYTE[totalSize];
	memcpy_s(gBuffer, JMP_COMMAND_PADDING, jmpCode, JMP_COMMAND_PADDING);
	memcpy_s(&gBuffer[JMP_COMMAND_PADDING], sizeof(DWORD64), &offsetAddr, sizeof(DWORD64));

	Hooking("ntdll.dll", "NtQuerySystemInformation", gBuffer, gBufferSize, gOriBuffer);
#endif
#endif
	

#ifdef TERMINATEPROCESS
	const wchar_t* tProcessName = L"Test.exe";

	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (snap == NULL) ErrorMessage("snap");

	PROCESSENTRY32 pe32 = { 0, };
	pe32.dwSize = sizeof(PROCESSENTRY32);

	Process32First(snap, &pe32);
	pe32.szExeFile;

	HANDLE tProcessHandle = NULL;

	while (1) {
		auto result = _wcsicmp(tProcessName, pe32.szExeFile);
		if (result == 0) {
			tProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
			TerminateProcess(tProcessHandle, 0);
		};

		result = Process32Next(snap, &pe32);
		if (result < 0) break;
		
		if (_kbhit()) break;
	};

	printf_s("Seuccess to Terminate Process\n");
#endif

	

	return 0;
};

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
	FARPROC pFunc;

	Hooking(dllName, procName, originBuffer, HOOKING_BUFFER);
	CreateProcessA(appName, cmdLine, procAttributes, threadAttributes, inHeritHandle, flags, env, currentDir, startupInfo, procInfo);

	ijt = new INJECTOR(procInfo->dwProcessId, PROCESS_ID);
	if (ijt == nullptr) ErrorMessage("Injector");

	ijt->SetDLLPath(DLL_PATH);
	ijt->Injection();

	return TRUE;
};

BOOL WINAPI NewCreateProcessW(_In_opt_ LPCWSTR appName, _Inout_opt_ LPWSTR cmdLine, _In_opt_ LPSECURITY_ATTRIBUTES procAttributes, _In_opt_ LPSECURITY_ATTRIBUTES threadAttributes, _In_ BOOL inHeritHandle, _In_ DWORD flags, _In_opt_ LPVOID env, _In_opt_ LPCWSTR currentDir, _In_ LPSTARTUPINFOW startupInfo, _Out_ LPPROCESS_INFORMATION procInfo) {

	return TRUE;
};

BOOL SetPrivileage(HANDLE hToken,const wchar_t* privilegeName, BOOL enable) {
	
	TOKEN_PRIVILEGES tp = { 0, };
	LUID luid;

	if (!LookupPrivilegeValueW(NULL, privilegeName, &luid)) {
		printf_s("LookupPrivilegeValue\n");
		return false;
	};

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (enable) tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else tp.Privileges[0].Attributes = 0;

	if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) ErrorMessage("AdjustTokenPrivileges");
	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
		printf_s("Token dosen't have Privilege\n");
		return false;
	};

	return TRUE;
};

#ifdef STEALTHPROCESS
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
	char procName[MAX_PATH] = { 0, };
	int result;

	Hooking("ntdll.dll", "NtQuerySystemInformation", gOriBuffer, gOriSize);
	status = ((NewQsi)gProcAddr) (sysInfoClass, sysInfo, sysInfoLen, retLen);
	if (status != STATUS_SEVERITY_SUCCESS) goto __NEWQSI_END;

	if (sysInfoClass == SYSTEM_PROCESS_INFORMATION) {
		pCur = (PSystemPrcoessInforMation)sysInfo;

		while (TRUE) {
			if (pCur->Reserved2[1] != NULL) {
				result = _wcsicmp((PWSTR)(pCur->Reserved2[1]), oriProcName);
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
	Hooking("ntdll.dll", "ZwQuerySystemInformation", gBuffer, gBufferSize);
	return status;
};
#endif