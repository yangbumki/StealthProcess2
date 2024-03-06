#include <Windows.h>
#include <Psapi.h>

#include <iostream>
#include <conio.h>

#include "Injector.hpp"

#define BUFSIZE			1024
#define MODULE_BUF		BUFSIZE

BOOL CALLBACK EnumWindowsProc(_In_ HWND   hwnd, _In_ LPARAM lParam);
BOOL SetRootPrivilege();

INJECTOR ij;
TCHAR* DLLPATH = (TCHAR*)L"D:\\Source\\StealthProcess2\\StealthProcess.dll";

int main(void) {

	if (!SetRootPrivilege()) {
		std::cerr << "SetRootPrivilege()" << std::endl;
		return -1;
	};

	while (1) {

		EnumWindows(EnumWindowsProc, (LPARAM)L"Taskmgr.exe");
		if (_kbhit()) break;
	};

	return 0;
};

BOOL SetRootPrivilege() {

	HANDLE token = NULL;
	
	auto result = OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &token);
	if (result == FALSE) {
		std::cerr << "token" << std::endl;
		return FALSE;
	};

	LUID luid = { 0, };

	result = LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid);
	if (result == FALSE) {
		std::cerr << "LookupPrivilegeValue" << std::endl;
		return FALSE;
	};

	TOKEN_PRIVILEGES tp = { 0, };
	
	tp.Privileges[0].Luid= luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	result = AdjustTokenPrivileges(token, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
	if (result == FALSE) {
		std::cerr << "AdjustTokenPrivileges" << std::endl;
		return FALSE;
	};

	return TRUE;
};

BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
	
	DWORD pid = -1;
	GetWindowThreadProcessId(hwnd, &pid);
	if (pid == -1) {
		std::cerr<< "pid" << std::endl;
		return FALSE;
	};

	HANDLE procHandle = NULL;

	procHandle = OpenProcess(PROCESS_ALL_ACCESS, TRUE, pid);
	if (procHandle == NULL) {
		std::cerr << "procHandle" << std::endl;
		return FALSE;
	};

	wchar_t filePath[MAX_PATH] = { 0, };
	auto result = GetModuleFileNameEx(procHandle,NULL, filePath, MAX_PATH);
	if (result <= 0) {
		std::cerr << "filePath" << std::endl;
		return FALSE;
	};

	/*static int cnt = 0;
	std::cout<<cnt++<<std::endl;*/
	
	wchar_t* exeName = NULL;
	wchar_t* parsingFilePath = NULL;

	exeName = (wchar_t*)lParam;
	parsingFilePath = wcsrchr(filePath, '\\');

	result = _wcsicmp(exeName, parsingFilePath+1);
	if (result == 0 && result != -1) {
		HMODULE hModAry[MODULE_BUF] = { 0, };
		DWORD readedModCnt = 0;
		result = EnumProcessModulesEx(procHandle, hModAry, MODULE_BUF, &readedModCnt, LIST_MODULES_ALL);
		if (result) {
			for (int i = 0; i < readedModCnt; i++) {
				wchar_t procDLLname[MAX_PATH] = { 0, };
				if (GetModuleFileName(hModAry[i], procDLLname, MAX_PATH)) {
					result = _wcsicmp(procDLLname, ij.GetDLLPath());
					if (result == 0 && result != -1) {
						return TRUE;
					};
				};
			};
		};

		ij.SetDLLPath(DLLPATH);
		ij.SetPID(pid);
		ij.Injection();
	};


	return TRUE;
};