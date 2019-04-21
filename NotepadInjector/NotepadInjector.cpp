#include <Windows.h>
#include <stdio.h>
#include <iostream>
#include <tlhelp32.h>

int main(int argc, char* argv[]) {
	char buffer[] = "";

	DWORD targetPID = 0;
	std::wstring targetProcessName = L"Notepad.exe";
	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32W entry;
	entry.dwSize = sizeof entry;
	if (!Process32FirstW(snap, &entry)) {
		printf("Can't get the process list.\n");
		system("pause");
		return 1;
	} do {
		if (std::wstring(entry.szExeFile) == targetProcessName) {
			targetPID = entry.th32ProcessID;
		}
	} while (Process32NextW(snap, &entry));

	if (targetPID) printf("Got the process: %d\n", targetPID);
	else {
		printf("No process found.\n");
		system("pause");
		return 1;
	}
	int procID = targetPID;
	HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, TRUE, procID);
	if (process == NULL) {
		printf("Error: the specified process couldn't be found.\n");
		system("pause");
		return 1;
	}

	LPVOID addr = (LPVOID)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");
	if (addr == NULL) {
		printf("Error: the LoadLibraryA function was not found inside kernel32.dll library.\n");
		system("pause");
		return 1;
	}

	LPVOID arg = (LPVOID)VirtualAllocEx(process, NULL, strlen(buffer), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (arg == NULL) {
		printf("Error: the memory could not be allocated inside the chosen process.\n");
		system("pause");
		return 1;
	}

	int n = WriteProcessMemory(process, arg, buffer, strlen(buffer), NULL);
	if (n == 0) {
		printf("Error: there was no bytes written to the process's address space.\n");
		system("pause");
		return 1;
	}

	HANDLE threadID = CreateRemoteThread(process, NULL, 0, (LPTHREAD_START_ROUTINE)addr, arg, NULL, NULL);
	if (threadID == NULL) {
		printf("Error: the remote thread could not be created.\n");
		system("pause");
		return 1;
	} else {
		printf("Success: the remote thread was successfully created.\n");
	}
	WaitForSingleObject(threadID, INFINITE);
	CloseHandle(process);
	return 0;
}

// References
// http://en.ciholas.fr/get-process-id-pid-from-process-name-string-c-windows-api/    Get the PID from name
// https://pentest.blog/offensive-iat-hooking/										  API Hooking