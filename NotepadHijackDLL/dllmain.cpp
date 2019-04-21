#include <stdio.h>
#include <Windows.h>
#include <winternl.h>
#include <fcntl.h>
#include <io.h>

typedef BOOL(WINAPI* PHookedWriteFile) (
	_In_ HANDLE hFile,
	_In_reads_bytes_opt_(nNumberOfBytesToWrite) LPCVOID lpBuffer,
	_In_ DWORD nNumberOfBytesToWrite,
	_Out_opt_ LPDWORD lpNumberOfBytesWritten,
	_Inout_opt_ LPOVERLAPPED lpOverlapped
	);

typedef _Must_inspect_result_ BOOL (WINAPI* PHookedReadFile) (
	_In_ HANDLE hFile,
	_Out_writes_bytes_to_opt_(nNumberOfBytesToRead, *lpNumberOfBytesRead) __out_data_source(FILE) LPVOID lpBuffer,
	_In_ DWORD nNumberOfBytesToRead,
	_Out_opt_ LPDWORD lpNumberOfBytesRead,
	_Inout_opt_ LPOVERLAPPED lpOverlapped
);

// Static variables
static FILE* g_consoleFile = 0;
static PHookedWriteFile g_pOrgWriteFile = 0;
static PHookedReadFile g_pOrgReadFile = 0;
static HMODULE* g_Self = 0;

BOOL WINAPI HookedWriteFile(
	_In_ HANDLE hFile,
	_In_reads_bytes_opt_(nNumberOfBytesToWrite) LPCVOID lpBuffer,
	_In_ DWORD nNumberOfBytesToWrite,
	_Out_opt_ LPDWORD lpNumberOfBytesWritten,
	_Inout_opt_ LPOVERLAPPED lpOverlapped
);

_Must_inspect_result_ BOOL WINAPI HookedReadFile (
	_In_ HANDLE hFile,
	_Out_writes_bytes_to_opt_(nNumberOfBytesToRead, *lpNumberOfBytesRead) __out_data_source(FILE) LPVOID lpBuffer,
	_In_ DWORD nNumberOfBytesToRead,
	_Out_opt_ LPDWORD lpNumberOfBytesRead,
	_Inout_opt_ LPOVERLAPPED lpOverlapped
	);

BOOL hook_iat(LPCSTR szDllName, PROC pfnOrg, PROC pfnNew);
int LockLibraryIntoProcessMem(HMODULE DllHandle, HMODULE* LocalDllHandle);

INT WINAPI DllMain(HMODULE hDLL, DWORD Reason, LPVOID Reserved) {
	if (!g_consoleFile) {
		AllocConsole();
		freopen_s(&g_consoleFile, "CONOUT$", "w", stdout);
	}

	switch (Reason) {
	case DLL_PROCESS_ATTACH:
		printf("Starting monitoring...\n");
		if (!g_Self) LockLibraryIntoProcessMem(hDLL, g_Self);

		g_pOrgWriteFile = (PHookedWriteFile)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "WriteFile");
		g_pOrgReadFile = (PHookedReadFile)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "ReadFile");
		if (g_pOrgWriteFile &&
			g_pOrgReadFile &&
			hook_iat("kernel32.dll", (PROC)g_pOrgWriteFile, (PROC)HookedWriteFile) &&
			hook_iat("kernel32.dll", (PROC)g_pOrgReadFile, (PROC)HookedReadFile)) {
			printf("[Attached]\n");
		}
		else {
			printf("[Attach Failed]\n");
			return FALSE;
		}
		break;
	}
	return TRUE;
}

BOOL WINAPI HookedWriteFile(
	_In_ HANDLE hFile,
	_In_reads_bytes_opt_(nNumberOfBytesToWrite) LPCVOID lpBuffer,
	_In_ DWORD nNumberOfBytesToWrite,
	_Out_opt_ LPDWORD lpNumberOfBytesWritten,
	_Inout_opt_ LPOVERLAPPED lpOverlapped
) {
	printf("\n<writeFile>:\n%.*s\n", (int)nNumberOfBytesToWrite, (char*)lpBuffer);
	return (*g_pOrgWriteFile)(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
}

_Must_inspect_result_ BOOL WINAPI HookedReadFile(
	_In_ HANDLE hFile,
	_Out_writes_bytes_to_opt_(nNumberOfBytesToRead, *lpNumberOfBytesRead) __out_data_source(FILE) LPVOID lpBuffer,
	_In_ DWORD nNumberOfBytesToRead,
	_Out_opt_ LPDWORD lpNumberOfBytesRead,
	_Inout_opt_ LPOVERLAPPED lpOverlapped
) {
	int statusCode = (*g_pOrgReadFile)(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
	printf("\n<readFile>:\n%.*s\n", *((int*)lpNumberOfBytesRead), (char*)lpBuffer);
	return statusCode;
}

BOOL hook_iat(LPCSTR szDllName, PROC pfnOrg, PROC pfnNew) {
	HMODULE hMod;
	LPCSTR szLibName;
	PIMAGE_IMPORT_DESCRIPTOR pImportDesc;
	PIMAGE_THUNK_DATA pThunk;
	DWORD dwRVA;
	PBYTE pAddr;

	hMod = GetModuleHandle(NULL);
	pAddr = (PBYTE)hMod;

	pAddr += *((DWORD*)& pAddr[0x3c]);
	dwRVA = *((DWORD*)& pAddr[0x80]);
	pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)hMod + dwRVA);

	for (; pImportDesc->Name; pImportDesc++) {
		szLibName = (LPCSTR)((DWORD)hMod + pImportDesc->Name);
		if (!_stricmp(szLibName, szDllName)) {
			pThunk = (PIMAGE_THUNK_DATA)((DWORD)hMod + pImportDesc->FirstThunk);
			for (; pThunk->u1.Function; pThunk++) {
				if (pThunk->u1.Function == (DWORD)pfnOrg) {
					DWORD dwOldProtect;
					VirtualProtect((LPVOID)& pThunk->u1.Function, 4, PAGE_EXECUTE_READWRITE, &dwOldProtect);
					pThunk->u1.Function = (DWORD)pfnNew;
					VirtualProtect((LPVOID)& pThunk->u1.Function, 4, dwOldProtect, &dwOldProtect);
					return TRUE;
				}
			}
		}
	}
	printf("[API hooking failed]\n");
	return FALSE;
}

int LockLibraryIntoProcessMem(
	HMODULE DllHandle,
	HMODULE* LocalDllHandle)
{
	if (NULL == LocalDllHandle)
		return ERROR_INVALID_PARAMETER;
	*LocalDllHandle = NULL;
	TCHAR moduleName[1024];
	if (0 == GetModuleFileName(
		DllHandle,
		moduleName,
		sizeof(moduleName) / sizeof(TCHAR)))
		return GetLastError();
	*LocalDllHandle = LoadLibrary(moduleName);
	if (NULL == *LocalDllHandle)
		return GetLastError();
	return NO_ERROR;
}


//// References
/*
fileapi.h (include Windows.h)

BOOL WriteFile(
  HANDLE       hFile,
  LPCVOID      lpBuffer,
  DWORD        nNumberOfBytesToWrite,
  LPDWORD      lpNumberOfBytesWritten,
  LPOVERLAPPED lpOverlapped
);
*/

/*
	switch (Reason) {
		case DLL_PROCESS_ATTACH:
			fprintf(file, "DLL attach function called.\n");
			break;
		case DLL_PROCESS_DETACH:
			fprintf(file, "DLL detach function called.\n");
			break;
		case DLL_THREAD_ATTACH:
			fprintf(file, "DLL thread attach function called.\n");
			break;
		case DLL_THREAD_DETACH:
			fprintf(file, "DLL thread detach function called.\n");
			break;
	}
	return 0;
*/

// https://www.apriorit.com/dev-blog/160-apihooks API hooking
// https://blogs.msmvps.com/vandooren/2006/10/09/preventing-a-dll-from-being-unloaded-by-the-app-that-uses-it/  Lock