#include "hook.h"

BOOL restoreHook(LPHOOK_RESULT hookResult) {
	if (!hookResult) return FALSE;

	DWORD currProt;

	VirtualProtect(hookResult->hookFunAddr, hookResult->len, PAGE_EXECUTE_READWRITE, &currProt);

	CopyMemory(hookResult->hookFunAddr, hookResult->originalData, hookResult->len);

	DWORD dummy;

	VirtualProtect(hookResult->hookFunAddr, hookResult->len, currProt, &dummy);

	HeapFree(GetProcessHeap(), HEAP_GENERATE_EXCEPTIONS, hookResult->originalData);
	HeapFree(GetProcessHeap(), HEAP_GENERATE_EXCEPTIONS, hookResult);

	return TRUE;
}

LPHOOK_RESULT installHook(LPVOID hookFunAddr, LPVOID jmpAddr, SIZE_T len) {
	if (len < 5) {
		return NULL;
	}

	DWORD currProt;


	LPBYTE originalData = (LPBYTE)HeapAlloc(GetProcessHeap(), HEAP_GENERATE_EXCEPTIONS, len);
	CopyMemory(originalData, hookFunAddr, len);

	LPHOOK_RESULT hookResult = (LPHOOK_RESULT)HeapAlloc(GetProcessHeap(), HEAP_GENERATE_EXCEPTIONS, sizeof(HOOK_RESULT));

	hookResult->hookFunAddr = hookFunAddr;
	hookResult->jmpAddr = jmpAddr;
	hookResult->len = len;

	hookResult->originalData = originalData;

	VirtualProtect(hookFunAddr, len, PAGE_EXECUTE_READWRITE, &currProt);

	memset(hookFunAddr, 0x90, len); 

	SIZE_T relativeAddress = ((SIZE_T)jmpAddr - (SIZE_T)hookFunAddr) - 5;

	*(LPBYTE)hookFunAddr = 0xE9; // JMP OP CODE
	*(PSIZE_T)((SIZE_T)hookFunAddr + 1) = relativeAddress;

	DWORD temp;
	VirtualProtect(hookFunAddr, len, currProt, &temp);

	printf("Hook installed at address: %02uX\n", (SIZE_T)hookFunAddr);

	return hookResult;
}