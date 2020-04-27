#include "memory.h"

/*
BOOL restoreHeap(LPARRAY heapInfoArray) {
	for (int i = 0; i < heapInfoArray->size; i++) {
		LPHEAP_INFO heapInfo = (LPHEAP_INFO)heapInfoArray->arr + i;
		DWORD dummy;
		
		VirtualProtect(heapInfo->lpData, heapInfo->size, PAGE_READWRITE, &dummy);

		CopyMemory(heapInfo->lpDataAddr, heapInfo->lpData, heapInfo->size);
		SecureZeroMemory(heapInfo->lpData, heapInfo->size);

		VirtualFree(heapInfo->lpData, heapInfo->size, MEM_RELEASE);
	}

	return TRUE;
}

VOID lookSigsAtHeap() {
	DWORD dummy;
	
	VirtualProtect(detectableSignature, 20, PAGE_READONLY, &dummy);

	SIGNATURE sig;
	sig.signature = detectableSignature;

	sig.sigSize = 20;

	PROCESS_HEAP_ENTRY heapEntry;

	SecureZeroMemory(&heapEntry, sizeof(PROCESS_HEAP_ENTRY));


	HANDLE heap = GetProcessHeap();
	int ctr = 0;

	PATTERN_RESULT res = { 0 };
	res.sigs = malloc(sizeof(SIZE_T) * 10);
	
	HeapLock(heap);
	printf("locked heap\n");
	Sleep(3000);
	while (HeapWalk(heap, &heapEntry)) {
		if (heapEntry.wFlags & PROCESS_HEAP_ENTRY_BUSY) {
			printf("ctr: %d, addr: %X, size: %X\n", ctr++, heapEntry.lpData, heapEntry.cbData);
			
			patternScanEx((SIZE_T)heapEntry.lpData, heapEntry.cbData, "xxxxxxxxxxxxxxxxxxxx", &sig, &res, 10);
		}
	}
	HeapUnlock(heap);

	VirtualProtect(detectableSignature, 20, PAGE_NOACCESS, &dummy);

}*/


BOOL searchWholeThing(LPSIGNATURE sig) {
	ALLOCATED_ADDRESSES_RESULT result = { 0 };

	DWORD TOTAL = 50;

	result.arr = calloc(TOTAL, sizeof(MEMORY_BASIC_INFORMATION)); // 100 positions

	SIZE_T ctr = 0;

	SYSTEM_INFO si = { 0 };

	GetSystemInfo(&si);

	SIZE_T currentAddress = (SIZE_T)si.lpMinimumApplicationAddress;
	SIZE_T max = (SIZE_T)si.lpMaximumApplicationAddress;

	printf("address of signature: 0x%X\n", sig->signature);

	PATTERN_RESULT patternRes = { 0 };
	patternRes.sigs = malloc(sizeof(SIZE_T) * 10);

	while (currentAddress < max) {
		MEMORY_BASIC_INFORMATION info;
		SecureZeroMemory(&info, sizeof(MEMORY_BASIC_INFORMATION));

		VirtualQuery((LPVOID)currentAddress, &info, sizeof(MEMORY_BASIC_INFORMATION));

		if (info.Type == MEM_PRIVATE && info.State != MEM_FREE && info.Protect != PAGE_NOACCESS) {
			DWORD oldProtect, dummyProtect;
			
			if (!VirtualProtect(info.AllocationBase, info.RegionSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
				// printf("[FATAL] virtual protect failed, %d at 0x%X\n", GetLastError(), info.AllocationBase);
				currentAddress = (SIZE_T)info.BaseAddress + (SIZE_T)info.RegionSize;
				continue;
			}

			

			patternScanEx((SIZE_T)info.AllocationBase, info.RegionSize, "xxxxxxxxxxxxxxxxxxxx", sig, &patternRes, 10);

			if (patternRes.size > 0 && patternRes.sigs[0] != sig->signature) {
				printf("Old protcet was: %X\n", info.Protect);
				//printMemoryInfo((LPVOID)patternRes.sigs[0]);
				SecureZeroMemory(patternRes.sigs[0], 20);
			}

			VirtualProtect(info.AllocationBase, info.RegionSize, oldProtect, &dummyProtect);
		}

		currentAddress = (SIZE_T)info.BaseAddress + (SIZE_T)info.RegionSize;
	}

	result.dwSize = ctr;
	return TRUE;
}

/*
BOOL cleanHeap(LPARRAY arr) {
	DWORD dummy2;
	VirtualProtect(detectableSignature, 20, PAGE_READWRITE, &dummy2);

	SIGNATURE sig;
	sig.signature = detectableSignature;

	sig.sigSize = 20;

	PROCESS_HEAP_ENTRY heapEntry;

	ZeroMemory(&heapEntry, sizeof(PROCESS_HEAP_ENTRY));

	HANDLE heap = GetProcessHeap();

	LPARRAY heapInfoArray = arr;
	SIZE_T heapInfoSize = 20;

	heapInfoArray->arr = malloc(sizeof(HEAP_INFO) * heapInfoSize);

	PATTERN_RESULT res = { 0 };
	res.sigs = malloc(sizeof(SIZE_T) * 10);

	HeapLock(heap); // that makes sure that other thread dont have access to heap
	while (HeapWalk(heap, &heapEntry)) {
		if (heapEntry.wFlags & PROCESS_HEAP_ENTRY_BUSY) {

			patternScanEx((SIZE_T)heapEntry.lpData, heapEntry.cbData, "xxxxxxxxxxxxxxxxxxxx", &sig, &res, 10);
			
			if (heapInfoArray->size == heapInfoSize) { // if we have reached full size of array, resize
				LPVOID newArr = malloc(sizeof(HEAP_INFO) * heapInfoSize * 2);

				CopyMemory(newArr, heapInfoArray->arr, heapInfoSize);

				heapInfoSize *= 2;

				free(heapInfoArray->arr);
				heapInfoArray->arr = newArr;
			}
			
			if (res.size > 0) { // if we have a match in this region
				LPHEAP_INFO heapInfo = ((LPHEAP_INFO)heapInfoArray->arr) + heapInfoArray->size++;
				DWORD dummy;

				heapInfo->lpData = VirtualAlloc(NULL, heapEntry.cbData, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
				heapInfo->size = heapEntry.cbData;
				heapInfo->lpDataAddr = heapEntry.lpData;

				CopyMemory(heapInfo->lpData, heapEntry.lpData, heapEntry.cbData);
				VirtualAlloc(heapInfo->lpData, heapInfo->size, PAGE_NOACCESS, &dummy); // secure data to no access page
				
				printf("Wiping memory at: %X, size: %X\n", heapEntry.lpData, heapEntry.cbData);
				SecureZeroMemory(heapEntry.lpData, heapEntry.cbData); // wipe whole region in heap
				if (verifyNullMem(heapEntry.lpData, heapEntry.cbData)) {
					printf("Memory is clean, verified!\n");
				}
				else {
					printf("Memory is not clean\n");
				}
			}
			
		}
	}

	HeapUnlock(heap);
	free(res.sigs);

	SecureZeroMemory(detectableSignature, 20);

	return TRUE;
}*/

/*
BOOL verifyNullMem(LPVOID start, SIZE_T size) {
	PBYTE mem = (PBYTE)start;

	for (SIZE_T i = 0; i < size; i++) {
		if (*mem != 0) {
			printf("Memory is NOT NULL\n");
			return FALSE;
		}
	}

	printf("Memory is NULL\n");
	return TRUE;
}*/

VOID printMemoryInfo(LPVOID address) {
	MEMORY_BASIC_INFORMATION info = { 0 };

	VirtualQuery(address, &info, sizeof(MEMORY_BASIC_INFORMATION));

	printf("BaseAddress -> %02X\n", (DWORD)info.BaseAddress);
	printf("AllocationBase -> %02X\n", (DWORD)info.AllocationBase);
	printf("AllocationProtect -> %02X\n", (DWORD)info.AllocationProtect);
	printf("RegionSize -> %02X\n", (DWORD)info.RegionSize);
	printf("State -> %02X\n", (DWORD)info.State);
	printf("Protect -> %02X\n", (DWORD)info.Protect);
	printf("Type -> %02X\n", (DWORD)info.Type);
}


ALLOCATED_ADDRESSES_RESULT getAllocatedAddresses(DWORD dwProtect) {
	ALLOCATED_ADDRESSES_RESULT result = { 0 };

	DWORD TOTAL = 50;

	result.arr = calloc(TOTAL, sizeof(MEMORY_BASIC_INFORMATION)); // 50 positions

	SIZE_T ctr = 0;

	SYSTEM_INFO si = { 0 };

	GetSystemInfo(&si);

	SIZE_T currentAddress = (SIZE_T)si.lpMinimumApplicationAddress;
	SIZE_T max = (SIZE_T)si.lpMaximumApplicationAddress;

	MEMORY_BASIC_INFORMATION currentMemory = { 0 }; // used to exclude current memory
	VirtualQuery(setPermissions, &currentMemory, sizeof(MEMORY_BASIC_INFORMATION));
	
	while (currentAddress < max) {
		MEMORY_BASIC_INFORMATION info = { 0 };

		VirtualQuery((LPVOID)currentAddress, &info, sizeof(MEMORY_BASIC_INFORMATION));

		if (info.Protect == dwProtect && info.AllocationBase != currentMemory.AllocationBase) { // exclude current page
			result.arr[ctr++] = info;
			printf("[!X!] FOUND ADDRESS\n");
			printf("[!] Found memory region: %02X at %02X of size %02X\n\n", ctr, info.BaseAddress, info.RegionSize);
		}

		currentAddress = (SIZE_T)info.BaseAddress + (SIZE_T)info.RegionSize;

		if (ctr >= TOTAL) {
			break;
		}
	}

	result.dwSize = ctr;
	return result;
}

BOOL setPermissions(MEMORY_BASIC_INFORMATION* addresses, DWORD dwSize, DWORD dwProtect) {
	DWORD dummy;

	printf("[X] Memory to protect size: %d\n", dwSize);

	for (DWORD i = 0; i < dwSize; i++) {
		MEMORY_BASIC_INFORMATION* info = addresses + i;

		if (!VirtualProtect(info->AllocationBase, info->RegionSize, dwProtect, &dummy)) {
			printf("[X] Set permission failed, memory is not protected\n"); 
			return FALSE;
		}

		printf("[!] Changed protection of region: at %02X of size %02X\n\n", info->AllocationBase, info->RegionSize);
	}

	printf("Restored all the memory regions\n");
	return TRUE;
}


BOOL patternScanEx(SIZE_T startAddress, SIZE_T length, LPCSTR mask, LPSIGNATURE signature, LPPATTERN_RESULT res, DWORD resArrSize) {
	res->size = 0;

	if (strlen(mask) != signature->sigSize || length <= 0) {
		printf("Different size of mask and signature, mask: %d, signature: %d, length: %d\n", strlen(mask), signature->sigSize, length);
		return FALSE;
	}

	for (SIZE_T i = 0; i < length; i++) {
		if (patternMatches(startAddress + i, mask, signature)) {
			printf("[SIG_SCAN] Found bytes at %X\n", startAddress + i);
			if (res->size < resArrSize) {
				res->sigs[res->size++] = startAddress + i;
			}
			else {
				printf("Buffer overflow!!\n");
				res->size++;
			}
		}
	}

	return TRUE;
}


/*
*	Says when a area in the specified process matches the signature.
*
*	@param  a HANDLE to the process.
*	@param  the baseAddress that the function will try to match.
*	@param  the mask of the pattern.
*	@param  a vector which contains the signature of the pattern.
*	@return TRUE if the signature of the pattern matches the BYTES in the area in the memory specified by the @param address.
*/
BOOL patternMatches(SIZE_T address, LPCSTR mask, LPSIGNATURE signature) {
	LPBYTE mem = NULL;
	

	for (SIZE_T i = 0; i < signature->sigSize; i++) {
		mem = (LPBYTE)(address + i);
	
		// printf("mem is: %X, sig is: %X at %X, index: %d\n", *mem, signature->signature[i], address, i);
		
		if (mask[i] == 'x' && *mem != signature->signature[i]) {
			return FALSE;
		}
	}

	return TRUE;
}