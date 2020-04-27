#ifndef _METERPRETER_SOURCE_EXTENSION_NINJASPLOIT_HOOK_H
#define _METERPRETER_SOURCE_EXTENSION_NINJASPLOIT_HOOK_H

// #include "../../common/common.h"
#include <Windows.h>
#include <stdio.h>

typedef struct {
	LPVOID hookFunAddr;
	LPVOID jmpAddr;
	SIZE_T len;
	PBYTE originalData;
} HOOK_RESULT, *PHOOK_RESULT, *LPHOOK_RESULT;

BOOL restoreHook(LPHOOK_RESULT hookResult);

LPHOOK_RESULT installHook(LPVOID hookFunAddr, LPVOID jmpAddr, SIZE_T len);

#endif