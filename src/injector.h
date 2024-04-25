#pragma once

#include "proc.h"
#include "utils.h"

using LoadLibraryAPtr = HMODULE(__stdcall*)(LPCSTR lpLibFileName);
using GetProcAddressPtr = FARPROC(__stdcall*)(HMODULE hModule, LPCSTR  lpProcName);

struct IMAGE_RELOCATION_ENTRY
{
	WORD offset : 12; //Rva from current base relocation block 
	WORD type : 4;
};


struct RelocationParameters
{
	uint64_t			dllBaseAddress;
	LoadLibraryAPtr		LoadLibraryAAddress;
	GetProcAddressPtr	GetProcAddressAddress;
	uint64_t			DirectoryBaseRelocationAddr;
	uint64_t			ImageBase;
	size_t				SizeBaseRelocation;
	uint64_t			DirectoryImportAddr;
	size_t				SizeTLSCallBack;
	uint64_t			TLSEntryVirtualAddress;
	uint64_t			AddressEntryPoint;
};

namespace injector
{
	uint64_t WriteFileIntoProc(std::vector<char> image, mem* proc, PeHeader* PE);
	uint64_t GetModuleFunc(std::string_view modulename, std::string_view funcName, mem* proc);
	//void manualMapper(RelocationParameters* param);
	void RelocationStub(void* param);
}

/*
 *	void baseRelocation();
 *	void HandleImport(uint64_t dllBaseAddr, mem* myMem);
 * 	void InitializeTlsCallbacks();
 * 	void CallDllEntryPoint();
*/


