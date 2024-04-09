#pragma once
#include <cstdint>


#include "utils.h"

namespace injector
{
	uint64_t WriteFileIntoProc(std::vector<char> image, mem* proc, PeHeader* PE);
	uint64_t GetModuleFunc(std::string_view modulename, std::string_view funcName, mem* proc);
	void baseRelocation();
	void HandleImport(uint64_t dllBaseAddr, mem* myMem);
	void InitializeTlsCallbacks();
	void CallDllEntryPoint();
}
