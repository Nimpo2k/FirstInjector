#pragma once
#include <string>
#include <vector>
#include <iostream>
#include <fstream>
#include <filesystem>

#include "proc.h"
#include "PeHeader.h"


class mem;
class PeHeader;

namespace utils
{
	std::vector<char> ReadFile(const std::string& dllPath);
	void ErrorMsgExit(std::string_view msg, bool lastError);
	std::string GetDllPath();
}

namespace injector
{
	uint64_t WriteFileIntoProc(std::vector<char> image, mem* proc, PeHeader* PE);
	uint64_t GetModuleFunc(std::string_view modulename, std::string_view funcName, mem* proc);
	void baseRelocation();
	void HandleImport(uint64_t dllBaseAddr, mem* myMem);
	void InitializeTlsCallbacks();
	void CallDllEntryPoint();
}



	