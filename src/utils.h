#pragma once
#include <string>
#include <vector>
#include <iostream>
#include <fstream>
#include <filesystem>

#include "proc.h"
#include "PeHeader.h"

namespace utils
{
	uint64_t WriteFileIntoProc(std::vector<uint8_t> image, mem* proc, PeHeader* PE);
	std::vector<uint8_t> ReadFile(const std::string& dllPath);
	std::string GetDllPath();
	void ErrorMsgExit(std::string_view msg, bool lastError);
	uint64_t GetModuleFunc(std::string_view modulename, std::string_view funcName, mem* proc);
}
	