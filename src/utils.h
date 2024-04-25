#pragma once

#include <Windows.h>
#include <string>
#include <vector>
#include <filesystem>
#include <iostream>
#include <fstream>  

class mem;
class PeHeader;

namespace utils
{
	std::string GetDllPath();
	std::vector<char> ReadFile(std::string_view dllPath);
	void ErrorMsgExit(std::string_view msg, bool lastError);
}




	