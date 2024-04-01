#pragma once

#include <windows.h>
#include <tlhelp32.h>
#include <string>


namespace proc
{
	BOOL CALLBACK EnumWindowsProc(HWND hWindow, LPARAM ptr);
	uint32_t getModule(std::string_view moduleName, uint32_t pid);
}

struct ProcData
{
	std::string processName;
	DWORD     pid{};	  // means process id
	HANDLE	  hProc{};    // means handle process
	HWND	  hWindow{};  // means handle windows

	ProcData(std::string procName) : processName{ procName } 
	{ 
		EnumWindows(proc::EnumWindowsProc, reinterpret_cast<LPARAM>(this));
	}

	~ProcData()
	{
		CloseHandle(hProc);
		CloseHandle(hWindow);
	}
};


