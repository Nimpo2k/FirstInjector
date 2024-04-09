#pragma once

#include <windows.h>
#include <tlhelp32.h>
#include <string>

#include "utils.h"


namespace proc {
	BOOL CALLBACK EnumWindowsProc(HWND hWindow, LPARAM ptr);
}

class mem
{
private:
    std::string	 m_processName;
	uint32_t     m_pid{};	   // means process id
	HANDLE	     m_hProc{};    // means handle process

public:
    mem(std::string procName) : m_processName{ procName } { 
		EnumWindows(proc::EnumWindowsProc, reinterpret_cast<LPARAM>(this));
	}

	~mem() { CloseHandle(m_hProc); }

    uint32_t	GetPid() const { return m_pid; }
	HANDLE		GethProc() const { return m_hProc; }
	std::string GetProcessName() const { return m_processName; }

    void SetPid(uint32_t pid) { m_pid = pid; }
    void SethProc(HANDLE hProc) { m_hProc = hProc; }
    void SetprocessName(std::string processName) { m_processName = processName; }
    
	uint32_t GetModule(std::string_view moduleName);
	void*	 AllocateMemory(size_t size);
};


