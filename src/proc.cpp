#include "proc.h"


BOOL CALLBACK proc::EnumWindowsProc(HWND hWindow, LPARAM ptr)
{
    //Cast the LPARAM to a pointer to the struct
    auto pData = reinterpret_cast<mem*>(ptr);

    // get window name
    int length = GetWindowTextLength(hWindow);
    char* buffer = new char[length + 1];
    GetWindowText(hWindow, buffer, length + 1);

    std::string windowTitle = buffer;
    delete[] buffer;

    if (!windowTitle.compare(pData->GetProcessName()))
    {
        // get the pid
        DWORD tempPID{};
        if (GetWindowThreadProcessId(hWindow, &tempPID) == 0) { 
            utils::ErrorMsgExit("GetWindowThreadProcessId", true); 
        }

        pData->SetPid(static_cast<uint32_t>(tempPID));

        // get the process handler
        pData->SethProc( OpenProcess(PROCESS_ALL_ACCESS, FALSE, pData->GetPid()) );

        if (pData->GethProc() == nullptr ) { utils::ErrorMsgExit("OpenProcess", true); }
        return  false;
    }

    return true;
}

uint32_t mem::GetModule(std::string_view moduleName)
{
	MODULEENTRY32 moduleInfo;
	moduleInfo.dwSize = sizeof(moduleInfo);

	HANDLE moduleSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, m_pid);
	if (moduleSnapshot == INVALID_HANDLE_VALUE)
		exit(0);

	Module32First(moduleSnapshot, &moduleInfo);
	if (!moduleName.compare(moduleInfo.szModule)) 
    {
		CloseHandle(moduleSnapshot);
		return reinterpret_cast<uint32_t>(moduleInfo.modBaseAddr);
	}

	while (Module32Next(moduleSnapshot, &moduleInfo))
	{
		if (!moduleName.compare(moduleInfo.szModule)) {
			CloseHandle(moduleSnapshot);
			return reinterpret_cast<uint32_t>(moduleInfo.modBaseAddr);
		}
	}

	CloseHandle(moduleSnapshot);
	return 0;
}

void* mem::AllocateMemory(size_t size)
{
    void* allocatedMemory = VirtualAllocEx(
        m_hProc,
        nullptr,
        size,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_EXECUTE_READWRITE
    );

    if (allocatedMemory == nullptr) { utils::ErrorMsgExit("VirtualAllocEx", true); }
    return allocatedMemory;
}