#include "proc.h"

#define _DEBUG

BOOL CALLBACK proc::EnumWindowsProc(HWND hWindow, LPARAM ptr)
{
    //Cast the LPARAM to a pointer to the struct
    auto pData = reinterpret_cast<ProcData*>(ptr);

    // get window name
    int length = GetWindowTextLength(hWindow);
    char* buffer = new char[length + 1];
    GetWindowText(hWindow, buffer, length + 1);

    std::string windowTitle = buffer;
    delete[] buffer;

#ifdef _DEBUG 
    std::printf("[windowTitle] %s\n", windowTitle.c_str());
#endif

    if (!windowTitle.compare(pData->processName))
    {
        // get the pid
        GetWindowThreadProcessId(hWindow, &pData->pid);

        //get handle window
        pData->hWindow = hWindow;

        // get the process handler
        pData->hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pData->pid);
        if (!pData->hProc)
        {
            std::printf("[handle process] %zX \n", GetLastError());
            exit(EXIT_FAILURE);
        }
        return  false;
    }

    return true;
}

uint32_t proc::getModule(std::string_view moduleName, uint32_t pid)
{
	MODULEENTRY32 moduleInfo;
	moduleInfo.dwSize = sizeof(moduleInfo);

	HANDLE moduleSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
	if (moduleSnapshot == INVALID_HANDLE_VALUE)
		exit(0);

	Module32First(moduleSnapshot, &moduleInfo);
	if (!moduleName.compare(moduleInfo.szModule)) 
    {
		CloseHandle(moduleSnapshot);
		return reinterpret_cast<uint32_t>(moduleInfo.modBaseAddr);
	}

    
#ifdef _DEBUG
        std::printf("[module32] Name: %s\nAddr: %zX\n", moduleInfo.szModule, moduleInfo.modBaseAddr);
#endif // _DEBUG


	while (Module32Next(moduleSnapshot, &moduleInfo))
	{
#ifdef _DEBUG
        std::printf("[module32] Name: %s\nAddr: %zX\n", moduleInfo.szModule, moduleInfo.modBaseAddr);
#endif // _DEBUG

		if (!moduleName.compare(moduleInfo.szModule)) {
			CloseHandle(moduleSnapshot);
			return reinterpret_cast<uint32_t>(moduleInfo.modBaseAddr);
		}
	}

	CloseHandle(moduleSnapshot);
	return 0;
}

