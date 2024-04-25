#include "injector.h"
#include "proc.h"
#include "utils.h"
#include "PeHeader.h"



int main()
{
	mem proc{ "Untitled - Notepad" };

#ifdef _DEBUG
	printf("[pid] %d\t[hProc] 0x%zX\n", proc.GetPid(), proc.GethProc());
#endif


	//std::string dllPath{ utils::GetDllPath() };
	std::string dllPath{ "C:\\Users\\A6\\Documents\\c++\\Dumb shit\\DummyDLL\\x64\\Debug\\DummyDLL.dll" };
	
	std::vector<char> image{ utils::ReadFile(dllPath)};
	PeHeader PeImage{ image };

	uint64_t baseAddress{ injector::WriteFileIntoProc(image, &proc, &PeImage)};
	LoadLibraryAPtr loadLibraryAddr{ reinterpret_cast<LoadLibraryAPtr>(injector::GetModuleFunc("Kernel32.dll", "LoadLibraryA",&proc))};
	GetProcAddressPtr getProcAddr{ reinterpret_cast<GetProcAddressPtr>(injector::GetModuleFunc("Kernel32.dll", "GetProcAddress", &proc)) };

	RelocationParameters param = {
		.dllBaseAddress					= baseAddress,
		.LoadLibraryAAddress			= LoadLibraryA,
		.GetProcAddressAddress			= GetProcAddress,
		.DirectoryBaseRelocationAddr	= PeImage.GetDirectoryBaseRelocationAddr(),
		.ImageBase						= PeImage.GetImageBase(),
		.SizeBaseRelocation				= PeImage.GetSizeBaseRelocation(),
		.DirectoryImportAddr		    = PeImage.GetDirectoryImportAddr(),
		.SizeTLSCallBack				= PeImage.GetSizeTLSCallBack(),
		.TLSEntryVirtualAddress			= PeImage.GetTLSEntryVirtualAddress(),
		.AddressEntryPoint			    = PeImage.GetAddressEntryPoint(),
	};


#ifdef _DEBUG
	printf("\n\ndllBaseAddress [0x%zX]\n"		   ,baseAddress);
	printf("LoadLibraryAAddress [0x%zX]\n"		   ,loadLibraryAddr);
	printf("GetProcAddressAddress [0x%zX]\n"		   ,getProcAddr);
	printf("DirectoryBaseRelocationAddr [0x%zX]\n"  ,PeImage.GetDirectoryBaseRelocationAddr());
	printf("ImageBase [%zX]\n"					   ,PeImage.GetImageBase());
	printf("SizeBaseRelocation [%zX]\n"			   ,PeImage.GetSizeBaseRelocation());
	printf("DirectoryImportAddr [0x%zX]\n"		   ,PeImage.GetDirectoryImportAddr());
	printf("SizeTLSCallBack [%zX]\n"				   ,PeImage.GetSizeTLSCallBack());
	printf("TLSEntryVirtualAddress [0x%zX]\n"	   ,PeImage.GetTLSEntryVirtualAddress());
	printf("AddressEntryPoint [0x%zX]\n\n"		   ,PeImage.GetAddressEntryPoint());
#endif


	void* relocationParameterAlloc = VirtualAllocEx(
		proc.GethProc(),
		nullptr,
		sizeof(RelocationParameters),
		MEM_COMMIT | MEM_RESERVE ,
		PAGE_EXECUTE_READWRITE
	);

	void* manualMapAlloc = VirtualAllocEx(
		proc.GethProc(),
		nullptr,
		0x1000,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
	);


	if (!manualMapAlloc)
	{
		VirtualFreeEx(proc.GethProc(), reinterpret_cast<LPVOID>(baseAddress), 0, MEM_RELEASE);
		VirtualFreeEx(proc.GethProc(), reinterpret_cast<LPVOID>(relocationParameterAlloc), 0, MEM_RELEASE);
		VirtualFreeEx(proc.GethProc(), reinterpret_cast<LPVOID>(manualMapAlloc), 0, MEM_RELEASE);
		utils::ErrorMsgExit("mapping parameter relocation failed", true);
	}


	if(!relocationParameterAlloc)
	{
		VirtualFreeEx(proc.GethProc(), reinterpret_cast<LPVOID>(baseAddress), 0, MEM_RELEASE);
		utils::ErrorMsgExit("mapping parameter relocation failed", true);
	}
	 

	bool result = WriteProcessMemory(
		proc.GethProc(),
		relocationParameterAlloc,
		&param,
		sizeof(RelocationParameters),
		nullptr
		);

	if (!result)
	{
		VirtualFreeEx(proc.GethProc(), reinterpret_cast<LPVOID>(baseAddress), 0, MEM_RELEASE);
		VirtualFreeEx(proc.GethProc(), reinterpret_cast<LPVOID>(relocationParameterAlloc), 0, MEM_RELEASE);
		utils::ErrorMsgExit("WriteProcessMemory", true);
	}

	result = WriteProcessMemory(
		proc.GethProc(),
		manualMapAlloc,
		injector::RelocationStub,
		0x1000,
		nullptr
	);


	if (!result)
	{
		VirtualFreeEx(proc.GethProc(), reinterpret_cast<LPVOID>(baseAddress), 0, MEM_RELEASE);
		VirtualFreeEx(proc.GethProc(), reinterpret_cast<LPVOID>(relocationParameterAlloc), 0, MEM_RELEASE);
		VirtualFreeEx(proc.GethProc(), reinterpret_cast<LPVOID>(manualMapAlloc), 0, MEM_RELEASE);
		utils::ErrorMsgExit("WriteProcessMemory", true);
	}

	printf("[relocationParameterAlloc] %zX\n", relocationParameterAlloc);
	printf("[manualMapAlloc] %zX\n", manualMapAlloc);

	DWORD threadId;
	HANDLE hThread = CreateRemoteThread(
		proc.GethProc(), 
		nullptr, 
		0, 
		reinterpret_cast<LPTHREAD_START_ROUTINE>(manualMapAlloc),
		relocationParameterAlloc, 
		0, 
		&threadId 
	);


	WaitForSingleObject(hThread, INFINITE);
	CloseHandle(hThread);


	//injector::manualMapper(&param);

	

}