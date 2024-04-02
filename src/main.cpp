#include <iostream>
#include <string>
#include <Windows.h>
#include <vector>
#include <fstream>
#include <filesystem>

#include "proc.h"

using LoadLibraryAPtr = HMODULE(__stdcall*)(LPCSTR lpLibFileName);
using GetProcAddressPtr = FARPROC(__stdcall*)(HMODULE hModule, LPCSTR  lpProcName);

struct RelocationParameters
{
	uint64_t			remoteDllBaseAddress;
	LoadLibraryAPtr		remoteLoadLibraryAAddress;
	GetProcAddressPtr	remoteGetProcAddressAddress;
};


// look what it actually do (PASTED)
// https://www.codereversing.com/archives/652

struct RELOCATION_INFO
{
	uint16_t offset : 12;
	uint16_t type : 4;
};


struct PeHeader
{
	IMAGE_DOS_HEADER* m_dosHeader;
	IMAGE_NT_HEADERS* m_ntHeader;
	_IMAGE_SECTION_HEADER* m_currentSection;

	PeHeader(std::vector<char>& fileBytes)
	{
		m_dosHeader		 = reinterpret_cast<IMAGE_DOS_HEADER*>(fileBytes.data());
		m_ntHeader		 = reinterpret_cast<IMAGE_NT_HEADERS*>(fileBytes.data() + m_dosHeader->e_lfanew);
		m_currentSection = IMAGE_FIRST_SECTION(m_ntHeader);
	}  
};

std::vector<char> ReadFile(const std::string& dllPath)
{
	std::ifstream fileStream(dllPath.c_str(), std::ios::in | std::ios::binary | std::ios::ate);

	if (!std::filesystem::exists(dllPath.data()))
	{
		std::cerr << "[ERROR] the path doesn't exist" << std::endl;
		fileStream.close();
		exit(EXIT_FAILURE);
	}

	if (std::filesystem::path(dllPath.c_str()).extension().string().compare(".dll") == -1) {
		std::cerr << "[ERROR] file is not a dll" << std::endl;
		exit(EXIT_FAILURE);
	}


	if (fileStream.fail())
	{
		printf("can't read the file :(\n");
		fileStream.close();
		exit(EXIT_FAILURE);
	}

	const int fileSize = fileStream.tellg();

	fileStream.seekg(0, std::ios::beg);

	std::vector<char> fileBytes(fileSize);
	fileStream.read(fileBytes.data(), fileSize);
	
	fileStream.end;

	return fileBytes;
}


std::string GetDllPath()
{
	std::string dllPath{ "" };
	printf("Enter a path: ");
	std::getline(std::cin >> std::ws, dllPath);

	return dllPath;
}

uint64_t WriteFile(std::vector<char> filBytes, const ProcData* proc, PeHeader* PE)
{
	constexpr size_t relocAdrrSize{ 4096 };
	size_t bytesWritten{};

	std::printf("[PE] SizeOfImage: %zX\n", PE->m_ntHeader->OptionalHeader.SizeOfImage);


	const auto remoteBaseAddr = VirtualAllocEx(
		proc->hProc,
		nullptr,
		PE->m_ntHeader->OptionalHeader.SizeOfImage,
		MEM_RESERVE | MEM_COMMIT,
		PAGE_EXECUTE_READWRITE
	);

	if (remoteBaseAddr == nullptr) {
		std::cerr << "[ERROR] VirtualAllocEx: " << GetLastError() << std::endl;
		exit(EXIT_FAILURE);
	}

	std::printf("[remoteBaseAddr] %zX\n", remoteBaseAddr);


	for (size_t i = 0; i < PE->m_ntHeader->FileHeader.NumberOfSections; i++)
	{
		size_t bytesWritten;
		auto result = WriteProcessMemory(
			proc->hProc,
			reinterpret_cast<char*>(remoteBaseAddr) + PE->m_currentSection->VirtualAddress,
			filBytes.data() + PE->m_currentSection->PointerToRawData,
			PE->m_currentSection->SizeOfRawData,
			&bytesWritten
		);
		

		if (result == 0) {
			std::cerr << "[ERROR] WPM: " << GetLastError() << std::endl;
			exit(EXIT_FAILURE);
		}

		PE->m_currentSection++;
	} 

	bool result = WriteProcessMemory(proc->hProc, remoteBaseAddr, filBytes.data(), relocAdrrSize, &bytesWritten);
	if (!result || bytesWritten == 0) {
		std::cerr << "[ERROR] WPM: " << GetLastError() << std::endl;
		exit(EXIT_FAILURE);
	}


	return reinterpret_cast<uint64_t>(remoteBaseAddr);
}

uint64_t GetModuleFunc(std::string_view modulename, std::string_view funcName, ProcData* proc)
{
	// get info from own process
	void* localModuleAddr{ GetModuleHandleA(modulename.data()) };
	
	if (!localModuleAddr)
	{
		std::cerr << "[ERROR] GetModuleHandleA: " << GetLastError() << std::endl;
		exit(EXIT_FAILURE);
	}

	void* localFuncAddr{ GetProcAddress( reinterpret_cast<HMODULE>(localModuleAddr), funcName.data()) };

	if (!localFuncAddr)
	{
		std::cerr << "[ERROR] GetProcAddress: " << GetLastError() << std::endl;
		exit(EXIT_FAILURE);
	}

	// potential losing data
	auto funcOffset{ static_cast<uint64_t*>(localFuncAddr) - static_cast<uint64_t*>(localModuleAddr) };
	uint32_t targetModuleAddr{ proc::getModule(modulename.data(), proc->pid)};

	return targetModuleAddr + funcOffset;
}

void ApplyBaseRelocations(PeHeader* PE, RelocationParameters* param, uint64_t relocationOffset)
{
	// getting the address of the Base Relocation Table
	uint64_t baseRelocTableAddr{ PE->m_ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress };
	const auto* baseRelocationDirectoryEntry{ reinterpret_cast<IMAGE_BASE_RELOCATION*>(param->remoteDllBaseAddress + baseRelocTableAddr) };

	const int count = baseRelocationDirectoryEntry->SizeOfBlock / (sizeof(IMAGE_BASE_RELOCATION) / sizeof(RELOCATION_INFO));
	const auto* baseRelocationInfo{ reinterpret_cast<RELOCATION_INFO*>(reinterpret_cast<uint64_t>(baseRelocationDirectoryEntry) + sizeof(RELOCATION_INFO)) };

	// iterate over the relocation entry 
	for (size_t i{}; i < count; baseRelocationInfo++, i++)
	{
		if (baseRelocationDirectoryEntry->VirtualAddress == 0) break;

		if (baseRelocationInfo->type == IMAGE_REL_BASED_DIR64)
		{
			auto relocFixAddress{ param->remoteDllBaseAddress + baseRelocationDirectoryEntry->VirtualAddress + baseRelocationInfo->offset };
			relocFixAddress += static_cast<uint32_t>(relocationOffset);
		}
	}

	baseRelocationDirectoryEntry = reinterpret_cast<IMAGE_BASE_RELOCATION*>(baseRelocationDirectoryEntry->VirtualAddress + baseRelocationDirectoryEntry->SizeOfBlock) ;
}

// TO DO: look if there's better way to handle the import :(
void HandleImport(RelocationParameters* param, PeHeader* PE)
{
	auto* importDir = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(param->remoteDllBaseAddress + PE->m_ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	// iterate over each IMAGE_IMPORT_DESCRIPTOR 
	for (size_t index{}; importDir[index].Characteristics != 0; index++) {
		
		// retrieve the module name and load it
		const auto moduleName = reinterpret_cast<char*>(param->remoteDllBaseAddress + importDir[index].Name);
		const auto loadedModuleHandle = param->remoteLoadLibraryAAddress(moduleName);

		// retrieve the addr of the table entry and his name
		auto* addressTableEntry = reinterpret_cast<IMAGE_THUNK_DATA*>(param->remoteDllBaseAddress + importDir[index].FirstThunk);
		const auto* nameTableEntry = reinterpret_cast<IMAGE_THUNK_DATA*>(param->remoteDllBaseAddress + importDir[index].OriginalFirstThunk);

		if (nameTableEntry == nullptr) {
			nameTableEntry = addressTableEntry;
		}

		// Iterate over each entry in the name table
		for (; nameTableEntry->u1.Function != 0; nameTableEntry++, addressTableEntry++) {
			const auto* importedFunction = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(param->remoteDllBaseAddress + nameTableEntry->u1.AddressOfData);

			// Check if the entry is an ordinal or a name. If it's an ordinal, resolve the function address using the ordinal. If it's a name, resolve the function address using the function name.
			if (nameTableEntry->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
				addressTableEntry->u1.Function = reinterpret_cast<ULONGLONG>(
					param->remoteGetProcAddressAddress(loadedModuleHandle, MAKEINTRESOURCEA(nameTableEntry->u1.Ordinal)));
			}
			else {
				addressTableEntry->u1.Function = reinterpret_cast<ULONGLONG>(
					param->remoteGetProcAddressAddress(loadedModuleHandle, importedFunction->Name));
			}
		}
	}
}



void InitializeTlsCallbacks(RelocationParameters* param, PeHeader* PE)
{
	if (PE->m_ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size > 0)
	{
		const auto* tlsEntries{	reinterpret_cast<IMAGE_TLS_DIRECTORY*>(param->remoteDllBaseAddress + PE->m_ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress) };
		const auto* tlsCallback{ reinterpret_cast<PIMAGE_TLS_CALLBACK*>(tlsEntries->AddressOfCallBacks) };

		while(tlsCallback != nullptr)
		{
			// function been called 
			(*tlsCallback)(reinterpret_cast<uint64_t*>(param->remoteLoadLibraryAAddress), DLL_PROCESS_ATTACH, nullptr);

			// move to the next callBack
			++tlsCallback;
		}
	}
}


void CallDllEntryPoint(RelocationParameters* param, PeHeader* PE)
{
	using DllMainPtr = BOOL(__stdcall*)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);
	const auto DllMain{ reinterpret_cast<DllMainPtr>(param->remoteDllBaseAddress + PE->m_ntHeader->OptionalHeader.AddressOfEntryPoint) };

	DllMain(reinterpret_cast<HINSTANCE>(param->remoteDllBaseAddress), DLL_PROCESS_ATTACH, nullptr);
}


void Relocations(RelocationParameters* param)
{
	// ntHeader + dosheader
	const auto* dosHeader{ reinterpret_cast<IMAGE_DOS_HEADER*>(param->remoteDllBaseAddress) };
	const auto* ntHeader { reinterpret_cast<IMAGE_NT_HEADERS*>(param->remoteDllBaseAddress + dosHeader->e_lfanew) };


	// calculate the relocation offset 
	const uint64_t relocationOffset{ param->remoteDllBaseAddress - ntHeader->OptionalHeader.ImageBase };

	//ApplyBaseRelocations(PE, param, relocationOffset);
	
	// getting the address of the Base Relocation Table
	uint64_t baseRelocTableAddr{ ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress };
	const auto* baseRelocationDirectoryEntry{ reinterpret_cast<IMAGE_BASE_RELOCATION*>(param->remoteDllBaseAddress + baseRelocTableAddr) };

	const int count = baseRelocationDirectoryEntry->SizeOfBlock / (sizeof(IMAGE_BASE_RELOCATION) / sizeof(RELOCATION_INFO));
	const auto* baseRelocationInfo{ reinterpret_cast<RELOCATION_INFO*>(reinterpret_cast<uint64_t>(baseRelocationDirectoryEntry) + sizeof(RELOCATION_INFO)) };

	// iterate over the relocation entry 
	for (size_t i{}; i < count; baseRelocationInfo++, i++)
	{
		if (baseRelocationDirectoryEntry->VirtualAddress == 0) break;

		if (baseRelocationInfo->type == IMAGE_REL_BASED_DIR64)
		{
			auto relocFixAddress{ param->remoteDllBaseAddress + baseRelocationDirectoryEntry->VirtualAddress + baseRelocationInfo->offset };
			relocFixAddress += static_cast<uint32_t>(relocationOffset);
		}
	}

	baseRelocationDirectoryEntry = reinterpret_cast<IMAGE_BASE_RELOCATION*>(baseRelocationDirectoryEntry->VirtualAddress + baseRelocationDirectoryEntry->SizeOfBlock);
	
	//HandleImport(param, PE);
	
	auto* importDir = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(param->remoteDllBaseAddress + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	// iterate over each IMAGE_IMPORT_DESCRIPTOR 
	for (size_t index{}; importDir[index].Characteristics != 0; index++) {

		// retrieve the module name and load it
		const auto moduleName = reinterpret_cast<char*>(param->remoteDllBaseAddress + importDir[index].Name);
		const auto loadedModuleHandle = param->remoteLoadLibraryAAddress(moduleName);

		// retrieve the addr of the table entry and his name
		auto* addressTableEntry = reinterpret_cast<IMAGE_THUNK_DATA*>(param->remoteDllBaseAddress + importDir[index].FirstThunk);
		const auto* nameTableEntry = reinterpret_cast<IMAGE_THUNK_DATA*>(param->remoteDllBaseAddress + importDir[index].OriginalFirstThunk);

		if (nameTableEntry == nullptr) {
			nameTableEntry = addressTableEntry;
		}

		// Iterate over each entry in the name table
		for (; nameTableEntry->u1.Function != 0; nameTableEntry++, addressTableEntry++) {
			const auto* importedFunction = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(param->remoteDllBaseAddress + nameTableEntry->u1.AddressOfData);

			// Check if the entry is an ordinal or a name. If it's an ordinal, resolve the function address using the ordinal. If it's a name, resolve the function address using the function name.
			if (nameTableEntry->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
				addressTableEntry->u1.Function = reinterpret_cast<ULONGLONG>(
					param->remoteGetProcAddressAddress(loadedModuleHandle, MAKEINTRESOURCEA(nameTableEntry->u1.Ordinal)));
			}
			else {
				addressTableEntry->u1.Function = reinterpret_cast<ULONGLONG>(
					param->remoteGetProcAddressAddress(loadedModuleHandle, importedFunction->Name));
			}
		}
	}

	//InitializeTlsCallbacks(param, PE);

	if (ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size > 0)
	{
		const auto* tlsEntries{ reinterpret_cast<IMAGE_TLS_DIRECTORY*>(param->remoteDllBaseAddress + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress) };
		const auto* tlsCallback{ reinterpret_cast<PIMAGE_TLS_CALLBACK*>(tlsEntries->AddressOfCallBacks) };

		while (tlsCallback != nullptr)
		{
			// function been called 
			(*tlsCallback)(reinterpret_cast<uint64_t*>(param->remoteLoadLibraryAAddress), DLL_PROCESS_ATTACH, nullptr);

			// move to the next callBack
			++tlsCallback;
		}
	}
	
	//CallDllEntryPoint(param, PE);

	using DllMainPtr = BOOL(__stdcall*)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);
	const auto DllMain{ reinterpret_cast<DllMainPtr>(param->remoteDllBaseAddress + ntHeader->OptionalHeader.AddressOfEntryPoint) };

	DllMain(reinterpret_cast<HINSTANCE>(param->remoteDllBaseAddress), DLL_PROCESS_ATTACH, nullptr);
}

struct relocationInfo {
	void* m_remoteRelocationAddress;
	void* m_remoteParametersAddress;
};

void WriteRelocation(const HANDLE hProc, RelocationParameters* param, relocationInfo* test)
{
	constexpr size_t REMOTE_RELOC_STUB_ALLOC_SIZE = 4096;
	SIZE_T bytesWritten{};

	auto* const remoteParametersAddress{ VirtualAllocEx(hProc, nullptr, REMOTE_RELOC_STUB_ALLOC_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE) };
	
	std::printf("remoteParametersAddress: %zX \n", remoteParametersAddress);


	if (remoteParametersAddress == nullptr)
	{
		std::cerr << "[ERROR] VirtualAllocEx: " << GetLastError() << std::endl;
		CloseHandle(hProc);
		exit(EXIT_FAILURE);
	}

	auto result{ WriteProcessMemory(hProc, remoteParametersAddress, &param, sizeof(RelocationParameters), &bytesWritten) };

	if (!result)
	{
		std::cerr << "[ERROR] WPM1 " << GetLastError() << std::endl;
		CloseHandle(hProc);
		exit(EXIT_FAILURE);
	}

	auto* const remoteRelocationStubAddress{ VirtualAllocEx(hProc, nullptr, REMOTE_RELOC_STUB_ALLOC_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE) };
	
	std::printf("remoteParametersAddress: %zX \n", remoteRelocationStubAddress);

	if (remoteRelocationStubAddress == nullptr)
	{
		std::cerr << "[ERROR] VirtualAllocEx: " << GetLastError() << std::endl;
		CloseHandle(hProc);
		exit(EXIT_FAILURE);
	}

	result = WriteProcessMemory(hProc, remoteRelocationStubAddress, Relocations, REMOTE_RELOC_STUB_ALLOC_SIZE, &bytesWritten);

	if (!result)
	{
		std::cerr << "[ERROR] WPM2" << GetLastError() << std::endl;
		CloseHandle(hProc);
		exit(EXIT_FAILURE);
	}

	test->m_remoteParametersAddress = remoteParametersAddress;
	test->m_remoteRelocationAddress = remoteRelocationStubAddress;
}



int main()
{
	ProcData proc{ "Cube 2: Sauerbraten" };


	std::printf("[pid] %d\n[hproc] %zX\n[hWindow] %zX\n", proc.pid, proc.hProc, proc.hWindow);


	//std::string dllPath{ GetDllPath() };
	std::string dllPath{ "C:\\Users\\A6\\Documents\\c++\\Dumb shit\\DummyDLL\\x64\\Debug\\DummyDLL.dll" };

	std::vector<char> fileBytes{ ReadFile(dllPath) };

	PeHeader PE{ fileBytes };

	relocationInfo info{};

	uint64_t		  remoteBaseAddr{ WriteFile(fileBytes, &proc, &PE) };
	LoadLibraryAPtr   remoteLoadLibraryAAddress{ reinterpret_cast<LoadLibraryAPtr>(GetModuleFunc("Kernel32.dll", "LoadLibraryA", &proc)) };
	GetProcAddressPtr remoteGetProcAddressAddress{ reinterpret_cast<GetProcAddressPtr>(GetModuleFunc("Kernel32.dll", "GetProcAddress", &proc)) };

	RelocationParameters param{
		.remoteDllBaseAddress{ remoteBaseAddr },
		.remoteLoadLibraryAAddress  { remoteLoadLibraryAAddress },
		.remoteGetProcAddressAddress{ remoteGetProcAddressAddress },
	};

	WriteRelocation(proc.hProc, &param, &info);

	std::printf("Start address: %zX\nParameters address: %zX\n", info.m_remoteRelocationAddress, info.m_remoteParametersAddress);


	const auto remoteThread{ CreateRemoteThreadEx(
		proc.hProc, 
		nullptr, 
		0,
		reinterpret_cast<LPTHREAD_START_ROUTINE>(info.m_remoteRelocationAddress),
		info.m_remoteParametersAddress,
		0, 
		nullptr, 
		0) 
	};
}