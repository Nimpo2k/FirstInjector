#include "utils.h"




uint64_t utils::WriteFileIntoProc(std::vector<char> filBytes, mem* proc, PeHeader* PE)
{
	constexpr size_t relocAdrrSize{ 4096 };
	size_t bytesWritten{};


	const auto remoteBaseAddr = VirtualAllocEx(
	proc->GethProc(),
	nullptr,
	PE->GetSize(),
	MEM_RESERVE | MEM_COMMIT,
	PAGE_EXECUTE_READWRITE);

	if (remoteBaseAddr == nullptr) { utils::ErrorMsgExit("VirtualAllocEx", true); };

	//retarded asf 
	unsigned long oldProtect;
	VirtualProtectEx(proc->GethProc(), remoteBaseAddr, PE->GetImageBase(), PAGE_EXECUTE_READWRITE, &oldProtect);

	// read the file
	bool result = WriteProcessMemory(proc->GethProc(), remoteBaseAddr, filBytes.data(), 0x1000, &bytesWritten);
	if (!result || bytesWritten == 0) { ErrorMsgExit("WriteProcessMemory", true); }

#ifdef _DEBUG
	printf("[file size] %", filBytes.data());
	printf("[optional header size of image] %zX\n", PE->GetSize() );
#endif

	for (size_t i = 0; i < PE->GetNumberOfSection(); i++)
	{
		size_t bytesWritten;
		auto result = WriteProcessMemory(
			proc->GethProc(),
			static_cast<char*>(remoteBaseAddr) + PE->CS_GetVirtualAddress(),
			filBytes.data() + PE->CS_GetPointerToRawData(),
			PE->CS_GetSizeOfRawData(),
			&bytesWritten
		);

		if (result == 0) { ErrorMsgExit("WriteProcessMemory", true); }		

#ifdef _DEBUG
		printf("[the addr place that will be written] 0x%zX\n", reinterpret_cast<char*>(remoteBaseAddr) + PE->CS_GetVirtualAddress());
		printf("[current section VirtualAddress] %zX\n", PE->CS_GetVirtualAddress());
		printf("[current section PointerToRawData] %zX\n", PE->CS_GetPointerToRawData());
		printf("[current section SizeOfRawData] %zX\n", PE->CS_GetSizeOfRawData());
		printf("[current section Name] %s\n\n", PE->CS_GetName());
#endif // _DEBUG

		PE->IncrementCurrentSection();
	}


#ifdef _DEBUG
	printf("[remoteBaseAddr] %p\n", remoteBaseAddr);
	printf("[nt header sizeOfImage] %zX\n", PE->GetSize());
#endif // _DEBUG

	return reinterpret_cast<uint64_t>(remoteBaseAddr);
}

std::vector<char> utils::ReadFile(const std::string& dllPath)
{
	std::ifstream fileStream(dllPath.c_str(), std::ios::in | std::ios::binary | std::ios::ate);


	if (!std::filesystem::exists(dllPath.data()))
	{
		fileStream.close();
		ErrorMsgExit("the path doesn't exist", false);
	}

	if (std::filesystem::path(dllPath.c_str()).extension().string().compare(".dll") == -1) {
		fileStream.close();
		ErrorMsgExit("file your trying to read is not a dll", false);
	}

	if (fileStream.fail()) {
		fileStream.close();
		ErrorMsgExit("can't read the file", false);
	}

	const auto fileSize = fileStream.tellg();
	if(fileSize < 0x1000)
	{
		fileStream.close();
		ErrorMsgExit("FileSize invalid", false);
	}

	std::vector<char> fileBytes(fileSize);
	if(!fileBytes.data())
	{
		fileStream.close();
		ErrorMsgExit("didn't allocate the dll", false);
	}

	fileStream.seekg(0, std::ios::beg);
	fileStream.read(fileBytes.data(), fileSize);
	fileStream.close();

	return fileBytes;
}

std::string utils::GetDllPath()
{
	std::string dllPath{ "" };
	printf("Enter a path: ");
	std::getline(std::cin >> std::ws, dllPath);

	if (std::cin) { ErrorMsgExit("last input failed", false); }

	return dllPath;
}

void utils::ErrorMsgExit(std::string_view msg, bool lastError)
{
	lastError ? printf("[-] %s: %d \n", msg.data(), GetLastError()) : printf("[-] %s\n", msg.data());
	exit(EXIT_FAILURE);
}


uint64_t utils::GetModuleFunc(std::string_view modulename, std::string_view funcName, mem* proc)
{
	void* localModuleAddr{ GetModuleHandleA(modulename.data()) };

	if (!localModuleAddr) { ErrorMsgExit("GetModuleHandleA", true); }

	void* localFuncAddr{ GetProcAddress(reinterpret_cast<HMODULE>(localModuleAddr), funcName.data()) };

	if (!localFuncAddr) { ErrorMsgExit("GetProcAddress", true); }

	auto funcOffset{ static_cast<uint64_t*>(localFuncAddr) - static_cast<uint64_t*>(localModuleAddr) };
	uint32_t targetModuleAddr{ proc->GetModule(modulename.data()) };

	return targetModuleAddr + funcOffset;
}