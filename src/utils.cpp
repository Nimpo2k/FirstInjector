#include "utils.h"

uint64_t utils::WriteFileIntoProc(std::vector<uint8_t> filBytes, mem* proc, PeHeader* PE)
{

	constexpr size_t relocAdrrSize{ 4096 };
	size_t bytesWritten{};

	const auto remoteBaseAddr{ proc->AllocateMemory(PE->size()) };

	for (size_t i = 0; i < PE->NumberOfSection(); i++)
	{
		size_t bytesWritten;
		auto result = WriteProcessMemory(
			proc->GethProc(),
			reinterpret_cast<char*>(remoteBaseAddr) + PE->CS_VirtualAddress(),
			filBytes.data() + PE->CS_PointerToRawData(),
			PE->CS_SizeOfRawData(),
			&bytesWritten
		);

		if (result == 0) { ErrorMsgExit("WriteProcessMemory", true); }		

#ifdef _DEBUG
		printf("[current section VirtualAddress] %zX\n", PE->CS_VirtualAddress());
		printf("[current section PointerToRawData] %zX\n", PE->CS_PointerToRawData());
		printf("[current section SizeOfRawData] %zX\n", PE->CS_PointerToRawData());
		printf("[current section Name] %s\n\n", PE->CS_Name());
#endif

		PE->IncrementCurrentSection();
	}

	bool result = WriteProcessMemory(proc->GethProc(), remoteBaseAddr, filBytes.data(), relocAdrrSize, &bytesWritten);
	if (!result || bytesWritten == 0) { ErrorMsgExit("WriteProcessMemory", true); }	

#ifdef _DEBUG
	printf("[remoteBaseAddr] %zX\n", remoteBaseAddr);
	printf("[sizeOfImage] %zX\n", PE->size());
#endif 

	return reinterpret_cast<uint64_t>(remoteBaseAddr);
}

std::vector<uint8_t> utils::ReadFile(const std::string& dllPath)
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

	if (fileStream.fail()) 
	{
		fileStream.close();
		ErrorMsgExit("can't read the file", false);
	}

	fileStream.seekg(0, std::ios::end);
	const auto fileSize = fileStream.tellg();
	fileStream.seekg(0, std::ios::beg);

	std::vector<uint8_t> fileBytes;

	fileBytes.reserve(static_cast<uint32_t>(fileSize));
	fileBytes.insert(fileBytes.begin(), std::istream_iterator<uint8_t>(fileStream), std::istream_iterator<uint8_t>());
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
	if (!lastError)
	{
		printf("[-] %s: %zX \n", msg, GetLastError());
	}
	printf("[-] %s\n", msg);
	exit(EXIT_FAILURE);
}


uint64_t utils::GetModuleFunc(std::string_view modulename, std::string_view funcName, mem* proc)
{
	void* localModuleAddr{ GetModuleHandleA(modulename.data()) };

	if (!localModuleAddr) { ErrorMsgExit("GetModuleHandleA", true); }

	void* localFuncAddr{ GetProcAddress(reinterpret_cast<HMODULE>(localModuleAddr), funcName.data()) };

	if (!localFuncAddr) { ErrorMsgExit("GetProcAddress", true); }

	auto funcOffset{ static_cast<uint64_t*>(localFuncAddr) - static_cast<uint64_t*>(localModuleAddr) };
	uint32_t targetModuleAddr{ proc->getModule(modulename.data()) };

	return targetModuleAddr + funcOffset;
}