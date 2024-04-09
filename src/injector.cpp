#include "injector.h"

#include "PeHeader.h"

uint64_t injector::WriteFileIntoProc(std::vector<char> filBytes, mem* proc, PeHeader* PE)
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
	if (!result || bytesWritten == 0) { utils::ErrorMsgExit("WriteProcessMemory", true); }

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

		if (result == 0) { utils::ErrorMsgExit("WriteProcessMemory", true); }		

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


uint64_t injector::GetModuleFunc(std::string_view modulename, std::string_view funcName, mem* proc)
{
	void* localModuleAddr{ GetModuleHandleA(modulename.data()) };

	if (!localModuleAddr) { utils::ErrorMsgExit("GetModuleHandleA", true); }

	void* localFuncAddr{ GetProcAddress(reinterpret_cast<HMODULE>(localModuleAddr), funcName.data()) };

	if (!localFuncAddr) { utils::ErrorMsgExit("GetProcAddress", true); }

	auto funcOffset{ static_cast<uint64_t*>(localFuncAddr) - static_cast<uint64_t*>(localModuleAddr) };
	uint32_t targetModuleAddr{ proc->GetModule(modulename.data()) };

	return targetModuleAddr + funcOffset;
}



void mappingParameter()
{
	
}

void manualMapper()
{
	// 1) base relocation
	// 2) handle import
	// 3) TLS callback
	// 4) check SEH support
	// 5) call DLL Entry point
}