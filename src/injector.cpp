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
		auto result = WriteProcessMemory(
			proc->GethProc(),
			static_cast<char*>(remoteBaseAddr) + PE->CS_GetVirtualAddress(),
			filBytes.data() + PE->CS_GetPointerToRawData(),
			PE->CS_GetSizeOfRawData(),
			nullptr
		);

		if (result == 0) { utils::ErrorMsgExit("WriteProcessMemory", true); }		

#ifdef _DEBUG
		printf("\n\n[the addr place that will be written] 0x%zX\n", reinterpret_cast<char*>(remoteBaseAddr) + PE->CS_GetVirtualAddress());
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


#pragma runtime_checks( "", off )
#pragma optimize( "", off )

void injector::RelocationStub(void* param)
{

	RelocationParameters* parameters = reinterpret_cast<RelocationParameters*>(param);
	uint64_t relocationOffset = parameters->dllBaseAddress - parameters->ImageBase;

	typedef struct {
		WORD offset : 12;
		WORD type : 4;
	} RELOCATION_INFO;


	IMAGE_BASE_RELOCATION* relocationData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(parameters->dllBaseAddress + parameters->DirectoryBaseRelocationAddr);

	while (relocationData->VirtualAddress != 0)
	{
		uint64_t count = (relocationData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(RELOCATION_INFO);
		RELOCATION_INFO* baseRelocationInfo = reinterpret_cast<RELOCATION_INFO*>(reinterpret_cast<uint64_t>(relocationData) + sizeof(RELOCATION_INFO));

		for (size_t i{}; i < count; i++, baseRelocationInfo++) 
		{
			if (baseRelocationInfo->type == IMAGE_REL_BASED_DIR64) 
			{
				const auto fixAddress = reinterpret_cast<DWORD*>(parameters->dllBaseAddress + relocationData->VirtualAddress + baseRelocationInfo->offset);
				*fixAddress += static_cast<DWORD>(relocationOffset);
			}
		}

		relocationData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<DWORD_PTR>(relocationData) + relocationData->SizeOfBlock);
	}

	IMAGE_IMPORT_DESCRIPTOR* const importDescriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(parameters->dllBaseAddress + parameters->DirectoryImportAddr);

	for (size_t index{}; importDescriptor[index].Characteristics != 0; index++) {

		char* moduleName = reinterpret_cast<char*>(parameters->dllBaseAddress + importDescriptor[index].Name);
		HMODULE loadedModuleHandle = parameters->LoadLibraryAAddress(moduleName);

		if(!loadedModuleHandle)
			return;

		IMAGE_THUNK_DATA* addressTableEntry = reinterpret_cast<IMAGE_THUNK_DATA*>(parameters->dllBaseAddress + importDescriptor[index].FirstThunk);
		IMAGE_THUNK_DATA* nameTableEntry    = reinterpret_cast<IMAGE_THUNK_DATA*>(parameters->dllBaseAddress + importDescriptor[index].OriginalFirstThunk);

		if (nameTableEntry == nullptr) {
			nameTableEntry = addressTableEntry;
		}

		for (; nameTableEntry->u1.Function != 0; nameTableEntry++, addressTableEntry++) {

			IMAGE_IMPORT_BY_NAME* importedFunction = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(parameters->dllBaseAddress + nameTableEntry->u1.AddressOfData);

			if (nameTableEntry->u1.Ordinal & IMAGE_ORDINAL_FLAG)
			{
				addressTableEntry->u1.Function = reinterpret_cast<uint64_t>(parameters->GetProcAddressAddress(loadedModuleHandle, MAKEINTRESOURCEA(nameTableEntry->u1.Ordinal)));
			} else 
			{
				addressTableEntry->u1.Function = reinterpret_cast<uint64_t>(parameters->GetProcAddressAddress(loadedModuleHandle, importedFunction->Name));
			}
		}
	}


	if (parameters->SizeTLSCallBack > 0)
	{
		IMAGE_TLS_DIRECTORY* baseTlsEntries = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(parameters->dllBaseAddress + parameters->TLSEntryVirtualAddress);
		PIMAGE_TLS_CALLBACK* tlsCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(baseTlsEntries->AddressOfCallBacks);

		while (tlsCallback != nullptr) 
		{
			(*tlsCallback)(reinterpret_cast<void*>(parameters->dllBaseAddress), DLL_PROCESS_ATTACH, nullptr);
			tlsCallback++;
		}
	}

	using DllMainPtr = BOOL(__stdcall*)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);

	const auto DllMain = reinterpret_cast<DllMainPtr>(parameters->dllBaseAddress + parameters->AddressEntryPoint);

		DllMain(reinterpret_cast<HINSTANCE>(parameters->dllBaseAddress), DLL_PROCESS_ATTACH, nullptr);

}



/*
void injector::manualMapper(RelocationParameters* param)
{
	// 1) base relocation


	/// get the data from the .reloc section
	auto relocationData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(param->dllBaseAddress() + param->DirectoryBaseRelocationAddr());
	const uint64_t  relocationOffset = param->dllBaseAddress - param->ImageBase();


	size_t count = (relocationData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(unsigned short);
	auto relocationInfo = reinterpret_cast<IMAGE_RELOCATION_ENTRY*>(relocationData->VirtualAddress + sizeof(IMAGE_RELOCATION_ENTRY));

	if (!relocationData)
		return;

	if(!param->SizeBaseRelocation())
		return;

	// iterate over the relocation entry 
	for (size_t i = 0; i < count; count++)
	{
		if(relocationData->VirtualAddress == 0) 
			break;

		uint64_t relocationFixAddr = param->dllBaseAddress + relocationData->VirtualAddress + relocationInfo->offset;
		relocationFixAddr += static_cast<uint64_t>(relocationOffset);
	}

	relocationData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(relocationData->VirtualAddress + relocationInfo->offset);

	// 2) handle import

	auto importDescriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(param->dllBaseAddress + param->DirectoryImportAddr());
	if (!importDescriptor)
		return;


	
	// iterate over each IMAGE_IMPORT_DESCRIPTOR
	for(size_t i = 0; importDescriptor[i].Characteristics != 0; i++)
	{
		//retrieve the module name and load it
		char* moduleName		   = reinterpret_cast<char*>(param->dllBaseAddress + importDescriptor[i].Name);
		HMODULE loadedModuleHandle = param->LoadLibraryAAddress(moduleName);

		if(!loadedModuleHandle)
			return;

		// retrieve the addr of the table entry and his name :)
		IMAGE_THUNK_DATA* AddressTableEntry = reinterpret_cast<IMAGE_THUNK_DATA*>(param->dllBaseAddress + importDescriptor[i].FirstThunk);
		IMAGE_THUNK_DATA* nameTableEntry = reinterpret_cast<IMAGE_THUNK_DATA*>(param->dllBaseAddress + importDescriptor[i].OriginalFirstThunk);
		
		if (!nameTableEntry)
			nameTableEntry = AddressTableEntry;

		// iterate over each entry  in the name table
		for(; nameTableEntry->u1.Function != 0; nameTableEntry++, AddressTableEntry++)
		{
			IMAGE_IMPORT_BY_NAME* importFunction = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(param->dllBaseAddress + nameTableEntry->u1.AddressOfData);

			// check if the entry ordinal or a name
			if(nameTableEntry->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
				AddressTableEntry->u1.Function = reinterpret_cast<ULONGLONG>(param->GetProcAddressAddress(loadedModuleHandle, MAKEINTRESOURCEA(nameTableEntry->u1.Ordinal)) );
			} else {
				AddressTableEntry->u1.Function = reinterpret_cast<ULONGLONG>(param->GetProcAddressAddress(loadedModuleHandle, importFunction->Name));
			}
		}

	}

	// 3) TLS callback

	if(param->SizeTLSCallBack() > 0)
	{
		IMAGE_TLS_DIRECTORY* tlsEntry    = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(param->dllBaseAddress + param->TLSEntryVirtualAddress());
		PIMAGE_TLS_CALLBACK* tlsCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(tlsEntry->AddressOfCallBacks);

		while (!tlsEntry)
		{
			// call function
			(*tlsCallback)( reinterpret_cast<uint64_t*>(param->LoadLibraryAAddress), DLL_PROCESS_ATTACH, nullptr);
			++tlsCallback;
		}
	}


	// 5) call DLL Entry point
	using DllMainPtr = BOOL(__stdcall*)(HINSTANCE hinstDLL,
		DWORD fdwReason, LPVOID lpvReserved);

	DllMainPtr DllMain = reinterpret_cast<DllMainPtr>(param->dllBaseAddress + param->AddressEntryPoint());

	DllMain(reinterpret_cast<HINSTANCE>(param->dllBaseAddress), DLL_PROCESS_ATTACH, nullptr);

}*/



