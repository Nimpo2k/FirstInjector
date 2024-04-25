#pragma once

#include <Windows.h>
#include <vector>

#include "utils.h"
#include "proc.h"

class mem;



class PeHeader
{
private:
	IMAGE_DOS_HEADER*      m_dosHeader;
	IMAGE_NT_HEADERS*      m_ntHeader;
	IMAGE_FILE_HEADER*     m_fileHeader;
	_IMAGE_SECTION_HEADER* m_currentSection;
public:

	PeHeader(std::vector<char>& fileBytes);
	

	size_t GetSize() const {
		return m_ntHeader->OptionalHeader.SizeOfImage;
	}

	uint64_t GetEntryPointAddr() const {
		return m_ntHeader->OptionalHeader.AddressOfEntryPoint;
	}

	unsigned short GetNumberOfSection() const {
		return m_ntHeader->FileHeader.NumberOfSections;
	}

	uint64_t GetImageBase() const {
		return m_ntHeader->OptionalHeader.ImageBase;
	}


	uint64_t CS_GetVirtualAddress() const {
		return m_currentSection->VirtualAddress;
	}

	uint64_t CS_GetPointerToRawData() const {
		return m_currentSection->PointerToRawData;
	}

	uint64_t CS_GetSizeOfRawData() const {
		return m_currentSection->SizeOfRawData;
	}

	auto CS_GetName() const {
		return m_currentSection->Name;
	}

	void IncrementCurrentSection() {
		m_currentSection++;
	}

	uint64_t GetDirectoryImportAddr() const {
		return m_ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	}

	uint64_t GetDirectoryBaseRelocationAddr() const
	{
		return m_ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	}

	size_t GetSizeBaseRelocation() const
	{
		return m_ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
	}

	size_t GetSizeTLSCallBack() const
	{
		return m_ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size;
	}

	uint64_t GetTLSEntryVirtualAddress() const
	{
		return m_ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
	}

	uint64_t GetAddressEntryPoint() const
	{
		return m_ntHeader->OptionalHeader.AddressOfEntryPoint;
	}
};

