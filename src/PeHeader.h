#pragma once
#include <winnt.h>
#include <vector>


class PeHeader
{
private:
	IMAGE_DOS_HEADER* m_dosHeader;
	IMAGE_NT_HEADERS* m_ntHeader;
	_IMAGE_SECTION_HEADER* m_currentSection;
public:
	
	PeHeader(std::vector<uint8_t>& fileBytes);

	size_t size() const {
		return m_ntHeader->OptionalHeader.SizeOfImage;
	}

	uint64_t entryPointAddr() const {
		return m_ntHeader->OptionalHeader.AddressOfEntryPoint;
	}

	size_t NumberOfSection() const {
		return m_ntHeader->FileHeader.NumberOfSections;
	}

	uint64_t CS_VirtualAddress() const {
		return m_currentSection->VirtualAddress;
	}

	uint64_t CS_PointerToRawData() const {
		return m_currentSection->PointerToRawData;
	}

	uint64_t CS_SizeOfRawData() const {
		return m_currentSection->SizeOfRawData;
	}

	auto CS_Name() const {
		return m_currentSection->Name;
	}

	void IncrementCurrentSection() {
		m_currentSection++;
	}
};