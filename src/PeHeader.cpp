#include "PeHeader.h"

PeHeader::PeHeader(std::vector<char>& fileBytes)
{
	m_dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(fileBytes.data());
	if (m_dosHeader->e_magic != IMAGE_DOS_SIGNATURE) { utils::ErrorMsgExit("dos header invalid", false); }

	m_ntHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(fileBytes.data() + m_dosHeader->e_lfanew);
	if (m_ntHeader->Signature != IMAGE_NT_SIGNATURE) { utils::ErrorMsgExit("NT header invalid", false); }

	m_fileHeader = &m_ntHeader->FileHeader;
	if (m_fileHeader->Machine != IMAGE_FILE_MACHINE_AMD64) { utils::ErrorMsgExit("Invalid platform", false); }

	m_currentSection = IMAGE_FIRST_SECTION(m_ntHeader);
}

