#include "PeHeader.h"


PeHeader::PeHeader(std::vector<uint8_t>& fileBytes)
{
	m_dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(fileBytes.data());
	m_ntHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(fileBytes.data() + m_dosHeader->e_lfanew);
	m_currentSection = IMAGE_FIRST_SECTION(m_ntHeader);
}