#include "proc.h"
#include "utils.h"

int main()
{
	mem myMem{ "Untitled - Notepad" };

#ifdef _DEBUG
	printf("[pid] %d\t[hProc] 0x%zX\n", myMem.GetPid(), myMem.GethProc());
#endif


	//std::string dllPath{ utils::GetDllPath() };
	std::string dllPath{ "C:\\Users\\A6\\Documents\\c++\\Dumb shit\\DummyDLL\\x64\\Debug\\DummyDLL.dll" };
	
	std::vector<char> image{ utils::ReadFile(dllPath)};
	PeHeader PeImage{ image };

	uint64_t baseAddress{ utils::WriteFileIntoProc(image, &myMem, &PeImage) };

	PeImage.HandleImport(baseAddress, &myMem);


}