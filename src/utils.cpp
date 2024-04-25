#include "utils.h"

std::vector<char> utils::ReadFile(std::string_view dllPath)
{
	std::ifstream fileStream(dllPath.data(), std::ios::in | std::ios::binary | std::ios::ate);


	if (!std::filesystem::exists(dllPath.data()))
	{
		fileStream.close();
		ErrorMsgExit("the path doesn't exist", false);
	}

	if (std::filesystem::path(dllPath.data()).extension().string().compare(".dll") == -1) {
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
	lastError ? printf("[-] %s: %zX \n", msg.data(), GetLastError()) : printf("[-] %s\n", msg.data());
	exit(EXIT_FAILURE);
}

