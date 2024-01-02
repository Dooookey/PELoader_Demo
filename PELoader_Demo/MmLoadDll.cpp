#include "MmLoadDll.h"

/*
* 模拟LoadLibrary加载内存DLL文件到进程中
* lpData：内存DLL文件数据的基址
* dwSize：内存DLL文件的内存大小
* 返回值：内存DLL加载到进程的加载基址
*/
LPVOID MmLoadLibrary(LPVOID lpData, DWORD dwSize)
{
	DWORD dwSizeOfImage = GetSizeOfImage(lpData);
	LPVOID lpBaseAddress = VirtualAllocEx(GetCurrentProcess(), NULL, dwSizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (lpBaseAddress == NULL)
	{
		printf("VirtualAllocEx Failed: %d\n", GetLastError());
		return 0;
	}
	RtlZeroMemory(lpBaseAddress, dwSizeOfImage);

	if (FALSE == MmMapFile(lpData, lpBaseAddress))
	{
		printf("MmMapFile Failed: %d\n", GetLastError());
		return 0;
	}
	if (FALSE == DoRelocationTable(lpBaseAddress))
	{
		printf("DoRelocationTable Failed: %d\n", GetLastError());
		return 0;
	}
	if (FALSE == DoImportTable(lpBaseAddress))
	{
		printf("DoImportTable Failed: %d\n", GetLastError());
		return 0;
	}
	// 修改页属性, 应该根据每个页的属性单独设置其对应内存页的属性
	// 通知设置成一个属性PAGE_EXECUTE_READWRITE
	DWORD dwOldProctect = 0;
	if (FALSE == VirtualProtect(lpBaseAddress, dwSizeOfImage, PAGE_EXECUTE_READWRITE, &dwOldProctect))
	{
		printf("VirtualProtect Failed\n");
		return 0;
	}

	// 修改PE文件加载基址IMAGE_NT_HEADERS->OptionalHeader.ImageBase
	if (FALSE == SetImageBase(lpBaseAddress))
	{
		printf("SetImageBase Failed\n");
		return 0;
	}
	if (FALSE == CallDllMain(lpBaseAddress))
	{
		printf("CallDllMain Failed\n");
		return 0;
	}
	return lpBaseAddress;
}

/*
* 根据PE结构，获取PE文件加载到内存后的镜像大小
* lpData：内存DLL文件数据的基址
* 返回值：返回PE文件结构中IMAGE_NT_HEADERS->OptionalHeader.SizeOfImage值的大小
*/
DWORD GetSizeOfImage(LPVOID lpData)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)lpData;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + (DWORD)lpData);

	return pNtHeader->OptionalHeader.SizeOfImage;
}

/*
* 将内存DLL数据按SectionAlignment大小对齐映射到进程内存中
* lpData: FileBuffer数据基址
* lpBaseAddress: ImageBuffer数据基址
* 返回值: 成功返回TRUE，否则返回FALSE
*/
BOOL MmMapFile(LPVOID lpData, LPVOID lpBaseAddress)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)lpData;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + (DWORD)lpData);
	DWORD dwSizeOfHeaders = pNt->OptionalHeader.SizeOfHeaders;
	DWORD dwNumOfSections = pNt->FileHeader.NumberOfSections;
	RtlCopyMemory(lpBaseAddress, lpData, dwSizeOfHeaders);
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
	for (size_t i = 0; i < dwNumOfSections; i++)
	{
		if ((0 == pSection[i].VirtualAddress) || (0 == pSection[i].PointerToRawData))
		{
			continue;
		}
		LPVOID lpSrcMem = (LPVOID)(pSection[i].PointerToRawData + (DWORD)lpData);
		LPVOID lpDesMem = (LPVOID)(pSection[i].VirtualAddress + (DWORD)lpBaseAddress);
		DWORD dwSizeOfRawData = pSection[i].SizeOfRawData;
		RtlCopyMemory(lpDesMem, lpSrcMem, dwSizeOfRawData);
	}
	return TRUE;
}

BOOL DoRelocationTable(LPVOID lpBaseAddress)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)lpBaseAddress;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + (DWORD)lpBaseAddress);
	PIMAGE_DATA_DIRECTORY pDataDir = (PIMAGE_DATA_DIRECTORY)(pNt->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_BASERELOC);
	PIMAGE_BASE_RELOCATION pBaseRelcation = (PIMAGE_BASE_RELOCATION)(pDataDir->VirtualAddress + (DWORD)lpBaseAddress);

	if ((PVOID)pBaseRelcation == (PVOID)pNt)
	{
		return TRUE;
	}
	while ((pBaseRelcation->VirtualAddress + pBaseRelcation->SizeOfBlock) != 0)
	{
		PWORD pLocData = (PWORD)((PBYTE)pBaseRelcation + sizeof(IMAGE_BASE_RELOCATION));
		DWORD dwNumOfReloc = (pBaseRelcation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
		for (size_t i = 0; i < dwNumOfReloc; i++)
		{
			if ((DWORD)(pLocData[i] & 0x0000F000) == 0x00003000)
			{
				PDWORD pAddress = (PDWORD)((PBYTE)pDos + pBaseRelcation->VirtualAddress + (pLocData[i] & 0x0FFF));
				DWORD dwDelta = (DWORD)pDos - pNt->OptionalHeader.ImageBase;
				*pAddress += dwDelta;
			}

		}
		pBaseRelcation = (PIMAGE_BASE_RELOCATION)((PBYTE)pBaseRelcation + pBaseRelcation->SizeOfBlock);
	}
	return TRUE;
}

BOOL DoImportTable(LPVOID lpBaseAddress)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBaseAddress;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((ULONG32)pDosHeader + pDosHeader->e_lfanew);
	PIMAGE_IMPORT_DESCRIPTOR pImportTable = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)pDosHeader +
		pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	// 循环遍历DLL导入表中的DLL及获取导入表中的函数地址
	char* lpDllName = NULL;
	HMODULE hDll = NULL;
	PIMAGE_THUNK_DATA lpImportNameArray = NULL;
	PIMAGE_IMPORT_BY_NAME lpImportByName = NULL;
	PIMAGE_THUNK_DATA lpImportFuncAddrArray = NULL;
	FARPROC lpFuncAddress = NULL;
	DWORD i = 0;

	while (TRUE)
	{
		if (0 == pImportTable->OriginalFirstThunk)
		{
			break;
		}

		// 获取导入表中DLL的名称并加载DLL
		lpDllName = (char*)((DWORD)pDosHeader + pImportTable->Name);
		hDll = ::GetModuleHandleA(lpDllName);
		if (NULL == hDll)
		{
			hDll = ::LoadLibraryA(lpDllName);
			if (NULL == hDll)
			{
				pImportTable++;
				continue;
			}
		}

		i = 0;
		// 获取OriginalFirstThunk以及对应的导入函数名称表首地址
		lpImportNameArray = (PIMAGE_THUNK_DATA)((DWORD)pDosHeader + pImportTable->OriginalFirstThunk);
		// 获取FirstThunk以及对应的导入函数地址表首地址
		lpImportFuncAddrArray = (PIMAGE_THUNK_DATA)((DWORD)pDosHeader + pImportTable->FirstThunk);
		while (TRUE)
		{
			if (0 == lpImportNameArray[i].u1.AddressOfData)
			{
				break;
			}

			// 获取IMAGE_IMPORT_BY_NAME结构
			lpImportByName = (PIMAGE_IMPORT_BY_NAME)((DWORD)pDosHeader + lpImportNameArray[i].u1.AddressOfData);

			// 判断导出函数是序号导出还是函数名称导出
			if (0x80000000 & lpImportNameArray[i].u1.Ordinal)
			{
				// 序号导出
				// 当IMAGE_THUNK_DATA值的最高位为1时，表示函数以序号方式输入，这时，低位被看做是一个函数序号
				lpFuncAddress = ::GetProcAddress(hDll, (LPCSTR)(lpImportNameArray[i].u1.Ordinal & 0x0000FFFF));
			}
			else
			{
				// 名称导出
				lpFuncAddress = ::GetProcAddress(hDll, (LPCSTR)lpImportByName->Name);
			}
			// 注意此处的函数地址表的赋值，要对照PE格式进行装载，不要理解错了！！！
			lpImportFuncAddrArray[i].u1.Function = (DWORD)lpFuncAddress;
			i++;
		}

		pImportTable++;
	}

	return TRUE;
}

BOOL SetImageBase(LPVOID lpBaseAddress)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)lpBaseAddress;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + (ULONG32)lpBaseAddress);
	pNt->OptionalHeader.ImageBase = (DWORD)lpBaseAddress;

	return TRUE;
}

BOOL CallDllMain(LPVOID lpBaseAddress)
{
	typedef_DllMain DllMain = NULL;
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBaseAddress;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((ULONG32)pDosHeader + pDosHeader->e_lfanew);
	DllMain = (typedef_DllMain)((DWORD)pDosHeader + pNtHeaders->OptionalHeader.AddressOfEntryPoint);
	// 调用入口函数,附加进程DLL_PROCESS_ATTACH
	BOOL bRet = DllMain((HINSTANCE)lpBaseAddress, DLL_PROCESS_ATTACH, NULL);

	return bRet;
}

LPVOID MmGetProcAddress(LPVOID lpBaseAddress, wchar_t* lpszFuncName)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)lpBaseAddress;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + (DWORD)lpBaseAddress);
	PIMAGE_DATA_DIRECTORY pDataDir = (PIMAGE_DATA_DIRECTORY)(pNt->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_EXPORT);
	PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(pDataDir->VirtualAddress + (DWORD)lpBaseAddress);

	PDWORD dwAddressOfFunctions = (PDWORD)(pExport->AddressOfFunctions + (DWORD)lpBaseAddress);
	PDWORD dwAddressOfNames = (PDWORD)(pExport->AddressOfNames + (DWORD)lpBaseAddress);
	PWORD pwAddressOfNameOrdinals = (PWORD)(pExport->AddressOfNameOrdinals + (DWORD)lpBaseAddress);

	DWORD dwNumberOfNames = pExport->NumberOfNames;
	for (size_t i = 0; i < dwNumberOfNames; i++)
	{
		if (!dwAddressOfFunctions[i])
		{
			continue;
		}
		PWCHAR szFuncName = (PWCHAR)(dwAddressOfNames[i] + (DWORD)lpBaseAddress);
		if (lstrcmpi(lpszFuncName, szFuncName) == 0)
		{
			return (LPVOID)(dwAddressOfFunctions[pwAddressOfNameOrdinals[i]] + (DWORD)pDos);
			break;
		}
	}

	return LPVOID();
}

BOOL MmFreeLibrary(LPVOID lpBaseAddress)
{
	BOOL bRet = NULL;
	if (NULL == lpBaseAddress)
	{
		return bRet;
	}
	bRet = VirtualFree(lpBaseAddress, 0, MEM_RELEASE);
	lpBaseAddress = NULL;
	return bRet;
}
