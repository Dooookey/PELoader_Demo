#include "MmLoadDll.h"

/*
* ģ��LoadLibrary�����ڴ�DLL�ļ���������
* lpData���ڴ�DLL�ļ����ݵĻ�ַ
* dwSize���ڴ�DLL�ļ����ڴ��С
* ����ֵ���ڴ�DLL���ص����̵ļ��ػ�ַ
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
	// �޸�ҳ����, Ӧ�ø���ÿ��ҳ�����Ե����������Ӧ�ڴ�ҳ������
	// ֪ͨ���ó�һ������PAGE_EXECUTE_READWRITE
	DWORD dwOldProctect = 0;
	if (FALSE == VirtualProtect(lpBaseAddress, dwSizeOfImage, PAGE_EXECUTE_READWRITE, &dwOldProctect))
	{
		printf("VirtualProtect Failed\n");
		return 0;
	}

	// �޸�PE�ļ����ػ�ַIMAGE_NT_HEADERS->OptionalHeader.ImageBase
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
* ����PE�ṹ����ȡPE�ļ����ص��ڴ��ľ����С
* lpData���ڴ�DLL�ļ����ݵĻ�ַ
* ����ֵ������PE�ļ��ṹ��IMAGE_NT_HEADERS->OptionalHeader.SizeOfImageֵ�Ĵ�С
*/
DWORD GetSizeOfImage(LPVOID lpData)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)lpData;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + (DWORD)lpData);

	return pNtHeader->OptionalHeader.SizeOfImage;
}

/*
* ���ڴ�DLL���ݰ�SectionAlignment��С����ӳ�䵽�����ڴ���
* lpData: FileBuffer���ݻ�ַ
* lpBaseAddress: ImageBuffer���ݻ�ַ
* ����ֵ: �ɹ�����TRUE�����򷵻�FALSE
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

	// ѭ������DLL������е�DLL����ȡ������еĺ�����ַ
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

		// ��ȡ�������DLL�����Ʋ�����DLL
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
		// ��ȡOriginalFirstThunk�Լ���Ӧ�ĵ��뺯�����Ʊ��׵�ַ
		lpImportNameArray = (PIMAGE_THUNK_DATA)((DWORD)pDosHeader + pImportTable->OriginalFirstThunk);
		// ��ȡFirstThunk�Լ���Ӧ�ĵ��뺯����ַ���׵�ַ
		lpImportFuncAddrArray = (PIMAGE_THUNK_DATA)((DWORD)pDosHeader + pImportTable->FirstThunk);
		while (TRUE)
		{
			if (0 == lpImportNameArray[i].u1.AddressOfData)
			{
				break;
			}

			// ��ȡIMAGE_IMPORT_BY_NAME�ṹ
			lpImportByName = (PIMAGE_IMPORT_BY_NAME)((DWORD)pDosHeader + lpImportNameArray[i].u1.AddressOfData);

			// �жϵ�����������ŵ������Ǻ������Ƶ���
			if (0x80000000 & lpImportNameArray[i].u1.Ordinal)
			{
				// ��ŵ���
				// ��IMAGE_THUNK_DATAֵ�����λΪ1ʱ����ʾ��������ŷ�ʽ���룬��ʱ����λ��������һ���������
				lpFuncAddress = ::GetProcAddress(hDll, (LPCSTR)(lpImportNameArray[i].u1.Ordinal & 0x0000FFFF));
			}
			else
			{
				// ���Ƶ���
				lpFuncAddress = ::GetProcAddress(hDll, (LPCSTR)lpImportByName->Name);
			}
			// ע��˴��ĺ�����ַ��ĸ�ֵ��Ҫ����PE��ʽ����װ�أ���Ҫ�����ˣ�����
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
	// ������ں���,���ӽ���DLL_PROCESS_ATTACH
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
