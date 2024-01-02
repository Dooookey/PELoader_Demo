// PELoader_Demo.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <Windows.h>
#include "MmLoadDll.h"

int main()
{
    wchar_t szFileName[MAX_PATH] = L"C:\\Users\\dell\\OneDrive\\桌面\\哔哩哔哩学习\\PE Learn\\PELoader_Demo\\Debug\\TestDLL_01.dll";
    HANDLE hFile = CreateFile(
        szFileName, 
        GENERIC_READ | GENERIC_WRITE, 
        FILE_SHARE_READ | FILE_SHARE_WRITE, 
        NULL, 
        OPEN_EXISTING, 
        FILE_ATTRIBUTE_ARCHIVE, 
        NULL
    );
    if (INVALID_HANDLE_VALUE == hFile)
    {
        printf("CreateFile Failed: %d\n", GetLastError());
        return 0;
    }
    DWORD dwFileSize = GetFileSize(hFile, NULL);
    printf("FileSize: %d\n", dwFileSize);
    // 申请动态内存并读取DLL到内存中
    PBYTE lpData = new BYTE[dwFileSize];
    if (lpData == NULL)
    {
        printf("申请内存出错: %d\n", GetLastError());
        return 0;
    }
    DWORD dwRet = 0;
    BOOL bRet =  ReadFile(hFile, lpData, dwFileSize, &dwRet, NULL);
    if (!bRet)
    {
        printf("ReadFile Failed: %d\n", GetLastError());
        return 0;
    }
    printf("lpData: %08x\n", *(short*)lpData);
    // 将内存DLL加载到程序中
    LPVOID lpBaseAddress = MmLoadLibrary(lpData, dwFileSize);
    if (lpBaseAddress == NULL)
    {
        printf("MmLoadLibrary Failed: %d\n", GetLastError());
        return 0;
    }
    printf("DLL加载成功\n");

    // 获取DLL导出函数并调用
    typedef void (*typedef_ShowMessage)();
    const char* szName = "ShowMessage";
    typedef_ShowMessage ShowMessage = (typedef_ShowMessage)MmGetProcAddress(lpBaseAddress, (wchar_t*)szName);
    if (NULL == ShowMessage)
    {
        printf("MmGetProcAddress Failed\n");
        return 0;
    }
    ShowMessage();
    // 释放从内存加载的DLL
    BOOL bRet1 = MmFreeLibrary(lpBaseAddress);
    if (FALSE == bRet1)
    {
        printf("MmFreeLibrary Failed\n");
        return 0;
    }
    // 释放
    delete[] lpData;
    lpData = NULL;
    CloseHandle(hFile);

    //system("pause");
    return 0;
}
