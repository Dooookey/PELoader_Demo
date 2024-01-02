#ifndef _MM_LOAD_DLL_H_
#define _MM_LOAD_DLL_H_

#include <iostream>
#include <Windows.h>

typedef BOOL(WINAPI* typedef_DllMain)(HINSTANCE hInstance,DWORD  ul_reason_for_call,LPVOID lpReserved);

/*
* 模拟LoadLibrary加载内存DLL文件到进程中
* lpData：内存DLL文件数据的基址
* dwSize：内存DLL文件的内存大小
* 返回值：内存DLL加载到进程的加载基址
*/
LPVOID MmLoadLibrary(LPVOID lpData, DWORD dwSize);

/*
* 根据PE结构，获取PE文件加载到内存后的镜像大小
* lpData：内存DLL文件数据的基址
* 返回值：返回PE文件结构中IMAGE_NT_HEADERS->OptionalHeader.SizeOfImage值的大小
*/
DWORD GetSizeOfImage(LPVOID lpData);

/*
* 将内存DLL数据按SectionAlignment大小对齐映射到进程内存中
* lpData: FileBuffer数据基址
* lpBaseAddress: ImageBuffer数据基址
* 返回值: 成功返回TRUE，否则返回FALSE
*/
BOOL MmMapFile(LPVOID lpData, LPVOID lpBaseAddress);

/*
* 修改PE文件重定位表信息
* lpBaseAddress: 内存DLL数据按SectionAlignment大小对齐映射到进程内存中内存基址
* 返回值：成功返回TRUE，否则返回FALSE
*/
BOOL DoRelocationTable(LPVOID lpBaseAddress);
/*
* 填写PE文件导入表信息
* lpBaseAddress: 内存DLL数据按SectionAlignment大小对齐映射到进程内存中的内存基址
* 返回值: 成功返回TRUE, 否则返回FALSE
*/
BOOL DoImportTable(LPVOID lpBaseAddress);
/*
* 修改PE文件加载基址IMAGE_NT_HEADERS->OptionalHeader.ImageBase
* lpBaseAddress: 内存DLL数据按SectionAlignment大小对齐映射到进程内存中的内存基址
* 返回值: 成功返回TRUE, 否则返回FALSE
*/
BOOL SetImageBase(LPVOID lpBaseAddress);
/*
* 调用Dll的入口函数DllMain，函数地址即为PE文件入口点IMAGE_NT_HEADERS->OptionalHeader.AddressOfEntryPoint
* lpBaseAddress: 内存DLL数据按SectionAlignment大小对齐映射到进程内存中的内存基址
* 返回值: 成功返回TRUE, 否则返回FALSE
*/
BOOL CallDllMain(LPVOID lpBaseAddress);
/*
* 模拟GetProcAddress获取内存DLL导出函数
* lpBaseAddress: 内存DLL文件加载到进程中的加载基址
* lpszFunName: 导出函数的名称
* 返回值: 返回导出函数的地址
*/
LPVOID MmGetProcAddress(LPVOID lpBaseAddress, wchar_t* lpszFuncName);
/*
* 释放内存加载的DLL到进程内存的空间
* lpBaseAddress: 内存DLL数据按SectionAlignment大小对齐映射到进程内存中的内存基址
* 返回值: 成功返回TRUE, 否则返回FALSE
*/
BOOL MmFreeLibrary(LPVOID lpBaseAddress);

#endif