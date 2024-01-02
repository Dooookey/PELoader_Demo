// TestDll.cpp : 定义 DLL 应用程序的导出函数。
//

#include "pch.h"
#include <Windows.h>

void ShowMessage()
{
    MessageBox(NULL, L"I`m DLL File", L"HELLO", MB_OK);
}