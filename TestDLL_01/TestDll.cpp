// TestDll.cpp : ���� DLL Ӧ�ó���ĵ���������
//

#include "pch.h"
#include <Windows.h>

void ShowMessage()
{
    MessageBox(NULL, L"I`m DLL File", L"HELLO", MB_OK);
}