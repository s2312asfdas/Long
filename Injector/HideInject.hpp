#pragma once
#include <windows.h>
#include <iostream>
#include <tchar.h>

#include <imm.h>
#pragma comment(lib,"IMM32.lib")

#include"HideInjectHelper.hpp"




InjectClass::InjectClass(void)
{
	HKL InputHandle = NULL;

	HKL oldInputHandle = NULL;
}

InjectClass::~InjectClass(void)
{
}

typedef int  (WINAPI* g_IMESetPubString)(PWCHAR tmpStr, DWORD UnloadDLL, DWORD loadNextIme, DWORD DllData1, DWORD DllData2, DWORD DllData3);
HINSTANCE hModule = NULL;
g_IMESetPubString IMESetPubString = NULL;

//功能：获取输入法句柄字符串
void InjectClass::GetImeHandleString()
{
	//获得指定线程的活动键盘布局
	HKL iHandle = GetKeyboardLayout(NULL);

	//激活新输入法键盘布局
	::ActivateKeyboardLayout(InputHandle, NULL);
	//获取输入法键盘布局
	::GetKeyboardLayoutName(ImeSymbol);
	//激活原来活动键盘布局
	::ActivateKeyboardLayout(iHandle, NULL);
}


//功能：输入法注入 
bool InjectClass::ImeInstall(LPCWSTR lpszdllName)
{

	//保存原始键盘布局

	::SystemParametersInfo(SPI_GETDEFAULTINPUTLANG, NULL, oldInputHandle, NULL);

	//复制文件到目录

	//不需要拷贝  资源自给 CopyFile(L"Freeime.dll",L"C:\\WINDOWS\\SYSTEM32\\Freeime.ime",FALSE);

	//CopyFile(L"Gamedll.dll",L"C:\\WINDOWS\\SYSTEM32\\Gamedll.dll",FALSE);

	//加载输入法IME文件,必须在前面加载，否则会造成DLL共享变量错误。

	hModule = LoadLibrary(L"C:\\Windows\\System32\\Freeime.ime");

	//加载输入法

	InputHandle = ImmInstallIME(L"C:\\WINDOWS\\SYSTEM32\\Freeime.ime", L"极品五笔.12");

	//获取输入法标识符
	GetImeHandleString();

	if (!ImmIsIME(InputHandle))
	{
		//句柄不存在，枚举输入法查找句柄
		InputHandle = EnumIme(L"紫光华宇拼音输入法V6.7", L"C:\\WINDOWS\\SYSTEM32\\unispim6.ime");
	}

	if (hModule)
	{
		IMESetPubString = (g_IMESetPubString)GetProcAddress(hModule, "IMESetPubString");
		if (IMESetPubString)
		{
			/*WCHAR CurPath[MAX_PATH+1] = {NULL};

			wmemset(CurPath,0,MAX_PATH+1);

			GetCurDirectory(CurPath);

			wcscat(CurPath,lpszdllName);*/

			IMESetPubString((PWCHAR)lpszdllName, 0, 0, 0, 0, 0);
		}
		else
		{
			FreeLibrary(hModule);
			return FALSE;
		}
	}
	else
	{
		return FALSE;
	}
	return TRUE;





}


//功能：枚举输入法，返回句柄  InputName：输入法名称，FileName 输入法文件名
HKL InjectClass::EnumIme(CString InputName, CString FileName)
{
	HKL* HKLList;

	HKL Imehandle;

	int StrCount = 0, FileCount = 0;

	HKLList = NULL;

	UINT uCount = GetKeyboardLayoutList(0, NULL);

	if (0 != uCount)
	{
		HKLList = new HKL[uCount];

		//获得与系统中输入点的当前集相对应的键盘布局句柄。该函数将句柄拷贝到指定的缓冲区中
		GetKeyboardLayoutList(uCount, HKLList);

		//TRACE("GetKeyboardLayoutList OK!!\n");
	}
	else
	{
		int nErr = GetLastError();

		//TRACE("Error is %d\n", nErr);
	}

	CString strLayoutText;

	CString strFileText;

	CString InputString;

	CString InputFile;

	for (UINT i = 0; i < uCount; i++)
	{
		//取得输入法名
		StrCount = ImmGetDescription(HKLList[i], strLayoutText.GetBuffer(256), 256);

		InputString = strLayoutText.Left(StrCount);

		if (InputString == InputName)
		{
			//得到该输入法的文件名称，如果名称相同，返回输入法句柄。
			FileCount = ImmGetIMEFileName(HKLList[i], strFileText.GetBuffer(256), 256);

			InputFile = strFileText.Left(FileCount);

			if (InputFile = FileName)
			{
				Imehandle = HKLList[i];

				break;
			}
		}
	}
	delete[]HKLList;

	return Imehandle;
}