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

//���ܣ���ȡ���뷨����ַ���
void InjectClass::GetImeHandleString()
{
	//���ָ���̵߳Ļ���̲���
	HKL iHandle = GetKeyboardLayout(NULL);

	//���������뷨���̲���
	::ActivateKeyboardLayout(InputHandle, NULL);
	//��ȡ���뷨���̲���
	::GetKeyboardLayoutName(ImeSymbol);
	//����ԭ������̲���
	::ActivateKeyboardLayout(iHandle, NULL);
}


//���ܣ����뷨ע�� 
bool InjectClass::ImeInstall(LPCWSTR lpszdllName)
{

	//����ԭʼ���̲���

	::SystemParametersInfo(SPI_GETDEFAULTINPUTLANG, NULL, oldInputHandle, NULL);

	//�����ļ���Ŀ¼

	//����Ҫ����  ��Դ�Ը� CopyFile(L"Freeime.dll",L"C:\\WINDOWS\\SYSTEM32\\Freeime.ime",FALSE);

	//CopyFile(L"Gamedll.dll",L"C:\\WINDOWS\\SYSTEM32\\Gamedll.dll",FALSE);

	//�������뷨IME�ļ�,������ǰ����أ���������DLL�����������

	hModule = LoadLibrary(L"C:\\Windows\\System32\\Freeime.ime");

	//�������뷨

	InputHandle = ImmInstallIME(L"C:\\WINDOWS\\SYSTEM32\\Freeime.ime", L"��Ʒ���.12");

	//��ȡ���뷨��ʶ��
	GetImeHandleString();

	if (!ImmIsIME(InputHandle))
	{
		//��������ڣ�ö�����뷨���Ҿ��
		InputHandle = EnumIme(L"�Ϲ⻪��ƴ�����뷨V6.7", L"C:\\WINDOWS\\SYSTEM32\\unispim6.ime");
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


//���ܣ�ö�����뷨�����ؾ��  InputName�����뷨���ƣ�FileName ���뷨�ļ���
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

		//�����ϵͳ�������ĵ�ǰ�����Ӧ�ļ��̲��־�����ú��������������ָ���Ļ�������
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
		//ȡ�����뷨��
		StrCount = ImmGetDescription(HKLList[i], strLayoutText.GetBuffer(256), 256);

		InputString = strLayoutText.Left(StrCount);

		if (InputString == InputName)
		{
			//�õ������뷨���ļ����ƣ����������ͬ���������뷨�����
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