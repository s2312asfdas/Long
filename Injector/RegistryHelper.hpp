#pragma once
#include <windows.h>
#include <tchar.h>
#include <iostream>
#define WINDOWS  _T("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows")	

// ����AppInit_Dlls��ֵ���ڵ���LoadLibrary(user32.dll)ʱ����
/*
RegOpenKeyEx����һ��ָ����ע����
	HKEY hKey,			//��Ҫ�򿪵�����������       HKEY_LOCAL_MACHINE����ǰ�����
	LPCTSTR lpSubKey,	//��Ҫ�򿪵��Ӽ�������
	DWORD ulOptions,	//��������Ϊ0
	REGSAM samDesired,  //��ȫ���ʱ�ǣ�Ҳ����Ȩ��
	PHKEY phkResult     //���ڷ��أ��õ���Ҫ�򿪼��ľ��
        ����ֵ���ɹ��򷵻�0(LONG��)
		ʧ�ܣ�IsOk=2������0���ַ������⣬���ܽ�char*ת��ΪLPCWSTR
		ʧ�ܣ�IsOk=5������0��Ȩ�޲�����Ҫ�Թ���Ա��ʽ����VS����
        ע�⣬Ҫ��RegCloseKey�ر�
*/
/*
RegSetValueEx������ָ��ֵ�����ݺ�����
	HKEY hKey,				//�Ѵ���ľ��
	LPCTSTR lpValueName,	//������ֵ������
	DWORD Reserved,			//��������Ϊ0
	DWORD dwType,			//�����洢����������    REG_SZ��һ����0��β���ַ���
	CONST BYTE *lpData,		//һ������������������Ϊָ��ֵ���ƴ洢������
	DWORD cbData			//lpData������ָ������ݵĴ�С

*/
namespace  _REGISTER_HELPER_
{
	LONG  registry_inject_helper(TCHAR* dll_fullpath);
	LONG  registry_inject_helper(TCHAR* dll_fullpath)
	{
		HKEY key_handle = NULL;
		BYTE buffer_data[MAX_PATH] = { 0 };
		LONG is_ok = RegOpenKeyEx(HKEY_LOCAL_MACHINE, WINDOWS, 0, KEY_ALL_ACCESS, &key_handle);//�򿪶�Ӧ��
		if (is_ok != ERROR_SUCCESS)
		{
			_tprintf(_T("RegOpenKeyEx() Error!\n"));
			goto Exit;
		}
		memcpy(buffer_data, dll_fullpath, (_tcslen(dll_fullpath) + 1) * sizeof(TCHAR));
		//д���ֵ	
		is_ok = RegSetValueEx(key_handle, _T("AppInit_DLLs"), 0, REG_SZ, buffer_data, (_tcslen(dll_fullpath) + 1));	
		if (is_ok != ERROR_SUCCESS)
		{
			_tprintf(_T("RegSetKeyValue() Error!\n"));
			goto Exit;
		}
	Exit:
		if (key_handle)
			RegCloseKey(key_handle);
		return is_ok;
	}


}
