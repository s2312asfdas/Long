#pragma once
#include <windows.h>
#include <tchar.h>
#include <iostream>
#define WINDOWS  _T("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows")	

// 利用AppInit_Dlls键值会在调用LoadLibrary(user32.dll)时加载
/*
RegOpenKeyEx：打开一个指定的注册表键
	HKEY hKey,			//需要打开的主键的名称       HKEY_LOCAL_MACHINE：当前计算机
	LPCTSTR lpSubKey,	//需要打开的子键的名称
	DWORD ulOptions,	//保留，设为0
	REGSAM samDesired,  //安全访问标记，也就是权限
	PHKEY phkResult     //用于返回，得到将要打开键的句柄
        返回值：成功则返回0(LONG型)
		失败：IsOk=2，而非0。字符集问题，不能将char*转换为LPCWSTR
		失败：IsOk=5，而非0。权限不够，要以管理员方式启动VS！！
        注意，要用RegCloseKey关闭
*/
/*
RegSetValueEx：设置指定值的数据和类型
	HKEY hKey,				//已打开项的句柄
	LPCTSTR lpValueName,	//欲设置值的名称
	DWORD Reserved,			//保留，设为0
	DWORD dwType,			//将被存储的数据类型    REG_SZ：一个以0结尾的字符串
	CONST BYTE *lpData,		//一个缓冲区，包含了欲为指定值名称存储的数据
	DWORD cbData			//lpData参数所指向的数据的大小

*/
namespace  _REGISTER_HELPER_
{
	LONG  registry_inject_helper(TCHAR* dll_fullpath);
	LONG  registry_inject_helper(TCHAR* dll_fullpath)
	{
		HKEY key_handle = NULL;
		BYTE buffer_data[MAX_PATH] = { 0 };
		LONG is_ok = RegOpenKeyEx(HKEY_LOCAL_MACHINE, WINDOWS, 0, KEY_ALL_ACCESS, &key_handle);//打开对应键
		if (is_ok != ERROR_SUCCESS)
		{
			_tprintf(_T("RegOpenKeyEx() Error!\n"));
			goto Exit;
		}
		memcpy(buffer_data, dll_fullpath, (_tcslen(dll_fullpath) + 1) * sizeof(TCHAR));
		//写入键值	
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
