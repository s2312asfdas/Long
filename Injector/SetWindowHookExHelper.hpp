#pragma once
#include <windows.h>
#include <iostream>
#include <tchar.h>
#include <vector>
#include"ThreadHelper.h"

namespace _SETWINDOWHOOK_HELPER_
{
	void setwindow_inject_helper()
	{
		_tsetlocale(0, _T("Chinese-simplified"));
		_ERROR_HELPER_::SeInitializeMember();
		_MEMORY_HELPER_::SeInitializeMember();
		_SYSTEM_HELPER_::SeInitializeMember();
		HANDLE process_identify = 0;
		TCHAR  process_imagename[MAX_PATH] = { 0 };
		HANDLE process_handle = INVALID_HANDLE_VALUE;
		SIZE_T return_length = 0;
		LPVOID virtual_address = NULL;
		TCHAR  buffer_data[MAX_PATH] = { 0 };
		BOOL   is_ok = FALSE;
		int    last_error = 0;
		TCHAR  v3[MAX_PATH] = { 0 };
		TCHAR* process_fullpath = v3;
		ULONG_PTR process_fullpath_length = MAX_PATH;
		vector<HANDLE>   thread_identify;
		HHOOK hook_handle = NULL;
		FARPROC text_1 = NULL;
		HMODULE module_base = NULL;

		_tprintf(_T("Please Input a ProcessName:\r\n"));
		//_tscanf(_T("%s"), &ProcessImageName);
		int i = 0;
		_gettchar();
		TCHAR v1 = _gettchar();
		while (v1 != '\n')
		{
			process_imagename[i++] = v1;
			v1 = _gettchar();
		}
		BOOL iswow64_1 = FALSE;
		BOOL iswow64_2 = FALSE;
		GetCurrentDirectory(MAX_PATH, buffer_data);
		//获得当前进程的进程位数
		IsWow64Process(GetCurrentProcess(), &iswow64_1);
		is_ok = _PROCESS_HELPER_::SeGetProcessIdentify(&process_identify, sizeof(HANDLE),
			process_imagename, MAX_PATH * sizeof(TCHAR));
		if (is_ok == FALSE)
		{
			last_error = GetLastError();
			goto Exit;
		}
		is_ok = _PROCESS_HELPER_::SeGetProcessFullPath(&process_fullpath, &process_fullpath_length, process_identify, FALSE);
		if (is_ok == FALSE)
		{
			last_error = GetLastError();
			goto Exit;
		}
		if (_PROCESS_HELPER_::SeIsWow64Process(process_fullpath, process_fullpath_length, &iswow64_2) == FALSE)
		{
			last_error = GetLastError();
			goto Exit;
		}
		if (iswow64_1 == TRUE && iswow64_2 == TRUE)
		{
			_tcscat_s(buffer_data, _T("\\Dll.dll"));
		}
		else if (iswow64_1 == FALSE && iswow64_2 == FALSE)
		{
			_tcscat_s(buffer_data, _T("\\Dll.dll"));
		}
		else if (iswow64_1 == TRUE && iswow64_2 == FALSE)
		{
			//使用Wow64系列函数
			goto Exit;
		}
		else
		{
			//?????(64->32)
			goto Exit;
		}
		if (_THREAD_HELPER_::SeGetThreadIdentify(process_identify, thread_identify) == FALSE)
		{
			last_error = GetLastError();
			goto Exit;
		}
		module_base = LoadLibrary(buffer_data);
		if (module_base == NULL)
		{
			last_error = GetLastError();
			goto Exit;
		}
		text_1 = GetProcAddress(module_base, "text_1");
		if (text_1 == NULL)
		{
			last_error = GetLastError();
			goto Exit;
		}
		for (int i = 0; i < thread_identify.size(); ++i)
		{
			//WH_KEYBOARD 用来对底层的键盘输入事件进行监视
			hook_handle = SetWindowsHookEx(WH_KEYBOARD, (HOOKPROC)text_1, module_base, (DWORD)thread_identify[i]);//
			if (hook_handle != NULL)
			{
				break;
			}
		}
		_tprintf(_T("Input AnyKey To Exit\r\n"));
		_gettchar();
	Exit:
		if (hook_handle != NULL)
		{
			UnhookWindowsHookEx(hook_handle);  //Remove Dll 
			hook_handle = NULL;
		}
		if (thread_identify.empty() == false)
		{
			vector<HANDLE>().swap(thread_identify);    //vector<>stl  
		}
		if (!!(thread_identify.size()))
		{
			//ThreadIdentify.~vector();
			vector<HANDLE>().swap(thread_identify);
		}
		if (module_base != NULL)
		{
			FreeLibrary(module_base);
			module_base = NULL;
		}
	}


}