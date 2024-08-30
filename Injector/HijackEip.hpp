#pragma once
#include <windows.h>
#include <iostream>
#include <tchar.h>
#include"HijackEipHelper.hpp"
#include"ErrorHelper.h"
#include"MemoryHelper.h"
#include"SystemHelper.h"
#include"ProcessHelper.h"
#include"FileHelper.h"

namespace _HIJACK_EIP_
{
	typedef HMODULE(WINAPI* LPFN_LOADLIBRARYW)(LPCWSTR lpLibFileName);
	typedef HMODULE(WINAPI* LPFN_LOADLIBRARYA)(LPCSTR lpLibFileName);
	void hijack_eip();

#ifdef UNICODE
	LPFN_LOADLIBRARYW LoadLibrary_Pointer = NULL;
#else
	LPFN_LOADLIBRARYA LoadLibrary_Pointer = NULL;
#endif

	void hijack_eip()
	{
		setlocale(LC_ALL, "Chinese-simplified");
		_ERROR_HELPER_::SeInitializeMember();
		_MEMORY_HELPER_::SeInitializeMember();
		_SYSTEM_HELPER_::SeInitializeMember();
		HANDLE process_identify = 0;
		TCHAR  process_imagename[MAX_PATH] = { 0 };
		HANDLE process_handle = INVALID_HANDLE_VALUE;
		SIZE_T return_length = 0;
		LPVOID virtual_address = NULL;
		TCHAR buffer_data[MAX_PATH] = { 0 };
		BOOL  is_ok = FALSE;
		int last_error = 0;
		vector<HANDLE> thread_identify{};
		HMODULE  kernel32_modulebase = NULL;
		ULONG    os_bit = 0;

		_tprintf(_T("Please Input a ProcessName:\r\n"));
		//_tscanf(_T("%s"), &ProcessImageName);
		int i = 0;
		HANDLE ThreadHandle = INVALID_HANDLE_VALUE;
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
		//判断系统位数
		//获得当前进程的进程位数
		is_ok = _PROCESS_HELPER_::SeGetProcessIdentify(&process_identify, sizeof(HANDLE),
			process_imagename, MAX_PATH * sizeof(TCHAR));
		if (is_ok == FALSE)
		{
			last_error = GetLastError();
			goto Exit;
		}
		os_bit = _SYSTEM_HELPER_::SeGetOSBit();
		if (os_bit == 32)
		{
			iswow64_1 = iswow64_2 = TRUE;
		}
		else if (os_bit == 64)
		{
			IsWow64Process(GetCurrentProcess(), &iswow64_1);
			TCHAR v3[MAX_PATH] = { 0 };
			TCHAR* ProcessFullPath = v3;
			ULONG_PTR ProcessFullPathLength = MAX_PATH;
			is_ok = _PROCESS_HELPER_::SeGetProcessFullPath(&ProcessFullPath, &ProcessFullPathLength, process_identify, FALSE);
			if (is_ok == FALSE)
			{
				last_error = GetLastError();
				goto Exit;
			}
			if (_PROCESS_HELPER_::SeIsWow64Process(ProcessFullPath, ProcessFullPathLength, &iswow64_2) == FALSE)
			{
				last_error = GetLastError();
				goto Exit;
			}
		}
		else
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
#ifdef _UNICODE
		is_ok = _FILE_HELPER_::SeGetProcAddressEx(process_identify,
			(PVOID*)&LoadLibrary_Pointer, "Kernel32.dll", "LoadLibraryW");
#else
		is_ok = _FILE_HELPER_::SeGetProcAddressEx(process_identify,
			(PVOID*)&LoadLibrary_Pointer, "Kernel32.dll", "LoadLibraryA");
#endif
		if (LoadLibrary_Pointer == NULL)
		{
			last_error = GetLastError();
			goto Exit;
		}
		//获得目标进程下的所有线程
		if (_THREAD_HELPER_::SeGetThreadIdentify(process_identify, thread_identify) == FALSE)
		{
			last_error = GetLastError();
			goto Exit;
		}
		_HIJACK_EIP_HELPER_::HookEip(process_identify, thread_identify[0], buffer_data, (_tcslen(buffer_data) + 1) * sizeof(TCHAR));

	Exit:
		thread_identify.~vector();
		_tprintf(_T("Input AnyKey To Exit\r\n"));
		getchar();
	}
}