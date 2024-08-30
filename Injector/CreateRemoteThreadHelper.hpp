#pragma once
#include <windows.h>
#include <iostream>
#include <tchar.h>
#include"ErrorHelper.h"
#include"MemoryHelper.h"
#include"SystemHelper.h"
#include"ProcessHelper.h"

namespace _REMOTE_THREAD_INHECT_HELPER_
{
	void create_remotethread_inject_Helper();
	void create_remotethread_inject_Helper()
	{
		setlocale(LC_ALL, "Chinese-simplified");
		_ERROR_HELPER_::SeInitializeMember();
		_MEMORY_HELPER_::SeInitializeMember();
		_SYSTEM_HELPER_::SeInitializeMember();
		HANDLE process_identify = 0;
		TCHAR  process_imageName[MAX_PATH] = { 0 };
		HANDLE process_handle = INVALID_HANDLE_VALUE;
		SIZE_T return_length = 0;
		LPVOID virtual_address = NULL;
		TCHAR buffer_data[MAX_PATH] = { 0 };
		BOOL   is_ok = FALSE;
		int last_error = 0;
		HANDLE thread_handle = NULL;
		HANDLE mapping_handle = NULL;
		ULONG buffer_length = 0;
		TCHAR v3[MAX_PATH] = { 0 };
		TCHAR* process_fullpath = v3;
		ULONG_PTR process_fullpath_Length = MAX_PATH;

		_tprintf(_T("Please Input a ProcessName:\r\n"));
		//_tscanf(_T("%s"), &process_imageName);
		ULONG_PTR v10 = 0;
		int i = 0;
		_gettchar();
		TCHAR v1 = _gettchar();
		while (v1 != '\n')
		{
			process_imageName[i++] = v1;
			v1 = _gettchar();
		}
		BOOL iswow64_1 = FALSE;
		BOOL iswow64_2 = FALSE;
		GetCurrentDirectory(MAX_PATH, buffer_data);
		IsWow64Process(GetCurrentProcess(), &iswow64_1);   //��ǰ���̵�λ��
		//���̵�ImageNameת��ΪProcessIdentify(__NtQuerySystemInformation)
		is_ok = _PROCESS_HELPER_::SeGetProcessIdentify(&process_identify, sizeof(HANDLE),
			process_imageName, MAX_PATH * sizeof(TCHAR));
		if (is_ok == FALSE)
		{
			last_error = GetLastError();
			goto Exit;
		}
		//ͨ������Identify��ý�������·��
		is_ok = _PROCESS_HELPER_::SeGetProcessFullPath(&process_fullpath, &process_fullpath_Length, process_identify, FALSE);
		if (is_ok == FALSE)
		{
			last_error = GetLastError();
			goto Exit;
		}
		//ͨ������·����ȡ�ļ�����  
		if (_PROCESS_HELPER_::SeIsWow64Process(process_fullpath, process_fullpath_Length, &iswow64_2) == FALSE)
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
			//ʹ��Wow64ϵ�к���
			goto Exit;
		}
		else
		{
			//(64->32)
			goto Exit;
		}
		process_handle = _PROCESS_HELPER_::SeOpenProcess(PROCESS_ALL_ACCESS, FALSE, process_identify);
		
		//��Ŀ����̿ռ��������ڴ�
		buffer_length = (_tcslen(buffer_data) + 1) * sizeof(TCHAR);
		//Ŀ����̿ռ��������ڴ�
		virtual_address = VirtualAllocEx(process_handle, NULL, buffer_length, MEM_COMMIT, PAGE_READWRITE);
		if (virtual_address == NULL)
		{
			last_error = GetLastError();
			goto Exit;
		}
		//Ŀ����̿ռ���д������
		if (_PROCESS_HELPER_::SeProcessMemoryWriteSafe(process_handle, virtual_address, buffer_data, buffer_length, &return_length) == FALSE)
		{
			last_error = GetLastError();
			goto Exit;
		}
		//CreateRemoteThread()��Kernel32ģ���е�������Ҳ�ǵ�ǰexeģ���е��뺯��
		 thread_handle = CreateRemoteThread(process_handle,
			NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibrary,     //��ǰģ���е��뺯���ĵ�ַ   
			virtual_address, 0, NULL);
		if (thread_handle == NULL)
		{
			int LastError = GetLastError();
			VirtualFreeEx(process_handle, virtual_address, buffer_length, MEM_RELEASE);
			goto Exit;
		}
		_tprintf(_T("Ŀ������е�LoadLibraryִ�����\r\n"));
		Sleep(1000);                    
		if (_MEMORY_HELPER_::SeOpenMemoryMappingEx(ACCESS_WRITE, FALSE, _T("SHINE"), &mapping_handle, &v10) == FALSE)
		{
			GetLastError();
		}
		else
		{
			__try
			{
				_tprintf(_T("%p\r\n"), *(ULONG_PTR*)virtual_address);

			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				last_error = GetExceptionCode();
			}
		}
		WaitForSingleObject(thread_handle, INFINITE);
		VirtualFreeEx(thread_handle, virtual_address, buffer_length, MEM_RELEASE);  //��̬��·�����ͷ�
		if (v10 != NULL)
		{
			thread_handle = CreateRemoteThread(thread_handle,
				NULL, 0, (LPTHREAD_START_ROUTINE)FreeLibrary,     //��ǰģ���е��뺯��
				(LPVOID)(*(ULONG_PTR*)v10), 0, NULL);

			WaitForSingleObject(thread_handle, INFINITE);
			_MEMORY_HELPER_::SeUnmapMemoryEx(mapping_handle, v10);
			_tprintf(_T("Ŀ������е�FreeLibraryִ�����\r\n"));
		}
	Exit:
		if (process_handle != NULL)
		{
			_PROCESS_HELPER_::SeCloseHandle(process_handle);
			process_handle = INVALID_HANDLE_VALUE;
		}
		_tprintf(_T("Input AnyKey To Exit\r\n"));
		_gettchar();
	}

}








