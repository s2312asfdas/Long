#pragma once
#include <windows.h>
#include <iostream>
#include <tchar.h>

typedef HMODULE(WINAPI* LPFN_LOADLIBRARYW)(LPCWSTR lpLibFileName);
typedef HMODULE(WINAPI* LPFN_LOADLIBRARYA)(LPCSTR lpLibFileName);
#ifdef UNICODE
LPFN_LOADLIBRARYW LoadLibrary_Pointer = NULL;
#else
LPFN_LOADLIBRARYA LoadLibrary_Pointer = NULL;
#endif

namespace _APC_INJECT_HELPER_
{
	void apc_inject_helper();
	void apc_inject_helper()
	{
		_tsetlocale(0, _T("Chinese-simplified"));
		_ERROR_HELPER_::SeInitializeMember();
		_MEMORY_HELPER_::SeInitializeMember();
		_SYSTEM_HELPER_::SeInitializeMember();
		HANDLE process_identify = 0;
		TCHAR  process_imageName[MAX_PATH] = { 0 };
		HANDLE process_handle = INVALID_HANDLE_VALUE;
		SIZE_T return_length = 0;
		LPVOID virtual_address = NULL;
		TCHAR buffer_data[MAX_PATH] = { 0 };
		BOOL  is_ok = FALSE;
		int last_error = 0;
		vector<HANDLE> thread_identify{};
		HMODULE  kernel32_module_base = NULL;
		ULONG    os_bit = 0;
		ULONG buffer_length = 0;

		_tprintf(_T("Please Input a ProcessName:\r\n"));
		//_tscanf(_T("%s"), &ProcessImageName);
		int i = 0;
		HANDLE thread_handle = INVALID_HANDLE_VALUE;
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
		//�ж�ϵͳλ��
		//��õ�ǰ���̵Ľ���λ��
		is_ok = _PROCESS_HELPER_::SeGetProcessIdentify(&process_identify, sizeof(HANDLE),
			process_imageName, MAX_PATH * sizeof(TCHAR));
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
			//ʹ��Wow64ϵ�к���
			goto Exit;
		}
		else
		{
			//?????(64->32)
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
		//���Ŀ������µ������߳�
		if (_THREAD_HELPER_::SeGetThreadIdentify(process_identify, thread_identify) == FALSE)
		{
			last_error = GetLastError();
			goto Exit;
		}
		kernel32_module_base = GetModuleHandle(_T("KERNEL32.DLL"));
		if (kernel32_module_base == NULL)
		{
			goto Exit;
		}
#ifdef UNICODE
		LoadLibrary_Pointer = (LPFN_LOADLIBRARYW)GetProcAddress(kernel32_module_base, "LoadLibraryW");
#else
		LoadLibrary_Pointer = (LPFN_LOADLIBRARYA)GetProcAddress(kernel32_module_base, "LoadLibraryA");
#endif
		if (LoadLibrary_Pointer == NULL) {

			goto Exit;
		}
		for (i = thread_identify.size() - 1; i >= 0; i--)
		{
			thread_handle = _THREAD_HELPER_::SeOpenThread(THREAD_SET_CONTEXT, FALSE, thread_identify[i]);
			if (thread_handle)
			{
				//��Ŀ������еĸ����̵߳�APC���в���ִ����
				QueueUserAPC((PAPCFUNC)LoadLibrary_Pointer,
					thread_handle,
					(ULONG_PTR)virtual_address);
				CloseHandle(thread_handle);  
			}
		}
	Exit:
		if (process_handle != NULL)
		{
			_PROCESS_HELPER_::SeCloseHandle(process_handle);
			process_handle = INVALID_HANDLE_VALUE;
		}
		thread_identify.~vector();  //��������
		_tprintf(_T("Input AnyKey To Exit\r\n"));
		_gettchar();
	}
}