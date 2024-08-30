#pragma once
#include <windows.h>
#include <iostream>
#include <tchar.h>

namespace _HIJACK_EIP_HELPER_
{
#ifdef _WIN64
	UINT8	__ShellCode[0x100] = {
		0x48,0x83,0xEC,0x28,	// sub rsp ,28h   //rcx rdx r8 r9  对齐 

		0x48,0x8D,0x0d,			// [+4] lea rcx,    
		0x00,0x00,0x00,0x00,	// [+7] DllFullPathOffset = [+43] - [+4] - 7
		// call 跳偏移，到地址，解*号
		0xff,0x15,				// [+11]
		0x00,0x00,0x00,0x00,	// [+13] LoadLibraryAddressOffset

		0x48,0x83,0xc4,0x28,	// [+17] add rsp,28h

		// jmp 跳偏移，到地址，解*号
		0xff,0x25,				// [+21]
		0x00,0x00,0x00,0x00,	// [+23] Jmp Rip

		// 存放原先的 rip
		0x00,0x00,0x00,0x00,	// [+27]   //
		0x00,0x00,0x00,0x00,	// [+31]

		// 跳板 loadlibrary地址
		0x00,0x00,0x00,0x00,	// [+35] 
		0x00,0x00,0x00,0x00,	// [+39]

		// 存放dll完整路径
		//	0x00,0x00,0x00,0x00,	// [+43]
		//	0x00,0x00,0x00,0x00		// [+47]
		//	......
	};

#else
	UINT8	__ShellCode[0x100] = {
		0x60,					// [+0] pusha   //其入栈顺序是:EAX,ECX,EDX,EBX,ESP,EBP,ESI,EDI
		0x9c,					// [+1] pushf
		0x68,					// [+2] push
		0x00,0x00,0x00,0x00,	// [+3] ShellCode + 
		0xff,0x15,				// [+7] call	
		0x00,0x00,0x00,0x00,	// [+9] LoadLibrary Addr  Addr
		0x9d,					// [+13] popf
		0x61,					// [+14] popa
		0xff,0x25,				// [+15] jmp
		0x00,0x00,0x00,0x00,	// [+17] jmp  eip

		// eip 地址
		0x00,0x00,0x00,0x00,	// [+21]
		//LoadLibrary地址
		0x00,0x00,0x00,0x00,	// [+25] 
		//DllFullPath 
		0x00,0x00,0x00,0x00		// [+29] 


	};
#endif



	BOOL HookEip(IN HANDLE process_identify, IN HANDLE thread_identify, TCHAR* dll_fullpath, ULONG dll_fullpath_Length);
	BOOL HookEip(IN HANDLE process_identify, IN HANDLE thread_identify, TCHAR* dll_fullpath, ULONG dll_fullpath_Length)
	{
		CONTEXT	thread_context = { 0 };
		int     last_error = 0;
		PVOID   virtual_address = NULL;
		BOOL    is_ok = FALSE;
		HANDLE  thread_handle = NULL;
		HANDLE  process_handle = NULL;
		PUINT8	v1 = NULL;
		UINT32 dll_fullpath_offset = 0;
		UINT32	loadlibrary_address_offset = 0;

		process_handle = _PROCESS_HELPER_::SeOpenProcess(PROCESS_ALL_ACCESS, FALSE, process_identify);   //向目标进程内存空间写数据
		if (process_handle == NULL)
		{
			last_error = GetLastError();
			goto Exit;
		}
		if (_MEMORY_HELPER_::IsBadReadPtr(dll_fullpath, dll_fullpath_Length))
		{
			last_error = ERROR_INVALID_PARAMETER;
			goto Exit;
		}
		//目标进程空间申请内存
		virtual_address = VirtualAllocEx(process_handle, NULL,
			sizeof(__ShellCode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (virtual_address == NULL)
		{
			last_error = GetLastError();
			goto Exit;
		}

		//构建汇编指令
#ifdef _WIN64
	    //构建动态库完整路径
		v1 = __ShellCode + 43;
		memcpy(v1, dll_fullpath, dll_fullpath_Length);
		//lea rcx Offset
		dll_fullpath_offset = (UINT32)(((PUINT8)virtual_address + 43)
			- ((PUINT8)virtual_address + 4) - 7);
		*(PUINT32)(__ShellCode + 7) = dll_fullpath_offset;
		// ShellCode + 35处 放置 LoadLibrary 函数地址
		*(PUINT64)(__ShellCode + 35) = (UINT64)LoadLibrary_Pointer;   //当前模块导入表函数
		//ff15 Offset
		loadlibrary_address_offset = (UINT32)(((PUINT8)virtual_address + 35) - ((PUINT8)virtual_address + 11) - 6);
		*(PUINT32)(__ShellCode + 13) = loadlibrary_address_offset;

		//通过主线程ID获得主线程句柄
		thread_handle = _THREAD_HELPER_::SeOpenThread(THREAD_ALL_ACCESS, FALSE, (HANDLE)thread_identify);
		if (thread_handle == NULL)
		{
			last_error = GetLastError();
			goto Exit;
		}
		//首先挂起线程获得该线程的RIP
		SuspendThread(thread_handle);   //挂起
		thread_context.ContextFlags = CONTEXT_ALL;  //注意获得线程上下背景文时 
		if (GetThreadContext(thread_handle, &thread_context) == FALSE)
		{
			last_error = GetLastError();
			goto Exit;
		}
		//保存原先RIP
		*(PUINT64)(__ShellCode + 27) = thread_context.Rip;
		//将Ok的ShellCode直接写入到目标进程空间中
		if (!_PROCESS_HELPER_::SeProcessMemoryWriteSafe(process_handle, virtual_address, __ShellCode, sizeof(__ShellCode), NULL))
		{
			last_error = GetLastError();
			goto Exit;
		}
		//HookIP
		thread_context.Rip = (UINT64)virtual_address;
#else
		v1 = __ShellCode + 29;
		memcpy(v1, DllFullPath, DllFullPathLength);  //将Dll完整路径存入目标进程空间中   
		//Push Address 
		*(PULONG)(__ShellCode + 3) = (ULONG)virtual_address + 29;
		*(PULONG)(__ShellCode + 25) = (ULONG)__LoadLibrary;   //当前exe模块中的导入函数
		*(PULONG_PTR)(__ShellCode + 9) = (ULONG_PTR)virtual_address + 25;
		//通过主线ID获得主线程句柄
		thread_handle = _THREAD_HELPER_::SeOpenThread(THREAD_ALL_ACCESS, FALSE, (HANDLE)ThreadIdentify);     //通过目标主线程ID获得主线程句柄
		if (thread_handle == NULL)
		{
			LastError = GetLastError();
			goto Exit;
		}
		//首先挂起线程
		SuspendThread(thread_handle);   //目标进程中的主线程挂起   EIP
		thread_context.ContextFlags = CONTEXT_ALL;
		if (GetThreadContext(thread_handle, &ThreadContext) == FALSE)
		{
			LastError = GetLastError();
			goto Exit;
		}
		*(PULONG_PTR)(__ShellCode + 21) = thread_context.Eip;
		*(PULONG_PTR)(__ShellCode + 17) = (ULONG_PTR)VirtualAddress + 21;
		if (!_PROCESS_HELPER_::SeProcessMemoryWriteSafe(ProcessHandle, VirtualAddress, __ShellCode, sizeof(__ShellCode), NULL))
		{
			LastError = GetLastError();
			goto Exit;
		}
		//把现在的ShellCode作为新的指令
		thread_context.Eip = (ULONG_PTR)VirtualAddress;
#endif
		//将线程上下背景文设置回线程中
		if (!SetThreadContext(thread_handle, &thread_context))
		{
			last_error = GetLastError();
			goto Exit;
		}
		//恢复线程继续执行
		ResumeThread(thread_handle);
		is_ok = TRUE;
	Exit:
		if (virtual_address != NULL)
		{
			VirtualFreeEx(process_handle, virtual_address, sizeof(__ShellCode), MEM_RELEASE);
		}
		if (thread_handle != INVALID_HANDLE_VALUE)
		{
			_PROCESS_HELPER_::SeCloseHandle(thread_handle);
		}

		if (process_handle != INVALID_HANDLE_VALUE)
		{
			_PROCESS_HELPER_::SeCloseHandle(process_handle);
		}
		return is_ok;
	}
}