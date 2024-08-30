#include "ThreadHelper.h"
#include "MemoryHelper.h"
#include "SystemHelper.h"
#include "ErrorHelper.h"


namespace _THREAD_HELPER_
{
	BOOL __EnableDebugPrivilege = TRUE;
	BOOL SeInitializeMember()
	{
		return TRUE;
	}
	BOOL SeEnableSeDebugPrivilege(const TCHAR*  PriviledgeName, BOOL IsEnable)
	{

		BOOL IsOk = FALSE;
		int  LastError = 0;
		//获取当前进程句柄(伪句柄)
		HANDLE  ProcessHandle = GetCurrentProcess();
		HANDLE  TokenHandle = INVALID_HANDLE_VALUE;
		TOKEN_PRIVILEGES TokenPrivileges = { 0 };

		//通过当前进程句柄获得当前进程中令牌句柄
		if (!OpenProcessToken(ProcessHandle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &TokenHandle))
		{

			LastError = GetLastError();
			goto Exit;
		}

		LUID			 v1;
		if (!LookupPrivilegeValue(NULL, PriviledgeName, &v1))		// 通过权限名称查找uID
		{
			LastError = GetLastError();
			goto Exit;
		}


		TokenPrivileges.PrivilegeCount = 1;		// 要提升的权限个数
		TokenPrivileges.Privileges[0].Attributes = IsEnable == TRUE ? SE_PRIVILEGE_ENABLED : 0;
		TokenPrivileges.Privileges[0].Luid = v1;


		if (!AdjustTokenPrivileges(TokenHandle, FALSE, &TokenPrivileges,
			sizeof(TOKEN_PRIVILEGES), NULL, NULL))
		{
			LastError = GetLastError();
			goto Exit;
		}


		IsOk = TRUE;

	Exit:

		if (TokenHandle != INVALID_HANDLE_VALUE)
		{
			CloseHandle(TokenHandle);
			TokenHandle = INVALID_HANDLE_VALUE;
		}

		SetLastError(LastError);
		return IsOk;
	}

	HANDLE SeOpenThread(DWORD DesiredAccess, BOOL InheritHandle, HANDLE ProcessIdentify)
	{
		if (__EnableDebugPrivilege)
		{
			SeEnableSeDebugPrivilege(_T("SeDebugPrivilege"), TRUE);
		}
		HANDLE ThreadHandle = OpenThread(DesiredAccess, InheritHandle, (DWORD)ProcessIdentify);
		DWORD LastError = GetLastError();
		if (__EnableDebugPrivilege)
		{
			SeEnableSeDebugPrivilege(_T("SeDebugPrivilege"), FALSE);
		}
		SetLastError(LastError);
		return ThreadHandle;
	}


	//Kernel32.dll
    /*BOOL SeGetThreadIdentify(HANDLE ProcessIdentify, vector<HANDLE>& ThreadIdentify)
	{

		BOOL IsOk = FALSE;
		HANDLE SnapshotHandle = INVALID_HANDLE_VALUE;
		THREADENTRY32	ThreadEntry32 = { 0 };
		ThreadEntry32.dwSize = sizeof(THREADENTRY32);
		int LastError = 0;

		if (_MEMORY_HELPER_::IsBadReadPtr(&ProcessIdentify, sizeof(HANDLE)))
		{

			LastError = ERROR_INVALID_PARAMETER;
			goto Exit;
		}

		SnapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		if (SnapshotHandle == INVALID_HANDLE_VALUE)
		{
			LastError = GetLastError();
			goto Exit;
		}
		if (!Thread32First(SnapshotHandle, &ThreadEntry32))
		{

			LastError = GetLastError();
			goto Exit;
		}

		do
		{
			if (ThreadEntry32.th32OwnerProcessID == (DWORD)ProcessIdentify)
			{

				ThreadIdentify.emplace_back((HANDLE)ThreadEntry32.th32ThreadID);
				IsOk = TRUE;
			}

		} while (Thread32Next(SnapshotHandle, &ThreadEntry32));

		LastError = ERROR_MOD_NOT_FOUND;
	Exit:

		if (SnapshotHandle != INVALID_HANDLE_VALUE)
		{
			CloseHandle(SnapshotHandle);
		}
		SnapshotHandle = INVALID_HANDLE_VALUE;
		SetLastError(LastError);
		return IsOk;
	}*/
	//Ntdll.dll
	BOOL SeGetThreadIdentify(HANDLE ProcessIdentify, vector<HANDLE>& ThreadIdentify)
	{
	
		BOOL   IsOk = FALSE;
		int    i = 0;
		int    LastError = 0;
		PVOID  v5 = NULL;
		SIZE_T v7 = 0;
	#define STATUS_SUCCESS                  (NTSTATUS)0x00000000		
		NTSTATUS  Status = STATUS_SUCCESS;
		PSYSTEM_PROCESS_INFORMATION SystemProcessInfo = NULL;
		ULONG v3 = 0;
		
		for (;;)
		{
			v7 += 0x10000;
			#define NtCurrentProcess() ( (HANDLE) -1 )
			Status = _MEMORY_HELPER_::__NtAllocateVirtualMemory(NtCurrentProcess(),
				&v5,
				0,
				&v7,
				MEM_COMMIT,
				PAGE_READWRITE);
#ifndef NT_SUCCESS
#define NT_SUCCESS(StatCode)  ((NTSTATUS)(StatCode) >= 0)
#endif
			if (!NT_SUCCESS(Status))
			{
				break;
			}

			Status = _SYSTEM_HELPER_::__NtQuerySystemInformation(_SYSTEM_HELPER_::SystemProcessInformation,
				v5,
				v7,
				NULL);
			#define STATUS_INFO_LENGTH_MISMATCH      ((NTSTATUS)0xC0000004L)
			if (Status == STATUS_INFO_LENGTH_MISMATCH)
			{
				_MEMORY_HELPER_::__NtFreeVirtualMemory(NtCurrentProcess(),
					&v5,
					&v7,
					MEM_RELEASE);
				v5 = NULL;
			}
			else
			{
				break;
			}
		}
		LastError = _ERROR_HELPER_::SeBaseSetLastNTError(Status);
		if (!NT_SUCCESS(Status))
		{
			goto Exit;
		}
		

		SystemProcessInfo = (PSYSTEM_PROCESS_INFORMATION)v5;
		do
		{
			SystemProcessInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)SystemProcessInfo + v3);

			if (SystemProcessInfo->UniqueProcessId==ProcessIdentify)
			{
				
				for (i=0;i<SystemProcessInfo->NumberOfThreads;i++)
				{
					ThreadIdentify.push_back(SystemProcessInfo->TH[i].ClientId.UniqueThread);
				}

				IsOk = TRUE;
				goto Exit;
			}
			v3 = SystemProcessInfo->NextEntryOffset;
		} while (v3 != 0);

		LastError = ERROR_MOD_NOT_FOUND;
	Exit:
		if (SystemProcessInfo != NULL)
		{
			_MEMORY_HELPER_::__NtFreeVirtualMemory(NtCurrentProcess(),
				&v5,
				&v7,
				MEM_RELEASE);
			v5 = NULL;
		}
		SetLastError(LastError);

		return IsOk;

	}
	
}