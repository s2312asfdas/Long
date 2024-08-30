#include "ProcessHelper.h"
#include "MemoryHelper.h"
#include "ObjectHelper.h"
#include "ErrorHelper.h"
#include "MemoryHelper.h"
#include "SystemHelper.h"
namespace  _PROCESS_HELPER_
{
	#define NtCurrentProcess() ( (HANDLE) -1 )

	BOOL __EnableDebugPrivilege = TRUE;
	LPFN_NTQUERYINFORMATIONPROCESS __NtQueryInformationProcess = NULL;
	BOOL SeInitializeMember()
	{
		HMODULE ModuleHandle = GetModuleHandle(_T("Ntdll.dll"));
		if (ModuleHandle == NULL)
		{
			return FALSE;
		}


		//获得ntdll模块下的函数地址
		__NtQueryInformationProcess = (LPFN_NTQUERYINFORMATIONPROCESS)GetProcAddress(
			ModuleHandle, "NtQueryInformationProcess");
		if (__NtQueryInformationProcess == NULL)
		{
			return FALSE;
		}

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

		if (TokenHandle!=INVALID_HANDLE_VALUE)
		{
			CloseHandle(TokenHandle);
			TokenHandle = INVALID_HANDLE_VALUE;
		}

		SetLastError(LastError);	
		return IsOk;
	}
	HANDLE SeOpenProcess(DWORD DesiredAccess, BOOL IsInheritHandle, HANDLE ProcessIdentify)
	{
		if (__EnableDebugPrivilege)
		{
			SeEnableSeDebugPrivilege(_T("SeDebugPrivilege"), TRUE);
		}
		HANDLE ProcessHandle = ::OpenProcess(DesiredAccess, IsInheritHandle, (DWORD)ProcessIdentify);

		DWORD LastError = GetLastError();
		if (__EnableDebugPrivilege)
		{
			SeEnableSeDebugPrivilege(_T("SeDebugPrivilege"), FALSE);
		}
		SetLastError(LastError);
		return ProcessHandle;
	}
	BOOL SeCloseHandle(HANDLE HandleValue)
	{
		DWORD HandleFlags;
		if (GetHandleInformation(HandleValue, &HandleFlags)
			&& (HandleFlags & HANDLE_FLAG_PROTECT_FROM_CLOSE) != HANDLE_FLAG_PROTECT_FROM_CLOSE)
			return !!::CloseHandle(HandleValue);
		return FALSE;
	}
	BOOL SeProcessMemoryWriteSafe(HANDLE ProcessHandle, LPVOID VirtualAddress, LPCVOID BufferData, SIZE_T BufferLength, SIZE_T* ReturnLength)
	{
		SIZE_T  v1 = 0;
		SIZE_T* v2 = 0;
		int    LastError = 0;
		DWORD  OldProtect = 0;
		BOOL   IsOk = FALSE;
		if ((ProcessHandle == 0) || (VirtualAddress == 0) || (BufferData == 0) || (BufferLength == 0))
		{

			LastError  = ERROR_INVALID_PARAMETER;
			goto Exit;
		}
		if (!ReturnLength)
		{
			v2 = &v1;
		}
		else
		{
			v2 = ReturnLength;
		}

		if (!WriteProcessMemory(ProcessHandle, VirtualAddress, BufferData, BufferLength, v2))
		{
			if (VirtualProtectEx(ProcessHandle, VirtualAddress, BufferLength, PAGE_EXECUTE_READWRITE, &OldProtect))
			{
				if (WriteProcessMemory(ProcessHandle, VirtualAddress, BufferData, BufferLength, v2))
				{
					IsOk = TRUE;
				}
				else
				{
					LastError = GetLastError();
				}
				VirtualProtectEx(ProcessHandle, VirtualAddress, BufferLength, OldProtect, &OldProtect);
			}
			else
			{
				LastError = GetLastError();
			}
		}
		else
		{
			IsOk = TRUE;
		}
	Exit:

		SetLastError(LastError);
		return IsOk;
	}
	BOOL SeProcessMemoryReadSafe(HANDLE ProcessHandle, LPVOID VirtualAddress, LPVOID BufferData, SIZE_T BufferLength, SIZE_T* ReturnLength)
	{
		SIZE_T v1 = 0;
		SIZE_T* v2 = 0;
		int    LastError = 0;
		DWORD  OldProtect = 0;
		BOOL   IsOk = FALSE;

		if ((ProcessHandle == 0) || (VirtualAddress == 0) || (BufferData == 0) || (BufferLength == 0))
		{

			LastError = ERROR_INVALID_PARAMETER;
			goto Exit;
		}
		
		if (!ReturnLength)
		{
			v2 = &v1;
		}
		else
		{
			v2 = ReturnLength;
		}

		if (!ReadProcessMemory(ProcessHandle, VirtualAddress, BufferData, BufferLength, v2))
		{
			if (VirtualProtectEx(ProcessHandle, VirtualAddress, BufferLength, PAGE_EXECUTE_READ,
				&OldProtect))
			{
				if (ReadProcessMemory(ProcessHandle, VirtualAddress, BufferData, BufferLength, v2))
				{
					IsOk = TRUE;
				}
				else
				{
					LastError = GetLastError();
				}
				VirtualProtectEx(ProcessHandle, VirtualAddress, BufferLength, OldProtect, &OldProtect);
			}
			else
			{
				LastError = GetLastError();
			}
		}
		else
		{
			IsOk = TRUE;
		}

	Exit:

		SetLastError(LastError);
		return IsOk;
	}
    //Kenrl32.dll
	/*
	BOOL SeGetProcessIdentify(HANDLE* ProcessIdentify,ULONG_PTR ProcessIdentifyLength,const TCHAR* ProcessImageName,ULONG_PTR ProcessImageNameLength)
	{
		BOOL IsOk = FALSE;
		HANDLE SnapshotHandle = INVALID_HANDLE_VALUE;
		PROCESSENTRY32 ProcessEntry32;
		ProcessEntry32.dwSize = sizeof(PROCESSENTRY32);
		int LastError = 0;
		if (_MEMORY_HELPER_::IsBadWritePtr(ProcessIdentify, ProcessIdentifyLength)||
		_MEMORY_HELPER_::IsBadReadPtr(ProcessImageName, ProcessImageNameLength))
		{

			LastError = ERROR_INVALID_PARAMETER;
			goto Exit;
		}	
		SnapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (SnapshotHandle == INVALID_HANDLE_VALUE)
		{
			LastError = GetLastError();
			return FALSE;
		}
				
		if (!Process32First(SnapshotHandle, &ProcessEntry32))
		{
			
			LastError = GetLastError();
			goto Exit;
		}
		
		do
		{

			if (_tcsicmp(ProcessEntry32.szExeFile, ProcessImageName) == 0)
			{

				*ProcessIdentify = (HANDLE)ProcessEntry32.th32ProcessID;
				IsOk = TRUE;
				goto Exit;
			}
		
		} while (Process32Next(SnapshotHandle, &ProcessEntry32));



		LastError = ERROR_MOD_NOT_FOUND;
	Exit:

		if (SnapshotHandle!=INVALID_HANDLE_VALUE)
		{
			CloseHandle(SnapshotHandle);
		}
		SnapshotHandle = INVALID_HANDLE_VALUE;
		SetLastError(LastError);
		return IsOk;

	}*/
	BOOL SeGetProcessIdentifyA(HANDLE* ProcessIdentify, ULONG_PTR ProcessIdentifyLength,
		const CHAR* ProcessImageName, 
		ULONG_PTR ProcessImageNameLength)
	{
		BOOL IsOk = TRUE;
		int LastError = 0;
		wchar_t* v5 = NULL;
		int v7 = 0;
		if (_MEMORY_HELPER_::IsBadWritePtr(ProcessIdentify, ProcessIdentifyLength) || _MEMORY_HELPER_::IsBadReadPtr(ProcessImageName, ProcessImageNameLength))
		{

			LastError = ERROR_INVALID_PARAMETER;
			goto Exit;
		}
    
		
		v7 = MultiByteToWideChar(CP_ACP, 0, ProcessImageName, -1, NULL, 0);
		v5 = SysAllocStringLen(NULL, v7 - 1);
		MultiByteToWideChar(CP_ACP, 0, ProcessImageName, -1, v5, v7);
		
		if (SeGetProcessIdentifyW(ProcessIdentify, ProcessIdentifyLength, v5, v7)==FALSE)
		{
			
			IsOk = FALSE;
		}
		LastError = GetLastError();
		
	Exit:
		if (v5!=NULL)
		{
			SysFreeString(v5);
			v5 = NULL;
		}
		
		SetLastError(LastError);
		return IsOk;
	}
	BOOL SeGetProcessIdentifyW(HANDLE* ProcessIdentify, ULONG_PTR ProcessIdentifyLength, 
		const WCHAR* ProcessImageName, 
		ULONG_PTR ProcessImageNameLength)  //Explorer.exe
	{
		ULONG v3 = 0;
		PVOID  v5 = NULL;
		SIZE_T v7 = 0;
		BOOL IsOk = FALSE;
		HANDLE SnapshotHandle = INVALID_HANDLE_VALUE;
		PROCESSENTRY32 ProcessEntry32;
		ProcessEntry32.dwSize = sizeof(PROCESSENTRY32);
		int LastError = 0;
		NTSTATUS  Status = STATUS_SUCCESS;
		if (_MEMORY_HELPER_::IsBadWritePtr(ProcessIdentify, ProcessIdentifyLength) ||
			_MEMORY_HELPER_::IsBadReadPtr(ProcessImageName, ProcessImageNameLength))
		{
			LastError = ERROR_INVALID_PARAMETER;
			goto Exit;
		}
		


		UNICODE_STRING v1;

		_STRING_HELPER_::RtlInitUnicodeString((_STRING_HELPER_::PUNICODE_STRING)&v1, ProcessImageName);


		for (;;)
		{
			v7 += 0x10000;

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
				LastError = _ERROR_HELPER_::SeBaseSetLastNTError(Status);
				goto Exit;
			}
#define STATUS_INFO_LENGTH_MISMATCH      ((NTSTATUS)0xC0000004L)
			Status =  _SYSTEM_HELPER_::__NtQuerySystemInformation(_SYSTEM_HELPER_::SystemProcessInformation,
				v5,
				v7,
				NULL);
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


		
		PSYSTEM_PROCESS_INFORMATION SystemProcessInfo;
		SystemProcessInfo = (PSYSTEM_PROCESS_INFORMATION)v5;
		do
		{
			SystemProcessInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)SystemProcessInfo + v3);
		
			if (_STRING_HELPER_::RtlCompareUnicodeString(((_STRING_HELPER_::PUNICODE_STRING)&v1), 
				((_STRING_HELPER_::PUNICODE_STRING)&SystemProcessInfo->ImageName),TRUE)==0)
			{

				
				*ProcessIdentify = SystemProcessInfo->UniqueProcessId;
				IsOk = TRUE;
				goto Exit;
			}
			



			v3 = SystemProcessInfo->NextEntryOffset;
		} while (v3 != 0);

		LastError = ERROR_MOD_NOT_FOUND;
	Exit:
		if (v5!=NULL)
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
	BOOL SeGetProcessFullPathA(CHAR** ProcessFullPath, ULONG_PTR* ProcessFullPathLength,
		HANDLE ProcessIdentify, BOOL IsAllocate)
	{
	
		HANDLE ProcessHandle = INVALID_HANDLE_VALUE;
		CHAR*   v5 = NULL;
		ULONG   v7 = BUFFER_SIZE;
		int LastError = 0;
		if (ProcessIdentify == NULL)
		{
			SetLastError(ERROR_INVALID_PARAMETER);
			return FALSE;
		}
		ProcessHandle = SeOpenProcess(PROCESS_QUERY_INFORMATION, FALSE, ProcessIdentify);
		if (ProcessHandle == NULL)
		{
			ProcessHandle = SeOpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,ProcessIdentify);
		}
		if (ProcessHandle == NULL)
		{
			return FALSE;
		}

		do 
		{
			v5 = (char*)malloc(v7*sizeof(char)); 
			if (v5==NULL)
			{
				LastError = GetLastError();
				goto Exit;
			}
			if (GetProcessImageFileNameA(ProcessHandle, v5, v7) == FALSE) //v5 = 0x000001f622954930 "\\Device\\HarddiskVolume4\\Windows\\explorer.exe"
			{
				int LastError = GetLastError();
				free(v5);
				v5 = NULL;
				
				if (LastError!=ERROR_INSUFFICIENT_BUFFER)
				{

					LastError = GetLastError();
					goto Exit;
				}

				v7 += BUFFER_SIZE;
			}
			else
			{
				break;
			}
		} while (1);
	
		if (IsAllocate == TRUE)
		{
			
			*ProcessFullPath = v5;
			*ProcessFullPathLength = v7;


		}
		else
		{
			int v1 = *ProcessFullPathLength;
			if (*ProcessFullPathLength>v7)  
			{
				v1 = v7;
			}
			memcpy(*ProcessFullPath, v5, v1*sizeof(char));
			if (v5 != NULL)
			{
				free(v5);
				v5 = NULL;
			}

		}	
Exit:
		if (ProcessHandle != INVALID_HANDLE_VALUE)
		{
			CloseHandle(ProcessHandle);
			ProcessHandle = INVALID_HANDLE_VALUE;
		}
		SetLastError(LastError);
		return TRUE;

	}
	BOOL SeGetProcessFullPathW(WCHAR** ProcessFullPath, 
		ULONG_PTR* ProcessFullPathLength,HANDLE ProcessIdentify, BOOL IsAllocate)
	{
	
		HANDLE ProcessHandle = INVALID_HANDLE_VALUE;
		WCHAR*  v5 = NULL;
		ULONG   v7 = BUFFER_SIZE;
		int LastError = 0;
		if (ProcessIdentify == NULL)
		{
			SetLastError(ERROR_INVALID_PARAMETER);
			return FALSE;
		}
		ProcessHandle = SeOpenProcess(PROCESS_QUERY_INFORMATION, FALSE, ProcessIdentify);
		if (ProcessHandle == NULL)
		{
			ProcessHandle = SeOpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ProcessIdentify);
		}
		if (ProcessHandle == NULL)
		{
			LastError = GetLastError();
			goto Exit;
		}

		do
		{
			v5 = (PWCHAR)malloc(v7*sizeof(WCHAR));
			if (v5 == NULL)
			{
				LastError = GetLastError();
				goto Exit;
			}
			if (GetProcessImageFileNameW(ProcessHandle, v5, v7) == FALSE)
			{
				int LastError = GetLastError();
				free(v5);
				v5 = NULL;

				if (LastError != ERROR_INSUFFICIENT_BUFFER)
				{

					SetLastError(LastError);
					return FALSE;
				}

				v7 += BUFFER_SIZE;
			}
			else
			{
				break;
			}
		} while (1);

		if (IsAllocate == TRUE)
		{

			*ProcessFullPath = v5;
			*ProcessFullPathLength = v7;   //内存有效长度 不是字节长


		}
		else
		{

			int v1 = *ProcessFullPathLength;
			if (*ProcessFullPathLength > v7)
			{
				v1 = v7;
			}
			memcpy(*ProcessFullPath, v5, v1*sizeof(WCHAR));
			if (v5 != NULL)
			{
				free(v5);
				v5 = NULL;
			}

		}
Exit:
		if (ProcessHandle!=INVALID_HANDLE_VALUE)
		{
			CloseHandle(ProcessHandle);
			ProcessHandle = INVALID_HANDLE_VALUE;
		}
		SetLastError(LastError);
		return TRUE;
	}
	BOOL SeIsWow64Process(TCHAR* ProcessFullPath, ULONG_PTR ProcessFullPathLength, PBOOL Wow64Process)
	{
		PIMAGE_DOS_HEADER ImageDosHeader = NULL;
		PIMAGE_NT_HEADERS ImageNtHeaders = NULL;
		BOOL IsOk = TRUE;
		HANDLE FileHandle = INVALID_HANDLE_VALUE;
		DWORD  FileLength = 0;
		HANDLE MappingHandle = INVALID_HANDLE_VALUE;
		ULONG_PTR MappedFileVA = 0;
		int LastError = 0;


		TCHAR* v1 = NULL;
		ULONG_PTR v2 = 0;
		BOOL  IsAllocate = TRUE;

		


		//最后一个参数为TRUE需要调用函数LocalFree()释放内存 
		if (SeDosPathToNtPath(&v1, &v2, ProcessFullPath, 
			ProcessFullPathLength * sizeof(TCHAR), IsAllocate)==FALSE)
		{
			LastError = GetLastError();
			IsOk = FALSE;
			goto Exit;
		}

		
		if (_MEMORY_HELPER_::SeMappingFileEx(v1, ACCESS_READ, 
			&FileHandle, &FileLength, &MappingHandle, &MappedFileVA, 0)==FALSE)
		{
			

		
			LastError = GetLastError();
			IsOk = FALSE;
			goto Exit;
		}
		else
		{
			
			ImageDosHeader = (PIMAGE_DOS_HEADER)MappedFileVA;

			ImageNtHeaders = (PIMAGE_NT_HEADERS)((UINT8*)MappedFileVA + ImageDosHeader->e_lfanew);


			switch (ImageNtHeaders->FileHeader.Machine)
			{
				case IMAGE_FILE_MACHINE_I386:
				{
					*Wow64Process = TRUE;
					break;
				}
				case IMAGE_FILE_MACHINE_IA64:
				case IMAGE_FILE_MACHINE_AMD64:
				{
					*Wow64Process = FALSE;
					break;
				}
				default:
				{
					LastError = ERROR_INVALID_EA_HANDLE;
					IsOk = FALSE;
					break;
				}


			}
			_MEMORY_HELPER_::SeUnmappingFileEx(FileHandle, FileLength, MappingHandle, MappedFileVA);
		Exit:


			if (IsAllocate == TRUE)
			{
				VirtualFree(v1,0,MEM_RELEASE);
				v1 = NULL;
			}
			SetLastError(LastError);
			return IsOk;

		}
		


		
	}
	BOOL SeDosPathToNtPathA(CHAR** DestinationData,ULONG_PTR* DestinationDataLength,CHAR* SourceData,ULONG_PTR SourceDataLength,BOOL IsAllocate)
	{
#define PAGE_SIZE 0x1000
		CHAR*  v5 = NULL;
		size_t v7 = 0;
		if (_MEMORY_HELPER_::IsBadReadPtr(SourceData, SourceDataLength) == TRUE)
		{
			SetLastError(ERROR_INVALID_PARAMETER);
			return FALSE;
		}
		v5 = (CHAR*)VirtualAlloc(NULL, PAGE_SIZE, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
		if (v5 == NULL)
		{
			return FALSE;
		}
		__try
		{	
			CHAR VolumeDeviceName[3] = "A:";   
			CHAR COMDeviceName[5] = "COM0";
			while (VolumeDeviceName[0] <= 0x5A) 
			{
				RtlZeroMemory(v5, PAGE_SIZE);
				//v5 = 0x0000012c9db70000 "\\Device\\HarddiskVolume4"
				if (QueryDosDeviceA(VolumeDeviceName, v5, MAX_PATH * 2) > NULL)
				{
					v7 = strlen(v5);
					strcat(v5, SourceData + v7);
					//v5 = 0x0000012c9db70000 "\\Device\\HarddiskVolume4\\Windows\\System32\\Taskmgr.exe"
					//SourceData = 0x000000195916f360 "\\Device\\HarddiskVolume4\\Windows\\System32\\Taskmgr.exe"
					if (stricmp(v5, SourceData) == NULL)
					{
						RtlZeroMemory(v5, 0x1000);
						strcat(v5, VolumeDeviceName);
						strcat(v5, SourceData + v7);
						//v5 = 0x0000012c9db70000 "C:\\Windows\\System32\\Taskmgr.exe"
						v7 = strlen(v5) + 1;
						if (IsAllocate)
						{
							CHAR* v1 = (CHAR*)LocalAlloc(LPTR, v7);
							if (v1 == NULL)
							{
								return FALSE;
							}

							*DestinationData = v1;
							*DestinationDataLength = v7;
							strncpy(*DestinationData, v5, v7);
							return TRUE;
						}
						else
						{
							if (v7 >= *DestinationDataLength)    
							{
								v7 = *DestinationDataLength;
							}
							strncpy(*DestinationData, v5, v7);

						
							return TRUE;
						}
					}
				}
				VolumeDeviceName[0]++;
			}
			while (COMDeviceName[3] <= 0x39)
			{
				RtlZeroMemory(v5, 0x1000);
				if (QueryDosDeviceA(COMDeviceName, v5, MAX_PATH * 2) > NULL)
				{
					v7 = strlen(v5);
					strcat(v5, SourceData + v7);

					if (stricmp(v5, SourceData) == NULL)
					{
						RtlZeroMemory(v5, 0x1000);
						strcat(v5, COMDeviceName);
						strcat(v5, SourceData + v7);
						v7 = strlen(v5) + 1;
						if (IsAllocate)
						{
							CHAR* v1 = (CHAR*)VirtualAlloc(NULL, v7, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
							if (v1 == NULL)
							{
								return FALSE;
							}

							*DestinationData = v1;
							*DestinationDataLength = v7;
							return TRUE;
						}
						else
						{
							if (v7 >= *DestinationDataLength)
							{
								return FALSE;
							}
							strncpy(*DestinationData, v5, v7);
							return TRUE;
						}
					}
				}
				COMDeviceName[3]++;
			}
		}
		__finally
		{
			if (v5 != NULL)
			{
				VirtualFree(v5, NULL, MEM_RELEASE);
			}
		}
		SetLastError(ERROR_PATH_NOT_FOUND);
		return FALSE;
	}
	BOOL SeDosPathToNtPathW(WCHAR** DestinationData,ULONG_PTR* DestinationDataLength,WCHAR* SourceData,ULONG_PTR SourceDataLength,BOOL IsAllocate)
	{
#define PAGE_SIZE 0x1000
		WCHAR* v5 = NULL;
		size_t v7 = 0;

		if (_MEMORY_HELPER_::IsBadReadPtr(SourceData, SourceDataLength) == TRUE)
		{
			SetLastError(ERROR_INVALID_PARAMETER);
			return FALSE;
		}

		v5 = (WCHAR*)VirtualAlloc(NULL, PAGE_SIZE, MEM_COMMIT, PAGE_READWRITE);
		if (v5 == NULL)
		{
			return FALSE;
		}

		__try
		{
			WCHAR VolumeDeviceName[3] = L"A:";
			WCHAR COMDeviceName[5] = L"COM0";

			while (VolumeDeviceName[0] <= 0x5A)  //Z
			{
				RtlZeroMemory(v5, PAGE_SIZE);

				if (QueryDosDeviceW(VolumeDeviceName, v5, MAX_PATH * 2) > NULL)
				{
					v7 = wcslen(v5);
					wcscat(v5, SourceData + v7);
					if (wcsicmp(v5, SourceData) == NULL)
					{
						RtlZeroMemory(v5, 0x1000);
						wcscat(v5, VolumeDeviceName);
						wcscat(v5, SourceData + v7);
						v7 = wcslen(v5) + 1;
						if (IsAllocate)
						{
							WCHAR* v1 = (WCHAR*)VirtualAlloc(NULL, v7, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
							if (v1 == NULL)
							{
								return FALSE;
							}

							*DestinationData = v1;
							*DestinationDataLength = v7;
							wcsncpy(*DestinationData, v5, v7);
							return TRUE;
						}
						else
						{
							if (v7 >= *DestinationDataLength)
							{
								v7 = *DestinationDataLength;
							}
							wcsncpy(*DestinationData, v5, v7);
							return TRUE;
						}
					}
				}
				VolumeDeviceName[0]++;
			}
			while (COMDeviceName[3] <= 0x39)
			{
				RtlZeroMemory(v5, 0x1000);
				if (QueryDosDeviceW(COMDeviceName, v5, MAX_PATH * 2) > NULL)
				{
					v7 = wcslen(v5);
					wcscat(v5, SourceData + v7);

					if (wcsicmp(v5, SourceData) == NULL)
					{
						RtlZeroMemory(v5, 0x1000);
						wcscat(v5, COMDeviceName);
						wcscat(v5, SourceData + v7);
						v7 = wcslen(v5) + 1;
						if (IsAllocate)
						{
							WCHAR* v1 = (WCHAR*)LocalAlloc(LPTR, v7);
							if (v1 == NULL)
							{
								return FALSE;
							}

							*DestinationData = v1;
							*DestinationDataLength = v7;
							return TRUE;
						}
						else
						{
							if (v7 >= *DestinationDataLength)
							{
								return FALSE;
							}
							wcsncpy(*DestinationData, v5, v7);
							return TRUE;
						}
					}
				}
				COMDeviceName[3]++;
			}
		}
		__finally
		{
			if (v5 != NULL)
			{
				VirtualFree(v5, NULL, MEM_RELEASE);
			}
		}

		SetLastError(ERROR_PATH_NOT_FOUND);
		return FALSE;
	}
	BOOL SeGetProcessPebEx(IN HANDLE ProcessIdentify, OUT PPEB Peb)
	{
		int LastError = 0;
		HMODULE NtdllModuleBase = NULL;
		NTSTATUS Status;
		PROCESS_BASIC_INFORMATION ProcessBasicInfo;
		SIZE_T ReturnLength = 0;
		HANDLE ProcessHandle = INVALID_HANDLE_VALUE;
		BOOL   IsOk = FALSE;
		
		if (__NtQueryInformationProcess==NULL)
		{
			NtdllModuleBase = GetModuleHandle(_T("Ntdll.dll"));
			if (NtdllModuleBase == NULL)
			{
				LastError = GetLastError();
				goto Exit;
			}
			__NtQueryInformationProcess = 
				(LPFN_NTQUERYINFORMATIONPROCESS)GetProcAddress(NtdllModuleBase,
				"NtQueryInformationProcess");
			if (__NtQueryInformationProcess == NULL)
			{
				LastError = GetLastError();
				goto Exit;
			}
		}
		
		ProcessHandle = SeOpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, ProcessIdentify);
		if (ProcessHandle == NULL)
		{
			LastError = GetLastError();
			goto Exit;
		}


		//通过目标进程句柄枚举目标进程中的Basic信息
	
		Status = __NtQueryInformationProcess(ProcessHandle,
			ProcessBasicInformation, &ProcessBasicInfo, sizeof(PROCESS_BASIC_INFORMATION),
			(ULONG*)&ReturnLength);

#ifndef NT_SUCCESS
#define NT_SUCCESS(StatCode)  ((NTSTATUS)(StatCode) >= 0)
#endif
		if (!NT_SUCCESS(Status))
		{

			LastError = _ERROR_HELPER_::SeBaseSetLastNTError(Status);
			goto Exit;
				
		}

		
		IsOk = SeProcessMemoryReadSafe(ProcessHandle, ProcessBasicInfo.PebBaseAddress,
			Peb, sizeof(PEB), &ReturnLength);
		if (IsOk == FALSE)
		{
		
			LastError = GetLastError();
			goto Exit;
		}

	Exit:
		
		if (ProcessHandle!=INVALID_HANDLE_VALUE)
		{
			SeCloseHandle(ProcessHandle);
			ProcessHandle = INVALID_HANDLE_VALUE;
		}

		SetLastError(LastError);
		return IsOk;
	}


}

