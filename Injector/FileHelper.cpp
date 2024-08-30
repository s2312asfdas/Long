#include "FileHelper.h"
#include "MemoryHelper.h"
#include "ProcessHelper.h"
#include "ErrorHelper.h"

namespace _FILE_HELPER_
{



	BOOL SeGetProcAddressEx(IN HANDLE ProcessIdentify,
		OUT PVOID* FunctionAddress, IN const char* ModuleName, IN const char* FunctionName)
	{
		//通过进程Id获得目标进程Peb
		PEB		Peb = { 0 };
		BOOL	IsOk = FALSE;
		HANDLE ProcessHandle = NULL;
		int LastError = 0;
		PVOID ImageBaseAddress = 0;
		IMAGE_DOS_HEADER ImageDosHeader = { 0 };
		IMAGE_NT_HEADERS ImageNtHeaders = { 0 };
		IMAGE_IMPORT_DESCRIPTOR	ImageImportDescriptor = { 0 };
		DWORD  ImportDirectoryRVA = 0;
		int i = 0;
		int j = 0;
		char v3[MAX_PATH] = { 0 };  //导入模块的名称
		IMAGE_THUNK_DATA  FirstThunkData = { 0 };
		IMAGE_THUNK_DATA  OriginalThunkData = { 0 };   
		SIZE_T ReturnLength = 0;
		char v5[MAX_PATH];
		
		
		//获得目标进程的Peb
		IsOk = _PROCESS_HELPER_::SeGetProcessPebEx(ProcessIdentify, (_PROCESS_HELPER_::PPEB)&Peb);
		if (IsOk == FALSE)
		{
			LastError = GetLastError();
			goto Exit;
		}
		//从目标进程中的Peb结构中获取目标进程的第1模块的基地址
		
		ImageBaseAddress = (PVOID)Peb.ImageBaseAddress;


		//打开目标进程句柄
		ProcessHandle = _PROCESS_HELPER_::SeOpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 
			FALSE, ProcessIdentify);
		if (ProcessHandle == NULL)
		{
			LastError = GetLastError();
			goto Exit;
		}

		
		
		if (_PROCESS_HELPER_::SeProcessMemoryReadSafe(ProcessHandle, ImageBaseAddress, &ImageDosHeader,
			sizeof(IMAGE_DOS_HEADER), NULL)==FALSE)
		{

			LastError = GetLastError();
			goto Exit;
		}
		
		
		//判断是不是Pe头部
		if (ImageDosHeader.e_magic != IMAGE_DOS_SIGNATURE)
		{
			LastError = ERROR_INVALID_FLAGS;
			goto Exit;
		}
		//读取目标进程数据
		
		if (_PROCESS_HELPER_::SeProcessMemoryReadSafe(ProcessHandle, (PVOID)((PUINT8)ImageBaseAddress + ImageDosHeader.e_lfanew),
			&ImageNtHeaders, sizeof(IMAGE_NT_HEADERS), NULL) == FALSE)
		{
			LastError = GetLastError();
			goto Exit;
		}

		//判断是不是Nt头部
		if (ImageNtHeaders.Signature != IMAGE_NT_SIGNATURE)
		{
			LastError = ERROR_INVALID_FLAGS;
			goto Exit;
		}
	
		ImportDirectoryRVA = 
			ImageNtHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	
		do
		{
			//读取目标进程的导入表
		
			if (_PROCESS_HELPER_::SeProcessMemoryReadSafe(ProcessHandle,
				(PVOID)(((PIMAGE_IMPORT_DESCRIPTOR)((PUINT8)ImageBaseAddress + ImportDirectoryRVA))
					+ i), &ImageImportDescriptor, sizeof(IMAGE_IMPORT_DESCRIPTOR), NULL) == FALSE)
			{
				LastError = GetLastError();
				goto Exit;
			}

			if (ImageImportDescriptor.FirstThunk == 0 && 
				ImageImportDescriptor.OriginalFirstThunk == 0)
			{
				LastError = ERROR_INVALID_FLAGS;
				goto Exit;
			}

			//读取目标进程中导入表中的模块名
			if (_PROCESS_HELPER_::SeProcessMemoryReadSafe(ProcessHandle,
				(PVOID)((PUINT8)ImageBaseAddress + ImageImportDescriptor.Name),
				v3, MAX_PATH, NULL) == FALSE)
			{
				LastError = GetLastError();
				goto Exit;
			}
					
			if (stricmp(v3, ModuleName) == 0) //与传参值进行比较
			{	
				do
				{
					if (_PROCESS_HELPER_::SeProcessMemoryReadSafe(ProcessHandle,
						(PVOID)(((PIMAGE_THUNK_DATA)((PUINT8)ImageBaseAddress + 
							ImageImportDescriptor.OriginalFirstThunk)) + j),
						&OriginalThunkData, sizeof(IMAGE_THUNK_DATA), NULL) == FALSE)
					{
						LastError = GetLastError();
						goto Exit;
					}
					if (IMAGE_SNAP_BY_ORDINAL(OriginalThunkData.u1.Ordinal))   //索引导入
					{
						j++;
						continue;
					}
					if (OriginalThunkData.u1.AddressOfData == NULL)
					{

				
						//Win10 Explorer.exe 进程中有空
						//LastError = GetLastError();
						//goto Exit;
						
						j++;
						continue;
					}
				
					if (_PROCESS_HELPER_::SeProcessMemoryReadSafe(ProcessHandle,
						(PVOID)((PUINT8)ImageBaseAddress + OriginalThunkData.u1.AddressOfData),
						v5, MAX_PATH, NULL) == FALSE)
					{
						LastError = GetLastError();
						goto Exit;
					}
			
					if (stricmp((const char*)((PIMAGE_IMPORT_BY_NAME)v5)->Name, FunctionName) == 0)
					{
						//获取函数地址
						if (_PROCESS_HELPER_::SeProcessMemoryReadSafe(ProcessHandle,
							(PVOID)(((PIMAGE_THUNK_DATA)((PUINT8)ImageBaseAddress + ImageImportDescriptor.FirstThunk)) + j),
							&FirstThunkData, sizeof(IMAGE_THUNK_DATA), NULL) == FALSE)
						{
							LastError = GetLastError();
							goto Exit;
						}

						*FunctionAddress = (PVOID)FirstThunkData.u1.Function;
						IsOk = TRUE;
						goto Exit;
					}
					j++;

				} while (TRUE);
			}
			i++;
		} while (TRUE);
	Exit:
		if (ProcessHandle != NULL)
		{
			CloseHandle(ProcessHandle);
			ProcessHandle = NULL;
		}
		SetLastError(LastError);
		return IsOk;
	}

	//同步
	BOOL SeOpenFileA(char* FileFullPath, DWORD DesiredAccess, LPHANDLE FileHandle,
		LPDWORD FileSizeLow, LPDWORD FileSizeHigh)
	{
		wchar_t v1[MAX_PATH] = {};

		if (FileFullPath != NULL)
		{
			MultiByteToWideChar(CP_ACP, NULL, FileFullPath, lstrlenA(FileFullPath) + 1,
				v1, sizeof(v1) / (sizeof(v1[0])));

			return SeOpenFileW(v1, DesiredAccess, FileHandle, FileSizeLow, FileSizeHigh);
		}
		else
		{
			return FALSE;
		}
	}
    BOOL SeOpenFileW(wchar_t* FileFullPath, DWORD DesiredAccess, LPHANDLE FileHandle,
		LPDWORD FileSizeLow, LPDWORD FileSizeHigh)
	{
		DWORD  LastError = 0;
		BOOL   IsOk = FALSE;
		//内存拷贝	
		__try
		{
			*FileHandle = CreateFileW(FileFullPath,
				DesiredAccess, FILE_SHARE_READ, NULL,
				OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
			if (FileHandle != INVALID_HANDLE_VALUE)
			{
				*FileSizeLow = GetFileSize(*FileHandle, FileSizeHigh);
				IsOk = TRUE;
			}
			else
			{
				IsOk = FALSE;
				
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			LastError = GetExceptionCode();
			_ERROR_HELPER_::SeBaseSetLastNTError(LastError);

		}
	Exit:
		return IsOk;
	}
	BOOL SeReadFile(HANDLE FileHandle, DWORD FilePositionLow, 
		LPDWORD FilePositionHigh, void* FileData, DWORD FileLength)
	{
		DWORD LastError = 0;
		DWORD ReturnLength = 0;
		BOOL  IsOk = FALSE;
		__try
		{
			if (SetFilePointer(FileHandle, FilePositionLow,
				(PLONG)FilePositionHigh, FILE_BEGIN) != INVALID_SET_FILE_POINTER)
			{
				if (ReadFile(FileHandle, FileData, FileLength, &ReturnLength, NULL))
				{
					if (ReturnLength == FileLength)
					{
						IsOk = TRUE;
					}
					else
					{
						
						IsOk = FALSE;
					}
				}
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			LastError = GetExceptionCode();
			_ERROR_HELPER_::SeBaseSetLastNTError(LastError);
		}
		return IsOk;
	}
	BOOL SeCloseHandle(HANDLE HandleValue)
	{
		DWORD HandleFlags;
		if (GetHandleInformation(HandleValue, &HandleFlags)
			&& (HandleFlags & HANDLE_FLAG_PROTECT_FROM_CLOSE) != HANDLE_FLAG_PROTECT_FROM_CLOSE)
			return !!::CloseHandle(HandleValue);
		return FALSE;
	}

	//BufferData = 0x000000833efaf680 L"C:\\Users\\Shine\\Desktop\\用户层注入\\x64\\Debug\\Demo.exe"
	//BufferData = 0x000000833efaf680 L"C:\\Users\\Shine\\Desktop\\用户层注入\\x64\\Debug"
	BOOL SePathRemoveFileName(LPTSTR BufferData) 
	{
		LPTSTR v1 = BufferData;
		BOOL bModified = FALSE;

		if (BufferData)
		{
			/* Skip directory or UNC path */
			if (*BufferData == TEXT('\\'))
				v1 = ++BufferData;
			if (*BufferData == TEXT('\\'))
				v1 = ++BufferData;

			while (*BufferData)
			{
				if (*BufferData == TEXT('\\'))
					v1 = BufferData; /* Skip dir */
				else if (*BufferData == TEXT(':'))
				{
					v1 = ++BufferData; /* Skip drive */
					if (*BufferData == TEXT('\\'))
						v1++;
				}
				if (!(BufferData = CharNext(BufferData)))
					break;
			}

			if (*v1)
			{
				*v1 = TEXT('\0');
				bModified = TRUE;
			}
		}
		return bModified;
	}

}