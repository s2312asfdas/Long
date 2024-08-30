#include"pch.h"
#include "MemoryHelper.h"
#include <Shlwapi.h>
#pragma comment(lib,"Shlwapi.lib")

namespace  _MEMORY_HELPER_
{

	#define PAGE_SIZE 0x1000
	

	BOOL IsBadReadPtr(CONST VOID *lp,UINT_PTR cb)
	{
		char* EndAddress;
		char* StartAddress;
		ULONG PageSize;

		PageSize = PAGE_SIZE;


		if (cb != 0) 
		{
			if (lp == NULL) {
				return TRUE;
				}

			StartAddress = (char*)lp;
			                                    
			EndAddress = StartAddress + cb - 1;  
			if ( EndAddress < StartAddress ) 
			{
				return TRUE;
			}
			else 
			{
				__try 
				{
					*(volatile CHAR *)StartAddress;    //获得当前页面是否能读
					//获得当前虚拟地址的所属页的基地址
					StartAddress = (PCHAR)((ULONG_PTR)StartAddress & (~((LONG)PageSize - 1)));//RoundDown向下对齐

	
					EndAddress = (PCHAR)((ULONG_PTR)EndAddress & (~((LONG)PageSize - 1)));
               
					while (StartAddress != EndAddress) 
					{
						StartAddress = StartAddress + PageSize;
						*(volatile CHAR *)StartAddress;
					}
				}
				__except(EXCEPTION_EXECUTE_HANDLER) 
				{
					return TRUE;
				}
			}
		}
			return FALSE;
	}

	BOOL IsBadWritePtr(LPVOID lp,UINT_PTR cb)  
	{
		char* EndAddress;
		char* StartAddress;
		ULONG PageSize;

		PageSize = PAGE_SIZE;

		if (cb != 0) 
		{
			if (lp == NULL) 
			{
				return TRUE;
			}

			StartAddress = (PCHAR)lp;
			EndAddress = StartAddress + cb - 1;
			if ( EndAddress < StartAddress ) {
            
				return TRUE;
			}
			else 
			{
				__try 
				{
					*(volatile CHAR *)StartAddress = *(volatile CHAR *)StartAddress;
					StartAddress = (PCHAR)((ULONG_PTR)StartAddress & (~((LONG)PageSize - 1)));
					EndAddress = (PCHAR)((ULONG_PTR)EndAddress & (~((LONG)PageSize - 1)));
					while (StartAddress != EndAddress)
					{
						StartAddress = StartAddress + PageSize;
						*(volatile CHAR *)StartAddress = *(volatile CHAR *)StartAddress;
					}
				}
				__except(EXCEPTION_EXECUTE_HANDLER)
				{
					return TRUE;
				}
			}
		}
		return FALSE;
	}
	BOOL IsBadStringPtrA(CONST CHAR* lpsz,UINT_PTR cchMax)
	{

		CONST char* EndAddress;
		CONST char* StartAddress;
		CHAR c;
		if (cchMax != 0) 
		{
			if (lpsz == NULL) 
			{
				return TRUE;
			}

			StartAddress = lpsz;
			EndAddress = StartAddress + cchMax - 1;
			__try
			{
				c = *(volatile CHAR *)StartAddress;
				while (c && StartAddress != EndAddress)
				{
					StartAddress++;
					c = *(volatile CHAR *)StartAddress;

				}
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
			
				return TRUE;
			}
		}
		return FALSE;
	}
	BOOL IsBadStringPtrW(CONST WCHAR* lpsz,UINT_PTR cchMax)
	{

		CONST WCHAR* EndAddress;
		CONST WCHAR* StartAddress;
		WCHAR c;
		if (cchMax != 0) 
		{
			if (lpsz == NULL) {
				return TRUE;
				}

			StartAddress = lpsz;

			EndAddress = (WCHAR*)((WCHAR*)StartAddress + (cchMax*2) - 2);
			__try 
			{
				c = *(volatile WCHAR *)StartAddress;
				while (c && StartAddress != EndAddress)
				{
					StartAddress++;
					c = *(volatile WCHAR *)StartAddress;

				}
			}
			__except(EXCEPTION_EXECUTE_HANDLER)
			{
				return TRUE;
				
			}
			
		}
		return FALSE;
	}
	void * __cdecl memcpy(void* pvDest,const void* pvSrc,size_t cb)       //非重叠
	{
		for (size_t i = 0; i < cb; i++)
		{
			((BYTE *)pvDest)[i] = ((const BYTE *)pvSrc)[i];     
		}		
		return pvDest;
	}
	void* __cdecl  memmove(void* pvDest, const void* pvSrc, size_t cb)   //重叠
	{
		BYTE *  pb1;
		BYTE *  pb2;

		if (pvSrc < pvDest)
		{
			pb1 = (BYTE *)pvDest + cb;
			pb2 = (BYTE *)pvSrc + cb;
			for (; cb; cb--)
			{
				*pb1-- = *pb2--;
			}
		}
		else if (pvSrc > pvDest)
		{
			pb1 = (BYTE *)pvDest;
			pb2 = (BYTE *)pvSrc;
			for (; cb; cb--)
			{
				*pb1++ = *pb2++;
			}
		}
		return pvDest;
	}


	BOOL SeMappingFileExA(char* FileFullPath, DWORD DesiredAccess, LPHANDLE FileHandle,LPDWORD FileLength, LPHANDLE MappingHandle, LPVOID MappedFileVA, DWORD FileOffset)
	{
		DWORD FileAccess = 0;
		DWORD FileMapType = 0;
		DWORD FileMapViewType = 0;
		int   LastError = 0;

		if (TRUE == PathFileExistsA(FileFullPath))
		{
			if (DesiredAccess == ACCESS_READ)
			{
				FileAccess = GENERIC_READ;
				FileMapType = PAGE_READONLY;
				FileMapViewType = FILE_MAP_READ;
			}
			else if (DesiredAccess == ACCESS_WRITE)
			{
				FileAccess = GENERIC_WRITE;
				FileMapType = PAGE_READWRITE;
				FileMapViewType = FILE_MAP_WRITE;
			}
			else if (DesiredAccess == ACCESS_ALL)
			{
				FileAccess = GENERIC_READ + GENERIC_WRITE + GENERIC_EXECUTE;
				FileMapType = PAGE_EXECUTE_READWRITE;
				FileMapViewType = FILE_MAP_WRITE;
			}
			else
			{
				FileAccess = GENERIC_READ + GENERIC_WRITE + GENERIC_EXECUTE;
				FileMapType = PAGE_EXECUTE_READWRITE;
				FileMapViewType = FILE_MAP_ALL_ACCESS;
			}

			HANDLE v1 = CreateFileA(FileFullPath, FileAccess, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
			if (v1 != INVALID_HANDLE_VALUE)
			{
				*FileHandle = v1;
				DWORD v7 = GetFileSize(v1, NULL);
				v7 = v7 + FileOffset;
				*FileLength = v7;
				HANDLE v2 = CreateFileMappingA(v1, NULL, FileMapType, NULL, v7, NULL);
				if (v2 != NULL)
				{
					*MappingHandle = v2;
					LPVOID v5 = MapViewOfFile(v2, FileMapViewType, NULL, NULL, NULL);
				
					/*	
					x00000195889D0000  4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 b8 00 00 00 00 00 00 00 40 00 00 00  MZ?.............?.......@...
					0x00000195889D001C  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ............................
					0x00000195889D0038  00 00 00 00 e8 00 00 00 0e 1f ba 0e 00 b4 09 cd 21 b8 01 4c cd 21 54 68 69 73 20 70  ....?.....?..?.?!?.L?!This p
					*/
				
					if (v5 != NULL)
					{
						RtlMoveMemory(MappedFileVA, &v5, sizeof ULONG_PTR);
						return TRUE;
					}
					else
					{
						LastError = GetLastError();
					}
				}
				else
				{
					LastError = GetLastError();
				}
				RtlZeroMemory(MappedFileVA, sizeof(ULONG_PTR));
				*FileHandle = NULL;
				*FileLength = NULL;
				CloseHandle(FileHandle);
			}
			else
			{
				LastError = GetLastError();
				RtlZeroMemory(MappedFileVA, sizeof ULONG_PTR);
			}
		}
		SetLastError(LastError);
		return FALSE;
	}
	BOOL SeMappingFileExW(wchar_t* FileFullPath,DWORD DesiredAccess, LPHANDLE FileHandle,LPDWORD FileLength, LPHANDLE MappingHandle,LPVOID MappedFileVA, DWORD FileOffset)
	{
		DWORD FileAccess = 0;
		DWORD FileMapType = 0;
		DWORD FileMapViewType = 0;
		int   LastError = 0;


		if (TRUE == PathFileExistsW(FileFullPath))
		{
			if (DesiredAccess == ACCESS_READ)
			{
				FileAccess = GENERIC_READ;
				FileMapType = PAGE_READONLY;
				FileMapViewType = FILE_MAP_READ;
			}
			else if (DesiredAccess == ACCESS_WRITE)
			{
				FileAccess = GENERIC_WRITE;
				FileMapType = PAGE_READWRITE;
				FileMapViewType = FILE_MAP_WRITE;
			}
			else if (DesiredAccess == ACCESS_ALL)
			{
				FileAccess = GENERIC_READ + GENERIC_WRITE + GENERIC_EXECUTE;
				FileMapType = PAGE_EXECUTE_READWRITE;
				FileMapViewType = FILE_MAP_WRITE;
			}
			else
			{
				FileAccess = GENERIC_READ + GENERIC_WRITE + GENERIC_EXECUTE;
				FileMapType = PAGE_EXECUTE_READWRITE;
				FileMapViewType = FILE_MAP_ALL_ACCESS;
			}

			HANDLE v1 = CreateFileW(FileFullPath, FileAccess, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
			if (v1 != INVALID_HANDLE_VALUE)
			{
				*FileHandle = v1;
				DWORD v7 = GetFileSize(v1, NULL);
				v7 = v7 + FileOffset;
				*FileLength = v7;
				HANDLE v2 = CreateFileMappingA(v1, NULL, FileMapType, NULL, v7, NULL);
				if (v2 != NULL)
				{
					*MappingHandle = v2;
					LPVOID v5 = MapViewOfFile(v2, FileMapViewType, NULL, NULL, NULL);
					if (v5 != NULL)
					{
						RtlMoveMemory(MappedFileVA, &v5, sizeof(ULONG_PTR));
						return TRUE;
					}
					else
					{
						LastError = GetLastError();
					}

				}
				else
				{
					LastError = GetLastError();
				}

				RtlZeroMemory(MappedFileVA, sizeof(ULONG_PTR));
				*FileHandle = NULL;
				*FileLength = NULL;
				CloseHandle(FileHandle);
			}
			else
			{
				LastError = GetLastError();
				RtlZeroMemory(MappedFileVA, sizeof ULONG_PTR);

			}
		}
		
		SetLastError(LastError);
		return FALSE;
	}
	void SeUnmappingFileEx(HANDLE FileHandle, DWORD FileLength, HANDLE MappingHandle, ULONG_PTR MappedFileVA)
	{
		if (UnmapViewOfFile((void*)MappedFileVA))
		{
			CloseHandle(MappingHandle);
			SetFilePointer(FileHandle, FileLength, NULL, FILE_BEGIN);
			SetEndOfFile(FileHandle);
			CloseHandle(FileHandle);
		}

	}
	BOOL CloseHandle(HANDLE HandleValue)
	{
		DWORD HandleFlags;
		if (GetHandleInformation(HandleValue, &HandleFlags)
			&& (HandleFlags & HANDLE_FLAG_PROTECT_FROM_CLOSE) != HANDLE_FLAG_PROTECT_FROM_CLOSE)
			return !!::CloseHandle(HandleValue);
		return FALSE;
	}

	BOOL SeIsValidReadPtr(LPVOID BufferData, DWORD BufferLength)
	{

		int LastError = 0;
		BOOL IsOk = TRUE;
		MEMORY_BASIC_INFORMATION MemoryBasicInfo = { 0 };
		if (BufferData == NULL || BufferLength == NULL)
		{
			LastError = ERROR_PARAMETER_INVALID;
			IsOk = FALSE;
			goto Exit;
		}
		while (BufferLength > NULL)
		{
			VirtualQuery(BufferData, &MemoryBasicInfo, sizeof MEMORY_BASIC_INFORMATION);
			if ((MemoryBasicInfo.State != MEM_COMMIT || !(MemoryBasicInfo.Protect & PAGE_READ_FLAGS)))
			{
				LastError = ERROR_PAGE_ATTRIBUTE_INVALID;
				IsOk = FALSE;
			}

			BufferData = (LPVOID)((ULONG_PTR)BufferData + MemoryBasicInfo.RegionSize);

			if (MemoryBasicInfo.RegionSize > BufferLength)
			{
				BufferLength = NULL;
			}
			else
			{
				BufferLength = BufferLength - (DWORD)MemoryBasicInfo.RegionSize;
			}
		}

	Exit:
		SetLastError(LastError);
		return IsOk;
	}
	BOOL SeIsValidWritePtr(LPVOID BufferData, DWORD BufferLength)
	{

		int LastError = 0;
		BOOL IsOk = TRUE;
		MEMORY_BASIC_INFORMATION MemoryBasicInfo = { 0 };
		if (BufferData == NULL || BufferLength == NULL)
		{
			LastError = ERROR_PARAMETER_INVALID;
			IsOk = FALSE;
			goto Exit;
		}
		while (BufferLength > NULL)
		{
			VirtualQuery(BufferData, &MemoryBasicInfo, sizeof MEMORY_BASIC_INFORMATION);
		
			if ((MemoryBasicInfo.State != MEM_COMMIT || !(MemoryBasicInfo.Protect & PAGE_WRITE_FLAGS)))  
			{
				LastError = ERROR_PAGE_ATTRIBUTE_INVALID;
				IsOk = FALSE;
			}


			BufferData = (LPVOID)((ULONG_PTR)BufferData + MemoryBasicInfo.RegionSize);

			if (MemoryBasicInfo.RegionSize > BufferLength)
			{
				BufferLength = NULL;
			}
			else
			{
				BufferLength = BufferLength - (DWORD)MemoryBasicInfo.RegionSize;
			}
		}

	Exit:
		SetLastError(LastError);
		return IsOk;
	}

	BOOL SeMappingMemoryEx(DWORD ReadOrWrite, DWORD MaximumSizeHigh,
		DWORD MaximumSizeLow, LPCTSTR ObjectName, _Out_ LPHANDLE MappingHandle, _Out_ ULONG_PTR* VirtualAddress)
	{
		DWORD DesiredAccess = 0;
		DWORD Protect = 0;
		HANDLE v1 = NULL;
		LPVOID v5 = NULL;
		int LastError = 0;

		if (MappingHandle == NULL || VirtualAddress == NULL)
		{
			LastError = ERROR_INVALID_PARAMETER;
			goto Exit;
		}
		if (ReadOrWrite == ACCESS_READ)
		{
			Protect = PAGE_READONLY;
			DesiredAccess = SECTION_MAP_READ;
		}
		else if (ReadOrWrite == ACCESS_WRITE)
		{
			Protect = PAGE_READWRITE;
			DesiredAccess = SECTION_MAP_READ | SECTION_MAP_WRITE;

		}
		else
		{
			LastError = ERROR_INVALID_PARAMETER;

			goto Exit;
		}

		__try
		{
			//创建一个命名内存对象
			v1 = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, Protect, MaximumSizeHigh, MaximumSizeLow, ObjectName);
			if (v1 != NULL)
			{
				*MappingHandle = v1;

				//通过句柄获得映射的虚拟内存
				v5 = MapViewOfFile(v1, DesiredAccess, 0, 0, 0);

				if (v5 != NULL)
				{
					(*VirtualAddress) = (ULONG_PTR)v5;

					return TRUE;
				}
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			LastError = GetExceptionCode();
			goto Exit;
		}
	Exit:
		SetLastError(LastError);
		return FALSE;
	}
	void SeUnmapMemoryEx(_In_ HANDLE MappingHandle, _In_ ULONG_PTR VirtualAdress)
	{
		__try
		{

			if (UnmapViewOfFile((void*)VirtualAdress))
			{
				CloseHandle(MappingHandle);
				MappingHandle = NULL;
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			SetLastError(GetExceptionCode());
		}
	}

	BOOL SeOpenMemoryMappingEx(DWORD ReadOrWrite, 
		DWORD IsInheritHandle, LPCTSTR ObjectName, _Out_ LPHANDLE MappingHandle, _Out_ ULONG_PTR* VirtualAddress)
	{
		DWORD DesiredAccess = 0;

		HANDLE v1 = NULL;
		LPVOID v5 = NULL;
		int LastError = 0;

		if (MappingHandle == NULL || VirtualAddress == NULL)
		{
			LastError = ERROR_INVALID_PARAMETER;
			goto Exit;
		}
		if (ReadOrWrite == ACCESS_READ)
		{

			DesiredAccess = SECTION_MAP_READ;
		}
		else if (ReadOrWrite == ACCESS_WRITE)
		{

			DesiredAccess = SECTION_MAP_READ | SECTION_MAP_WRITE;

		}
		else
		{
			LastError = ERROR_INVALID_PARAMETER;

			goto Exit;
		}

		__try
		{
			//打开一个命名内存对象
			v1 = OpenFileMapping(DesiredAccess, IsInheritHandle, ObjectName);
			if (v1 != NULL)
			{
				*MappingHandle = v1;

				//通过句柄获得映射的虚拟内存
				v5 = MapViewOfFile(v1, DesiredAccess, 0, 0, 0);

				if (v5 != NULL)
				{
					(*VirtualAddress) = (ULONG_PTR)v5;

					return TRUE;
				}
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			LastError = GetExceptionCode();
			goto Exit;
		}
	Exit:
		SetLastError(LastError);
		return FALSE;
	}
	


}



