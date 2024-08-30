#pragma once
#include <windows.h>
#include <tchar.h>
#include <iostream>
#include <vector>
using namespace std;

#define  ERROR_PARAMETER_INVALID       -1
#define  ERROR_PAGE_ATTRIBUTE_INVALID  -2

namespace  _MEMORY_HELPER_
{
	


	BOOL SeInitializeMember();
	BOOL IsBadReadPtr(CONST VOID *lp, UINT_PTR cb);
	BOOL IsBadWritePtr(LPVOID lp, UINT_PTR cb);
	BOOL IsBadStringPtrA(LPCSTR lpsz, UINT_PTR cchMax);
	BOOL IsBadStringPtrW(LPCWSTR lpsz, UINT_PTR cchMax);

	void * __cdecl memcpy(void* pvDest, const void* pvSrc, size_t cb);
	void * __cdecl memmove(void* pvDest, const void* pvSrc, size_t cb);



#define ACCESS_READ 0
#define ACCESS_WRITE 1
#define ACCESS_ALL 2
	//ÄÚ´æÓ³Éä
	BOOL SeMappingFileExA(char* FileFullPath, DWORD DesiredAccess, LPHANDLE FileHandle,
		LPDWORD FileLength, LPHANDLE MappingHandle, LPVOID MappedFileVA, DWORD FileOffset);
	BOOL SeMappingFileExW(wchar_t* FileFullPath,DWORD DesiredAccess, LPHANDLE FileHandle,
		LPDWORD FileLength, LPHANDLE MappingHandle,LPVOID MappedFileVA, DWORD FileOffset);
	void SeUnmappingFileEx(HANDLE FileHandle, DWORD FileLength, HANDLE MappingHandle, ULONG_PTR MappedFileVA);

	BOOL SeCloseHandle(HANDLE HandleValue);

#ifdef UNICODE
#define SeMappingFileEx  SeMappingFileExW
#else
#define SeMappingFileEx  SeMappingFileExA
#endif 

	BOOL SeMappingMemoryEx(DWORD ReadOrWrite, DWORD MaximumSizeHigh,
		DWORD MaximumSizeLow, LPCTSTR ObjectName, _Out_ LPHANDLE MappingHandle, _Out_ ULONG_PTR* VirtualAddress);
	void SeUnmapMemoryEx(_In_ HANDLE MappingHandle, _In_ ULONG_PTR VirtualAdress);

	BOOL SeOpenMemoryMappingEx(DWORD ReadOrWrite,
		DWORD IsInheritHandle, LPCTSTR ObjectName, _Out_ LPHANDLE MappingHandle, _Out_ ULONG_PTR* VirtualAddress);



#define PAGE_EXECUTE_FLAGS \
    (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)
#define PAGE_READ_FLAGS \
    (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)
#define PAGE_WRITE_FLAGS \
    (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)
	BOOL SeIsValidReadPtr(LPVOID BufferData, DWORD BufferLength);
	BOOL SeIsValidWritePtr(LPVOID BufferData, DWORD BufferLength);




}