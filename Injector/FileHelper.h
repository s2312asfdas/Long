#pragma once
#include <windows.h>
#include <tchar.h>
#include <iostream>
using namespace std;


namespace _FILE_HELPER_
{
	#define PAGE_SIZE 0x1000
	

	typedef struct _UNICODE_STRING {
		USHORT Length;
		USHORT MaximumLength;
		PWSTR  Buffer;
	} UNICODE_STRING, *PUNICODE_STRING;
	typedef struct _PEB_LDR_DATA
	{
		ULONG               Length;
		BOOLEAN             Initialized;
		PVOID               SsHandle;
		LIST_ENTRY          InLoadOrderModuleList;
		LIST_ENTRY          InMemoryOrderModuleList;
		LIST_ENTRY          InInitializationOrderModuleList;
		PVOID               EntryInProgress;
	} PEB_LDR_DATA, *PPEB_LDR_DATA;

	typedef struct _RTL_USER_PROCESS_PARAMETERS {
		BYTE Reserved1[16];
		PVOID Reserved2[10];
		UNICODE_STRING ImagePathName;
		UNICODE_STRING CommandLine;
	} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

	typedef struct _PEB {
		BOOLEAN InheritedAddressSpace;      // These four fields cannot change unless the
		BOOLEAN ReadImageFileExecOptions;   //
		BOOLEAN BeingDebugged;              //
		BOOLEAN SpareBool;                  //
		HANDLE Mutant;                      // INITIAL_PEB structure is also updated.

		PVOID ImageBaseAddress;
		PPEB_LDR_DATA Ldr;
		struct _RTL_USER_PROCESS_PARAMETERS *ProcessParameters;
		PVOID SubSystemData;
		PVOID ProcessHeap;
		PVOID FastPebLock;
		PVOID FastPebLockRoutine;
		PVOID FastPebUnlockRoutine;
		ULONG EnvironmentUpdateCount;
		PVOID KernelCallbackTable;
		HANDLE EventLogSection;
		PVOID EventLog;
		PVOID FreeList;
		ULONG TlsExpansionCounter;
		PVOID TlsBitmap;
		ULONG TlsBitmapBits[2];         // relates to TLS_MINIMUM_AVAILABLE
		PVOID ReadOnlySharedMemoryBase;
		PVOID ReadOnlySharedMemoryHeap;
		PVOID *ReadOnlyStaticServerData;
		PVOID AnsiCodePageData;
		PVOID OemCodePageData;
		PVOID UnicodeCaseTableData;

		// Useful information for LdrpInitialize
		ULONG NumberOfProcessors;
		ULONG NtGlobalFlag;

		// Passed up from MmCreatePeb from Session Manager registry key

		LARGE_INTEGER CriticalSectionTimeout;
		ULONG HeapSegmentReserve;
		ULONG HeapSegmentCommit;
		ULONG HeapDeCommitTotalFreeThreshold;
		ULONG HeapDeCommitFreeBlockThreshold;

		// Where heap manager keeps track of all heaps created for a process
		// Fields initialized by MmCreatePeb.  ProcessHeaps is initialized
		// to point to the first free byte after the PEB and MaximumNumberOfHeaps
		// is computed from the page size used to hold the PEB, less the fixed
		// size of this data structure.

		ULONG NumberOfHeaps;
		ULONG MaximumNumberOfHeaps;
		PVOID *ProcessHeaps;

		//
		//
		PVOID GdiSharedHandleTable;
		PVOID ProcessStarterHelper;
		PVOID GdiDCAttributeList;
		PVOID LoaderLock;

		// Following fields filled in by MmCreatePeb from system values and/or
		// image header.

		ULONG OSMajorVersion;
		ULONG OSMinorVersion;
		ULONG OSBuildNumber;
		ULONG OSPlatformId;
		ULONG ImageSubsystem;
		ULONG ImageSubsystemMajorVersion;
		ULONG ImageSubsystemMinorVersion;
		ULONG ImageProcessAffinityMask;
		#define GDI_HANDLE_BUFFER_SIZE      34
		ULONG GdiHandleBuffer[GDI_HANDLE_BUFFER_SIZE];
	} PEB, *PPEB;


	BOOL SeGetProcAddressEx(IN HANDLE ProcessIdentify,
		OUT PVOID* FunctionAddress, IN const char* ModuleName, IN const char* FunctionName);

#ifdef UNICODE
#define SeOpenFile SeOpenFileW
#else
#define SeOpenFile SeOpenFileA
#endif
	BOOL SeOpenFileA(char* FileFullPath, DWORD DesiredAccess, LPHANDLE FileHandle,
		LPDWORD FileSizeLow, LPDWORD FileSizeHigh);
	BOOL SeOpenFileW(wchar_t* FileFullPath, DWORD DesiredAccess, LPHANDLE FileHandle,
		LPDWORD FileSizeLow, LPDWORD FileSizeHigh);

	BOOL SeReadFile(HANDLE FileHandle, DWORD FilePositionLow,
		LPDWORD FilePositionHigh, void* FileData, DWORD FileLength);

	BOOL SeCloseHandle(HANDLE HandleValue);


	BOOL SePathRemoveFileName(LPTSTR BufferData);
}