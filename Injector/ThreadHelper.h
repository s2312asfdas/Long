#pragma once
#include <windows.h>
#include <tchar.h>
#include <iostream>
#include <TlHelp32.h>
#include <vector>
using namespace std;



namespace _THREAD_HELPER_
{




	typedef struct _UNICODE_STRING {
		USHORT Length;
		USHORT MaximumLength;
		PWSTR  Buffer;
	} UNICODE_STRING, *PUNICODE_STRING;
	typedef LONG KPRIORITY;
	typedef struct _CLIENT_ID
	{
		HANDLE UniqueProcess;
		HANDLE UniqueThread;
	} CLIENT_ID, *PCLIENT_ID;
	typedef struct _SYSTEM_THREAD_INFORMATION
	{
		LARGE_INTEGER KernelTime;
		LARGE_INTEGER UserTime;
		LARGE_INTEGER CreateTime;
		ULONG WaitTime;
		PVOID StartAddress;
		CLIENT_ID ClientId;
		KPRIORITY Priority;
		LONG BasePriority;
		ULONG ContextSwitches;
		ULONG ThreadState;
		ULONG WaitReason;
		ULONG PadPadAlignment;
	} SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;
#ifndef _WIN64
	C_ASSERT(sizeof(SYSTEM_THREAD_INFORMATION) == 0x40); // Must be 8-byte aligned
#endif
	typedef struct _SYSTEM_PROCESS_INFORMATION
	{
		ULONG NextEntryOffset;
		ULONG NumberOfThreads;
		LARGE_INTEGER WorkingSetPrivateSize; //VISTA
		ULONG HardFaultCount; //WIN7
		ULONG NumberOfThreadsHighWatermark; //WIN7
		ULONGLONG CycleTime; //WIN7
		LARGE_INTEGER CreateTime;
		LARGE_INTEGER UserTime;
		LARGE_INTEGER KernelTime;
		UNICODE_STRING ImageName;
		KPRIORITY BasePriority;
		HANDLE UniqueProcessId;
		HANDLE InheritedFromUniqueProcessId;
		ULONG HandleCount;
		ULONG SessionId;
		ULONG_PTR PageDirectoryBase;

		//
		// This part corresponds to VM_COUNTERS_EX.
		// NOTE: *NOT* THE SAME AS VM_COUNTERS!
		//
		SIZE_T PeakVirtualSize;
		SIZE_T VirtualSize;
		ULONG PageFaultCount;
		SIZE_T PeakWorkingSetSize;
		SIZE_T WorkingSetSize;
		SIZE_T QuotaPeakPagedPoolUsage;
		SIZE_T QuotaPagedPoolUsage;
		SIZE_T QuotaPeakNonPagedPoolUsage;
		SIZE_T QuotaNonPagedPoolUsage;
		SIZE_T PagefileUsage;
		SIZE_T PeakPagefileUsage;
		SIZE_T PrivatePageCount;

		//
		// This part corresponds to IO_COUNTERS
		//
		LARGE_INTEGER ReadOperationCount;
		LARGE_INTEGER WriteOperationCount;
		LARGE_INTEGER OtherOperationCount;
		LARGE_INTEGER ReadTransferCount;
		LARGE_INTEGER WriteTransferCount;
		LARGE_INTEGER OtherTransferCount;
		SYSTEM_THREAD_INFORMATION TH[1];
	} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;
	





	BOOL SeInitializeMember();
	BOOL SeEnableSeDebugPrivilege(const TCHAR*  PriviledgeName, BOOL IsEnable);
	HANDLE SeOpenThread(DWORD DesiredAccess, BOOL IsInheritHandle, HANDLE ProcessIdentify);
	BOOL SeGetThreadIdentify(HANDLE ProcessIdentify, vector<HANDLE>& ThreadIdentify);

};

