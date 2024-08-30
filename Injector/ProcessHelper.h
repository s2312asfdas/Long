#pragma once
#include <windows.h>
#include <iostream>
#include <tchar.h>
#include <TlHelp32.h>
#include <Psapi.h>
#pragma comment(lib,"Psapi.lib")

using namespace std;


namespace  _PROCESS_HELPER_
{
	#define BUFFER_SIZE 1024
	#define STATUS_SUCCESS                   ((NTSTATUS)0x00000000L) 
	
	
	typedef struct _UNICODE_STRING {
		USHORT Length;
		USHORT MaximumLength;
		PWSTR  Buffer;
	} UNICODE_STRING, *PUNICODE_STRING;

	typedef struct _ANSI_STRING
	{
		USHORT Length;
		USHORT MaximumLength;
		PSTR   Buffer;
	} ANSI_STRING;
	typedef ANSI_STRING *PANSI_STRING;

	BOOL SeInitializeMember();
	BOOL SeEnableSeDebugPrivilege(const TCHAR*  PriviledgeName, BOOL IsEnable);
	HANDLE SeOpenProcess(DWORD DesiredAccess, BOOL IsInheritHandle, HANDLE ProcessIdentify);
	
	//Kernel32.dll
	//BOOL SeGetProcessIdentify(HANDLE* ProcessIdentify, ULONG_PTR ProcessIdentifyLength,const TCHAR* ProcessImageName, ULONG_PTR ProcessImageNameLength);
	

	//Ntdll.dll
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
typedef LONG KPRIORITY;
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
		//    SYSTEM_THREAD_INFORMATION TH[1];
	} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;


#ifdef UNICODE
#define SeGetProcessIdentify SeGetProcessIdentifyW
#else
#define SeGetProcessIdentify SeGetProcessIdentifyA
#endif

	BOOL SeGetProcessIdentifyA(HANDLE* ProcessIdentify, ULONG_PTR ProcessIdentifyLength,
		const CHAR* ProcessImageName,
		ULONG_PTR ProcessImageNameLength);
	BOOL SeGetProcessIdentifyW(HANDLE* ProcessIdentify, ULONG_PTR ProcessIdentifyLength,
		const WCHAR* ProcessImageName,
		ULONG_PTR ProcessImageNameLength);

	//通过进程句柄在进程空间申请内存(Kernel32.dll)
	BOOL SeProcessMemoryWriteSafe(HANDLE ProcessHandle, LPVOID VirtualAddress, LPCVOID BufferData, SIZE_T BufferLength, SIZE_T* ReturnLength);
	BOOL SeProcessMemoryReadSafe(HANDLE ProcessHandle, LPVOID VirtualAddress, LPVOID BufferData, SIZE_T BufferLength, SIZE_T* ReturnLength);
	
	BOOL SeCloseHandle(HANDLE HandleValue);

	//通过进程完整路径映射PE文件到当前进程空间判断目标进程的位数(Option->Magic)
	BOOL SeIsWow64Process(TCHAR* ProcessFullPath, ULONG_PTR ProcessFullPathLength, PBOOL  Wow64Process);


#ifdef UNICODE
#define SeGetProcessFullPath SeGetProcessFullPathW
#else
#define SeGetProcessFullPath SeGetProcessFullPathA
#endif
	//通过进程句柄获得进程完整路径(Psapi.dll) 😁需要转换路径
	BOOL SeGetProcessFullPathA(CHAR** ProcessFullPath, ULONG_PTR* ProcessFullPathLength, HANDLE ProcessIdentify, BOOL IsAllocate);
	BOOL SeGetProcessFullPathW(WCHAR** ProcessFullPath, ULONG_PTR* ProcessFullPathLength, HANDLE ProcessIdentify, BOOL IsAllocate);

#ifdef UNICODE
#define SeDosPathToNtPath SeDosPathToNtPathW
#else
#define SeDosPathToNtPath SeDosPathToNtPathA
#endif
	BOOL SeDosPathToNtPathA(CHAR** DestinationData, ULONG_PTR* DestinationDataLength, CHAR* SourceData, ULONG_PTR SourceDataLength,BOOL IsAllocate);
	BOOL SeDosPathToNtPathW(WCHAR** DestinationData, ULONG_PTR* DestinationDataLength, WCHAR* SourceData, ULONG_PTR SourceDataLength,BOOL IsAllocate);



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

	BOOL SeGetProcessPebEx(IN HANDLE ProcessIdentify, OUT PPEB Peb);

	typedef enum _PROCESSINFOCLASS
	{
		ProcessBasicInformation,
		ProcessQuotaLimits,
		ProcessIoCounters,
		ProcessVmCounters,
		ProcessTimes,
		ProcessBasePriority,
		ProcessRaisePriority,
		ProcessDebugPort,
		ProcessExceptionPort,
		ProcessAccessToken,
		ProcessLdtInformation,
		ProcessLdtSize,
		ProcessDefaultHardErrorMode,
		ProcessIoPortHandlers,
		ProcessPooledUsageAndLimits,
		ProcessWorkingSetWatch,
		ProcessUserModeIOPL,
		ProcessEnableAlignmentFaultFixup,
		ProcessPriorityClass,
		ProcessWx86Information,
		ProcessHandleCount,
		ProcessAffinityMask,
		ProcessPriorityBoost,
		ProcessDeviceMap,
		ProcessSessionInformation,
		ProcessForegroundInformation,
		ProcessWow64Information,
		ProcessImageFileName,
		ProcessLUIDDeviceMapsEnabled,
		ProcessBreakOnTermination,
		ProcessDebugObjectHandle,
		ProcessDebugFlags,
		ProcessHandleTracing,
		ProcessIoPriority,
		ProcessExecuteFlags,
		ProcessTlsInformation,
		ProcessCookie,
		ProcessImageInformation,
		ProcessCycleTime,
		ProcessPagePriority,
		ProcessInstrumentationCallback,
		ProcessThreadStackAllocation,
		ProcessWorkingSetWatchEx,
		ProcessImageFileNameWin32,
		ProcessImageFileMapping,
		ProcessAffinityUpdateMode,
		ProcessMemoryAllocationMode,
		MaxProcessInfoClass
	} PROCESSINFOCLASS;

	typedef LONG KPRIORITY;
	typedef struct _PROCESS_BASIC_INFORMATION
	{
		NTSTATUS ExitStatus;
		PPEB PebBaseAddress;
		ULONG_PTR AffinityMask;    
		KPRIORITY BasePriority;
		ULONG_PTR UniqueProcessId;
		ULONG_PTR InheritedFromUniqueProcessId;
	} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;

	typedef
	NTSTATUS(NTAPI *LPFN_NTQUERYINFORMATIONPROCESS)(
			_In_ HANDLE ProcessHandle,
			_In_ PROCESSINFOCLASS ProcessInformationClass,
			_Out_ PVOID ProcessInformation,
			_In_ ULONG ProcessInformationLength,
			_Out_opt_ PULONG ReturnLength);




}