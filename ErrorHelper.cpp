#include "ErrorHelper.h"
#include <assert.h>

namespace _ERROR_HELPER_
{
	LPFN_RTLNTSTATUSTODOSERROR         __RtlNtStatusToDosError       = NULL;
	BOOL SeInitializeMember()
	{
		HMODULE NtdllModule = GetModuleHandle(_T("ntdll.dll"));
		if (!NtdllModule)
		{
			return FALSE;
		}
		if (__RtlNtStatusToDosError == NULL)
		{
			__RtlNtStatusToDosError = (LPFN_RTLNTSTATUSTODOSERROR)GetProcAddress(NtdllModule, "RtlNtStatusToDosError");
		}

		return TRUE;
	}
	ULONG SeBaseSetLastNTError(IN NTSTATUS Status)
	{
		LONG ErrorCode;

		ErrorCode = __RtlNtStatusToDosError(Status);
		SetLastError(ErrorCode);
		return(ErrorCode);
	}
	VOID SeOutputErrorInformation(__in_z CONST PTCHAR ParameterData1,
		__in_z CONST PTCHAR ParameterData2)
	{
#define PAGE_SIZE 0x1000
		TCHAR v1[PAGE_SIZE] = { 0 };

		assert(NULL != ParameterData1);
		assert(NULL != ParameterData2);

	
		_stprintf_s(v1, _T("%s::%s ErrorCode:%d\r\n"),
			ParameterData1, ParameterData2, GetLastError());
		OutputDebugString(v1);
	}
}


