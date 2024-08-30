
#include "SystemHelper.h"

namespace  _SYSTEM_HELPER_
{


	LPFN_NTQUERYSYSTEMINFORMATION  __NtQuerySystemInformation = NULL;

	BOOL SeInitializeMember()
	{
		HMODULE ModuleHandle = GetModuleHandle(_T("Ntdll.dll"));
		if (ModuleHandle==NULL)
		{
			return FALSE;
		}
		
		
		//获得ntdll模块下的函数地址
		__NtQuerySystemInformation = (LPFN_NTQUERYSYSTEMINFORMATION)GetProcAddress(ModuleHandle, "NtQuerySystemInformation");
		if (__NtQuerySystemInformation==NULL)
		{
			return FALSE;
		}

		return TRUE;
	}
	//获得操作系统位数
	ULONG SeGetOSBit()
	{
		int LastError = 0;
		SYSTEM_INFO SystemInfo = { 0 };
		GetNativeSystemInfo(&SystemInfo);
		if (SystemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ||
			SystemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64)
		{
			return 64;
		}
		else if (SystemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL)
		{
			return 32;
		}


		LastError = ERROR_MP_PROCESSOR_MISMATCH;
		SetLastError(LastError);
		return 0;
	}

}
