
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
		
		
		//���ntdllģ���µĺ�����ַ
		__NtQuerySystemInformation = (LPFN_NTQUERYSYSTEMINFORMATION)GetProcAddress(ModuleHandle, "NtQuerySystemInformation");
		if (__NtQuerySystemInformation==NULL)
		{
			return FALSE;
		}

		return TRUE;
	}
	//��ò���ϵͳλ��
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
