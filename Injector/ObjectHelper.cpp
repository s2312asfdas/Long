#include "ObjectHelper.h"



namespace _OBJECT_HELPER_
{
	LPFN_NTQUERYOBJECT __NtQueryObject = NULL;

	BOOL SeInitializeMember()
	{

		HMODULE ModuleHandle = NULL;
		ULONG   ReturnLength = 0;
		ModuleHandle = GetModuleHandle(_T("Ntdll.dll"));
		if (ModuleHandle == NULL)
		{
			return FALSE;
		}
		__NtQueryObject = (LPFN_NTQUERYOBJECT)GetProcAddress(ModuleHandle, "NtQueryObject");
		if (__NtQueryObject == NULL)
		{
			return FALSE;
		}

		return TRUE;

	}
}