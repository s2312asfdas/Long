// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include"MemoryHelper.h"
BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
		HANDLE mapping_handle = NULL;
		ULONG_PTR virtual_address = NULL;
		DWORD last_error = 0;
		HANDLE process_identify = (HANDLE)GetCurrentProcessId();
		TCHAR v1[MAX_PATH] = { 0 };

		if (_MEMORY_HELPER_::SeMappingMemoryEx(ACCESS_WRITE, 0, 0x1000, _T("SHINE"), &mapping_handle, &virtual_address) == FALSE)
		{
			last_error = GetLastError();
		}
		else
		{
			__try
			{
				memcpy((LPVOID)virtual_address, &hModule,
					sizeof(HMODULE));   //IPC
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				last_error = GetExceptionCode();
			}
		}
		if (virtual_address != NULL)
		{
			_stprintf(v1, _T("SectionObject:%p"), *(HMODULE)virtual_address);
			MessageBox(NULL, v1, _T("Injection"), 0);
		}
		_MEMORY_HELPER_::SeUnmapMemoryEx(mapping_handle, virtual_address); //回收资源
		break;
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}


void text_1()
{

	HANDLE ProcessIdentify = (HANDLE)GetCurrentProcessId();

	TCHAR v1[MAX_PATH] = { 0 };

	_stprintf(v1, _T("%d  Sub_1()"), ProcessIdentify);
	MessageBox(NULL, v1, _T("Injection"), 0);
}

