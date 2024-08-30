#pragma once
#include <windows.h>
#include <iostream>
#include <tchar.h>
#include <vector>
#include"RegistryHelper.hpp"

namespace _REGISTRY_INHECT_
{
	void registry_inject();
	void registry_inject()
	{
#ifdef _WIN64
		TCHAR dll_fullpath[MAX_PATH] = _T("Dll.dll");
#else
		TCHAR dll_fullpath[MAX_PATH] = _T("Dll.dll");
#endif
		_tprintf(_T("Input AnyKey To Begin Inject!\r\n"));
		_gettchar();

		BOOL is_ok = _REGISTER_HELPER_::registry_inject_helper(dll_fullpath);
		if (!is_ok)
			_tprintf(_T("Register Inject Success!\r\n"));
		else
			_tprintf(_T("Register Inject Fail!\r\n"));
		_tprintf(_T("Input AnyKey To Exit!\r\n"));
		_gettchar();
	}
}






