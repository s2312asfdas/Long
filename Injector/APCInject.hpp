#pragma once
#include <windows.h>
#include <iostream>
#include <tchar.h>
#include"APCInjectHelper.hpp"

namespace _APC_INJECT_
{
	void apc_inject();
	void apc_inject()
	{
		_APC_INJECT_HELPER_::apc_inject_helper();
	}
}