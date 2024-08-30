#pragma once
#include <windows.h>
#include <iostream>
#include <tchar.h>
#include"SetWindowHookExHelper.hpp"


namespace _SETWINDOWHOOK_
{
	void setwindow_inject();
	void setwindow_inject()
	{
		_SETWINDOWHOOK_HELPER_::setwindow_inject_helper();
	}

}