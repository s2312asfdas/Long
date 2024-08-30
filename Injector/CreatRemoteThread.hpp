#pragma once
#include <windows.h>
#include <iostream>
#include <tchar.h>
#include"CreateRemoteThreadHelper.hpp"


namespace _REMOTE_THREAD_INHECT_
{
	void create_remotethread_inject();
	void create_remotethread_inject()
	{
		_REMOTE_THREAD_INHECT_HELPER_::create_remotethread_inject_Helper();
	}


}