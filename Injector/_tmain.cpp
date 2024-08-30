#include<iostream>
#include<tchar.h>
#include"Registry.hpp"
#include"CreatRemoteThread.hpp"
#include"SetWindowHookEx.hpp"
#include"APCInject.hpp"
#include"HijackEip.hpp"
#include"HideInject.hpp"
//using namespace std;

#define REGISTER_INJECT      0
#define CREATE_REMOTE_THREAD 1
#define APC_INJECOT          2
#define SETWINDOWHOOKEX      3
#define HOOK_EIP             4

void _tmain(int argc, char* argv[], char* envp[])
{
	int flag;
	int inject_method;
	_tprintf(_T("Please Input Inject Method:(0~4)\r\n"));
	cin >> inject_method;
	_stscanf_s((const wchar_t*)argv[inject_method], _T("%d"), &flag);
	switch (flag)
	{
	case REGISTER_INJECT:
	{
		_REGISTRY_INHECT_::registry_inject();
	}
	case CREATE_REMOTE_THREAD:
	{
		_REMOTE_THREAD_INHECT_::create_remotethread_inject();
	}
	case SETWINDOWHOOKEX:
	{
		_SETWINDOWHOOK_::setwindow_inject();
	}
	case APC_INJECOT:
	{
		_APC_INJECT_::apc_inject();
	}
	case HOOK_EIP:
	{
		_HIJACK_EIP_::hijack_eip();
	}
	}

	

	


}

