#pragma once
#include <windows.h>
#include <tchar.h>
#include <iostream>
using namespace std;



namespace _ERROR_HELPER_
{

	typedef
		ULONG(WINAPI *LPFN_RTLNTSTATUSTODOSERROR)(
			IN NTSTATUS Status);


	typedef _Return_type_success_(return >= 0) LONG NTSTATUS;
	
	
	BOOL  SeInitializeMember();
	ULONG SeBaseSetLastNTError(IN NTSTATUS Status);
	VOID SeOutputErrorInformation(__in_z CONST PTCHAR ParameterData1,
		__in_z CONST PTCHAR ParameterData2);
};

