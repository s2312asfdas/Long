#pragma once
#include <windows.h>
#include <iostream>
#include <tchar.h>
#include<atlstr.h>


	class InjectClass
	{
	public:
		HKL InputHandle;
		HKL oldInputHandle;
		TCHAR ImeSymbol[255];

		InjectClass(void);
		~InjectClass(void);
		void GetImeHandleString();
		bool ImeInstall(LPCWSTR lpszdllName);
		HKL EnumIme(CString InputName, CString FileName);
	};

