#include "StringHelper.h"

namespace _STRING_HELPER_
{
	LPFN_RTLUNICODESTRINGTOANSISIZE     __RtlUnicodeStringToAnsiSize = NULL;
	LPFN_RTLUNICODESTRINGTOANSISTRING	__RtlUnicodeStringToAnsiString = NULL;
	BOOL SeInitializeMember()
	{
		HMODULE ModuleHandle = GetModuleHandle(_T("Ntdll.dll"));
		if (ModuleHandle == NULL)
		{
			return FALSE;
		}
		__RtlUnicodeStringToAnsiSize = (LPFN_RTLUNICODESTRINGTOANSISIZE)GetProcAddress(ModuleHandle, "RtlUnicodeStringToAnsiSize");
		__RtlUnicodeStringToAnsiString = (LPFN_RTLUNICODESTRINGTOANSISTRING)GetProcAddress(ModuleHandle, "RtlUnicodeStringToAnsiString");
		if (__RtlUnicodeStringToAnsiSize == NULL || __RtlUnicodeStringToAnsiString == NULL)
		{
			return FALSE;
		}
		return TRUE;
	}

	VOID
	RtlInitUnicodeString(
		OUT PUNICODE_STRING DestinationString,
		IN PCWSTR SourceString OPTIONAL
		)
	{
		SIZE_T Size;
	#define MAXUSHORT 0xffff
		const SIZE_T MaxSize = (MAXUSHORT & ~1) - sizeof(UNICODE_NULL); // an even number

		if (SourceString)
		{
			Size = wcslen(SourceString) * sizeof(WCHAR);
		
			if (Size > MaxSize)
				Size = MaxSize;
			DestinationString->Length = (USHORT)Size;
			DestinationString->MaximumLength = (USHORT)Size + sizeof(UNICODE_NULL);
		}
		else
		{
			DestinationString->Length = 0;
			DestinationString->MaximumLength = 0;
		}

		DestinationString->Buffer = (PWCHAR)SourceString;
	}

	LONG 
	RtlCompareUnicodeString(
		IN PUNICODE_STRING s1,
		IN PUNICODE_STRING s2,
		IN BOOLEAN  CaseInsensitive)  
	{
		unsigned int len;
		LONG ret = 0;
		LPCWSTR p1, p2;
		len = min(s1->Length, s2->Length) / sizeof(WCHAR);
		p1 = s1->Buffer;
		p2 = s2->Buffer;
	


		if (CaseInsensitive)
		{
			p1 = CharUpperW(s1->Buffer);
			p2 = CharUpperW(s2->Buffer);
			while (!ret && len--)
			{
				ret = *p1 - *p2;
				p1++;
				p2++;
			}
		}
		else
		{
			while (!ret && len--)
			{
				ret = *p1 - *p2;

				p1++;
				p2++;
			}
		}
		if (!ret)
		{
			ret = s1->Length - s2->Length;
		}
		return ret;
	}




}



