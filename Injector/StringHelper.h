#pragma once
#include <windows.h>
#include <tchar.h>
#include <iostream>
using namespace std;


namespace _STRING_HELPER_
{

	typedef struct _UNICODE_STRING {
		USHORT Length;                          
		USHORT MaximumLength;             
		PWSTR  Buffer;                         
	} UNICODE_STRING, *PUNICODE_STRING;

	typedef struct _ANSI_STRING
	{
		USHORT Length;
		USHORT MaximumLength;
		PSTR   Buffer;
	} ANSI_STRING;
	typedef ANSI_STRING *PANSI_STRING;

	typedef ULONG(WINAPI *LPFN_RTLUNICODESTRINGTOANSISIZE)(
		IN PUNICODE_STRING UnicodeString);
	typedef NTSTATUS(WINAPI * LPFN_RTLUNICODESTRINGTOANSISTRING)(PANSI_STRING DestinationString,
		PUNICODE_STRING SourceString,
		BOOLEAN AllocateDestinationString);

	extern LPFN_RTLUNICODESTRINGTOANSISIZE		__RtlUnicodeStringToAnsiSize;
	extern LPFN_RTLUNICODESTRINGTOANSISTRING	__RtlUnicodeStringToAnsiString;

	VOID RtlInitUnicodeString(OUT PUNICODE_STRING DestinationString,IN PCWSTR SourceString OPTIONAL);
	LONG
		RtlCompareUnicodeString(
			IN PUNICODE_STRING String1,
			IN PUNICODE_STRING String2,
			IN BOOLEAN CaseInSensitive);
	WCHAR RtlUpcaseUnicodeChar(IN WCHAR Source);



}

