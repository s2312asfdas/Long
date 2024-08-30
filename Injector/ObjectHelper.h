#pragma once
#include <windows.h>
#include <tchar.h>
#include <iostream>
using namespace std;

namespace  _OBJECT_HELPER_
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


	typedef enum _OBJECT_INFORMATION_CLASS
	{
		ObjectBasicInformation,
		ObjectNameInformation,
		ObjectTypeInformation,
		ObjectTypesInformation,
		ObjectHandleFlagInformation,
		ObjectSessionInformation,
		MaxObjectInfoClass
	} OBJECT_INFORMATION_CLASS;



	//宏2使用该结构
	typedef struct _OBJECT_TYPE_INFORMATION
	{
		UNICODE_STRING TypeName;
		ULONG TotalNumberOfObjects;
		ULONG TotalNumberOfHandles;
		ULONG TotalPagedPoolUsage;
		ULONG TotalNonPagedPoolUsage;
		ULONG TotalNamePoolUsage;
		ULONG TotalHandleTableUsage;
		ULONG HighWaterNumberOfObjects;
		ULONG HighWaterNumberOfHandles;
		ULONG HighWaterPagedPoolUsage;
		ULONG HighWaterNonPagedPoolUsage;
		ULONG HighWaterNamePoolUsage;
		ULONG HighWaterHandleTableUsage;
		ULONG InvalidAttributes;
		GENERIC_MAPPING GenericMapping;
		ULONG ValidAccessMask;
		BOOLEAN SecurityRequired;
		BOOLEAN MaintainHandleCount;
		ULONG PoolType;
		ULONG DefaultPagedPoolCharge;
		ULONG DefaultNonPagedPoolCharge;
	} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;



	typedef
		NTSTATUS(WINAPI* LPFN_NTQUERYOBJECT)(IN HANDLE ObjectHandle,
			IN OBJECT_INFORMATION_CLASS ObjectInformationClass,
			OUT PVOID ObjectInformation,
			IN ULONG Length,
			OUT PULONG ResultLength OPTIONAL);



	extern LPFN_NTQUERYOBJECT __NtQueryObject;

}
