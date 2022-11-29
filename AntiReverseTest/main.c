#include <conio.h>
#include <stdio.h>
#include <string.h>

#include <windows.h>

#include "md5.h"
#include "sha1.h"

// MASM functions
EXTERN_C VOID set_exception_handler(DWORD address);
EXTERN_C VOID f_rop(LPSTR buf, LPSTR str, DWORD len);

// TLS Callback
VOID WINAPI tls_callback1(PVOID dll_handle, DWORD reason, PVOID reserved);
#pragma comment (linker, "/INCLUDE:__tls_used")
#pragma comment (linker, "/INCLUDE:_p_tls_callback1")
#pragma data_seg(push)
#pragma data_seg(".CRT$XLAAA")
EXTERN_C PIMAGE_TLS_CALLBACK p_tls_callback1 = tls_callback1;
#pragma data_seg(pop)

// custom exception handler
DWORD WINAPI user_exception_dispatcher(CONST EXCEPTION_RECORD* exception_record, DWORD res1, CONTEXT* context, DWORD res2);

// main
INT main(INT argc, CHAR** argv);

// buffer for implementing function call via ROP
BYTE s_rop[8] = "ROP!";
//

VOID WINAPI tls_callback1(PVOID dll_handle, DWORD reason, PVOID reserved)
{
	PVOID p_nt_query_information_process;
	BOOL b = FALSE;

	if (reason != 1)
		return;

	__asm // IsDebuggerPresent
	{
		mov eax, fs: [18h]
		mov eax, [eax + 30h]
		movzx eax, BYTE PTR[eax + 2h]
		mov b, eax
	}

	printf("IsDebuggerPresent = %d\n", b);
	p_nt_query_information_process = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");

	__asm // NtQueryInformationProcess
	{
		push eax
		mov  eax, esp
		push 0
		push 4
		push eax
		push 7 // ProcessDebugPort
		push 0ffffffffh
		call p_nt_query_information_process
		pop  b
	}

	printf("ProcessDebugPort = %d\n", b);

	// configure the s_rop buffer to call the md5() function via buffer overflow in f_rop()
	DWORD p_md5 = (DWORD)&md5;
	s_rop[4] = (CHAR) * (PBYTE)&p_md5;
	s_rop[5] = (CHAR) * ((PBYTE)&p_md5 + 1);
	s_rop[6] = (CHAR) * ((PBYTE)&p_md5 + 2);
	s_rop[7] = 0;

	// replace the exception handler
	set_exception_handler((DWORD)user_exception_dispatcher);

	// calculate addresses of pages containing program functions
	DWORD base;
	DWORD old_pr;

	DWORD page_tls = (DWORD)tls_callback1 >> 12 << 12;
	DWORD page_main = (DWORD)main >> 12 << 12;
	DWORD page_disp = (DWORD)user_exception_dispatcher >> 12 << 12;

	DWORD page_tls1 = *(PDWORD)((PBYTE)tls_callback1 + 1) + (DWORD)tls_callback1 + 5;
	DWORD page_main1 = *(PDWORD)((PBYTE)main + 1) + (DWORD)main + 5;
	DWORD page_disp1 = *(PDWORD)((PBYTE)user_exception_dispatcher + 1) + (DWORD)user_exception_dispatcher + 5;

	page_tls1 = page_tls1 >> 12 << 12;
	page_main1 = page_main1 >> 12 << 12;
	page_disp1 = page_disp1 >> 12 << 12;

	// set PAGE_GUARD on 0x13 memory pages containing the project functions' code,
	// skipping the PE header and C runtime library functions
	for (DWORD i = 1; i < 0x14; i++)
	{
		base = (DWORD)dll_handle + (i << 12);
		PDWORD dwp = (PDWORD)base;
		VirtualProtect((PVOID)base, 0x1000, PAGE_EXECUTE_READWRITE, &old_pr);

		if (base == page_main || base == page_main1 || // do not set PAGE_GUARD on main
			base == page_tls || base == page_tls1 || // do not set PAGE_GUARD on TLS callback
			base == page_disp || base == page_disp1) // do not set PAGE_GUARD on Exception Dispatcher
		{
			continue;
		}

		for (DWORD j = 0; j < 1024; j++)
			dwp[j] ^= 0xFFFFFFFF;

		VirtualProtect((PVOID)base, 0x1000, PAGE_EXECUTE_READWRITE | PAGE_GUARD, &old_pr);
	}
}

DWORD WINAPI user_exception_dispatcher(CONST EXCEPTION_RECORD* exception_record, DWORD res1, CONTEXT* context, DWORD res2)
{
	if (exception_record->ExceptionCode == 0x80000001) // EXCEPTION_GUARD_PAGE
	{
		printf("KiUserExceptionDispatcher: Guarded page accessed!\n");
		DWORD base = (DWORD)exception_record->ExceptionAddress >> 12 << 12;
		PDWORD dwp = (PDWORD)base;

		for (DWORD j = 0; j < 1024; j++)
			dwp[j] ^= 0xFFFFFFFF;

		// function code may cross a page boundary,
		// in which case remove the PAGE_GUARD attribute from the next page as well
		if (((DWORD)exception_record->ExceptionAddress & 0xFFF) > 0xFF0)
		{
			DWORD oldPr;

			base += 0x1000;
			VirtualProtect((PVOID)base, 0x1000, PAGE_EXECUTE_READWRITE, &oldPr);
			dwp = (PDWORD)base;

			if (oldPr & PAGE_GUARD)
			{
				for (INT j = 0; j < 1024; j++)
					dwp[j] ^= 0xFFFFFFFF;
			}
		}

		return 0;
	}

	return 1;
}

INT main(INT argc, CHAR** argv)
{
	set_exception_handler((DWORD)user_exception_dispatcher);

	if (argc > 3)
	{
		printf("usage: %s <md5|sha-1> <string>\n", argv[0]);
		return 1;
	}

	if (argc == 3)
	{
		printf("Input string: %s\n", argv[2]);

		if (strcmp(argv[1], "md5") == 0)
			md5(argv[2], strlen(argv[2]));
		else if (strcmp(argv[1], "sha-1") == 0)
			SHA1(argv[2], strlen(argv[2]));
		else
		{
			printf("usage: %s <md5|sha-1> <string>\n", argv[0]);
			return 1;
		}

		return 0;
	}

	CHAR msg[1024];
	CHAR num[1024];

	printf("1. MD5\n2. SHA-1\n0. Exit\n>");
	scanf_s("%s", num, 1024);

	if (num[0] < '0' || num[0] > '9')
	{
		printf("Invalid value\n");
		_getch();
		return 1;
	}

	num[1] = 0;
	INT k = _atoi_l(num, 0);
	DWORD len = 0;

	if (k > 2)
	{
		printf("Invalid command\n");
		_getch();
		return 1;
	}

	if (k > 0)
	{
		printf("Enter string: ");
		memset(msg, 0, 1024);
		scanf_s("%s", msg, 1024);
		len = strlen(msg);
	}

	switch (k)
	{
	case 1:
		f_rop(s_rop, msg, len); // implicit call to md5()
		break;

	case 2:
		SHA1(msg, len);
		break;

	case 0:
		printf("Good bye!\n");
		break;

	default:
		break;
	}

	_getch();
	ExitProcess(0);
}
