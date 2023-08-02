#include "pe.h"
#include <libloaderapi.h>
#include <pe_parser.h>
#include <utils.h>

#include <Windows.h>

// 只支持大写不带后缀的模块名，如NTDLL
PVOID get_loaded_module_base(DWORD dwHash)
{
#ifdef _WIN64
	_PMYPEB pPeb = (_PMYPEB)__readgsqword(0x60);
    printf("current x64\r\n");
#else
	_PMYPEB pPeb = (_PMYPEB)__readfsdword(0x30);
#endif
    char name_buf[0x256];
	PPEB_LDR_DATA pLdr = pPeb->pLdr;
	PLDR_DATA_TABLE_ENTRY pLdrEntry = (PLDR_DATA_TABLE_ENTRY)(pLdr->InLoadOrderModuleList.Flink);
	while (pLdrEntry) {
		char* pModName = (char*)(pLdrEntry->BaseDllName.pBuffer);

        char* p1 = pModName;
        char* p2 = p1 + 1;
        int i = 0;
        for(i = 0;*p1 != 0 || *p2 != 0;i++)
        {
            char tmp = 0;
            if (*p1 >= 'a' && *p1 <= 'z') {
                tmp = *p1 - 32;
                name_buf[i] = tmp;
            }
            else
            {
                name_buf[i] = *p1;
            }
            p1 += 2;
            p2 = p1 + 1;
        }
        name_buf[i] = 0;

        char* p = name_buf;
        while(*p++)
        {
            if(*p == '.')
                *p = 0;
        }

		ULONG64 ulNameLen = pLdrEntry->BaseDllName.Length;
        DWORD ulDllNameHash = str_hash(name_buf);
		DWORD dwFindFunNum = 0;
		if (ulDllNameHash == dwHash)
            return pLdrEntry->DllBase;
			
		pLdrEntry = (PLDR_DATA_TABLE_ENTRY)(*(size_t*)pLdrEntry);
	}
	return NULL;
}

PVOID pe_get_export_func(char* pBase, DWORD dwHash)
{
    PIMAGE_DOS_HEADER pTebDllBase = (PIMAGE_DOS_HEADER)(pBase);
	PIMAGE_NT_HEADERS pTebNts = (PIMAGE_NT_HEADERS)((ULONG_PTR)pTebDllBase + pTebDllBase->e_lfanew);
	PIMAGE_DATA_DIRECTORY pTebExportDir = (PIMAGE_DATA_DIRECTORY) & (pTebNts->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
	PIMAGE_EXPORT_DIRECTORY pTebExp = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)pTebDllBase + pTebExportDir->VirtualAddress);

	int* rva_table = (int*)(pBase + pTebExp->AddressOfFunctions);
	short* ord_table = (short*)(pBase + pTebExp->AddressOfNameOrdinals);
	int* name_table = (int*)(pBase + pTebExp->AddressOfNames);

	for (int i = 0; i < pTebExp->NumberOfNames; i++)
	{
		int cur_rva = rva_table[ord_table[i]];
		int cur_hash = str_hash(pBase + name_table[i]);
		if (cur_hash == dwHash)
		{
			// 判断导出转发函数(函数地址处保存的是转发的模块+函数名)
			if (cur_rva > pTebExportDir->VirtualAddress && cur_rva < (pTebExportDir->VirtualAddress + pTebExportDir->Size))
			{
				// NTDLL.RtlAddVectoredExceptionHandler
				char* forward_str = pBase + cur_rva;
				size_t real_size = 0;

				char* p = forward_str;
				while (*(p++))
				{
					if (*p == '.')
                    {
			            *p = '\0';
						break;
                    }
				}
				char* pModName = forward_str;
				char* pFunName = p + 1;

				HMODULE hmod = (HMODULE)get_loaded_module_base(str_hash(pModName));
				if (!hmod)
                {
                    perror("pe_export: load forword module failed.");
                    return NULL;
                }

				PVOID retfun = (PVOID)pe_get_export_func((char*)hmod, str_hash(pFunName));
				if (!retfun)
                {
                    perror("pe_export: get forword function failed.");
                    return NULL;
                }


				return retfun;
			}
			return cur_rva + pBase;
		}
	}
	return NULL;
}