#include "pe.h"
#include <libloaderapi.h>
#include <pe_parser.h>
#include <utils.h>

#include <Windows.h>

intptr_t pe_get_export_func(pe_t* pe, intptr_t base, int hash)
{
    int32_t virtual_address = 0;
    int32_t virtual_size = 0;
    switch(pe->type)
    {
        case MAGIC_32BIT:
            virtual_address = ((pe32_t*)pe)->optional_header->export_table.virtual_address;
            virtual_size = ((pe32_t*)pe)->optional_header->export_table.size;
            break;
        case MAGIC_64BIT:
            virtual_address = ((pe64_t*)pe)->optional_header->export_table.virtual_address;
            virtual_size = ((pe64_t*)pe)->optional_header->export_table.size;
            break;
        default:
            perror("pe_export: only support x86 or x64.");
            return 0;
    }

    pe_export_table_t* pexp = (pe_export_table_t*)(base + virtual_address);

    int* rva_table = (int*)(base + pexp->AddressOfFunctions);
    short* ord_table = (short*)(base + pexp->AddressOfNameOrdinals);
    int* name_table = (int*)(base + pexp->AddressOfNames);

    for(int i = 0; i < pexp->NumberOfNames; i++) 
    {
        int cur_rva = rva_table[ord_table[i]];
        int32_t cur_hash = str_hash((char*)(base + name_table[i]));
        if(cur_hash == hash) 
        {
            // 判断导出转发函数(函数地址处保存的是转发的模块+函数名)
            if(cur_rva > virtual_address && cur_rva < (virtual_address + virtual_size))
            {
                // NTDLL.RtlAddVectoredExceptionHandler
                char* forward_str = (char*)(base + cur_rva);
                size_t real_size = 0;
                char** psub = split_string(forward_str, (char*)".", &real_size);
                if(!psub || real_size < 2)
                {
                    perror("pe_export: split forward export function failed.");
                    return 0;
                }

                HMODULE hmod = LoadLibraryA(psub[0]);
                if(!hmod)
                {
                    perror("pe_export: load forword module failed.");
                    return 0;
                }

                intptr_t retfun = (intptr_t)GetProcAddress(hmod, psub[1]);
                if(!retfun)
                {
                    perror("pe_export: get forword function failed.");
                    return 0;
                }

                return retfun;
            }
            return cur_rva + base;
        }
    }
    perror("pe_export: not find target function.");
    return 0;
}