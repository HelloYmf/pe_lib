#include <pe.h>
#include <cstdint>
#include <pe_parser.h>
#include <string.h>
#include <stdlib.h>
#include <Windows.h>

#include <iostream>
#include <winnt.h>

DWORD pe_get_section_idx32(PCHAR pBuffer, PCHAR pSecName)
{
    DWORD dwCmp = strlen(pSecName) > 8 ? 8 : strlen(pSecName);
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBuffer;
    PIMAGE_NT_HEADERS32 pNts = (PIMAGE_NT_HEADERS32)(pBuffer + pDos->e_lfanew);
    PIMAGE_SECTION_HEADER pSecs = (PIMAGE_SECTION_HEADER)((char*)pNts + sizeof(IMAGE_NT_HEADERS32));
    for(int i = 0; i < pNts->FileHeader.NumberOfSections; i++)
    {
        bool flag = true;
        int dwCurNameSize = 0;
        for(int j = 0; j < 8; j++)
        {
            if(pSecs[i].Name[j])
                dwCurNameSize++;      
        }
        int dwCmpNameSize = 0;
        for(int j = 0; j < dwCmp; j++)
        {
            if(pSecs[i].Name[j] != pSecName[j])
            {
                flag = false;
            }
            dwCmpNameSize++;
        }
        if(flag && dwCmpNameSize == dwCurNameSize)
            return i;
    }
    return -1;
}

size_t pe_get_section_null_size(pe_t* pe, const char* sec_name)
{
    int i = 0;
    for(; i < pe->number_of_sections; i++)
    {
        if(strcmp(pe->section_header[i]->name, sec_name) == 0)
        {
            break;
        }
    }
    if(i == pe->number_of_sections)
    {
        perror("can't find section");
        return 0;
    }
    
    uint32_t virtual_size = pe->section_header[i]->virtual_size;
    return pe->section_header[i+1]->virtual_address - (pe->section_header[i]->virtual_address + virtual_size);
}

// 因为32位和64位对异常表支持的不一样，所以需要分别处理
PCHAR pe_extend_section32(PCHAR pOldImageBuffer, DWORD dwIdx, DWORD dwSize, DWORD* pExtendStartRva)
{
    PIMAGE_DOS_HEADER old_dos_header = (PIMAGE_DOS_HEADER)pOldImageBuffer;
    PIMAGE_NT_HEADERS32 old_nt_header = (PIMAGE_NT_HEADERS32)(pOldImageBuffer + old_dos_header->e_lfanew);
    PIMAGE_SECTION_HEADER old_section_header = (PIMAGE_SECTION_HEADER)((char*)old_nt_header + sizeof(IMAGE_NT_HEADERS32));

    uint32_t new_rva_size = 0;                      // off_rva
    uint32_t new_foa_size = 0;                      // off_foa

    uint32_t section_align = old_nt_header->OptionalHeader.SectionAlignment;
    uint32_t file_align = old_nt_header->OptionalHeader.FileAlignment;

    new_rva_size = ( (dwSize > section_align ? (dwSize / section_align) : 0)
            + (dwSize % section_align != 0 ? 1 : 0) ) * section_align;
    new_rva_size += (new_rva_size == 0 ? section_align : 0);

    new_foa_size = ( (dwSize > file_align ? (dwSize / file_align) : 0)
            + (dwSize % file_align != 0 ? 1 : 0) ) * file_align;
    new_foa_size += (new_foa_size == 0 ? file_align : 0);

    uint32_t new_image_size = old_nt_header->OptionalHeader.SizeOfImage + new_rva_size;
    char* new_image_buffer = (char*)malloc(new_image_size);
    if(!new_image_buffer)
        return NULL;
    memset(new_image_buffer, 0, new_image_size);

    // copy old file headers -> new image buffer
    memcpy(new_image_buffer, pOldImageBuffer, old_nt_header->OptionalHeader.SizeOfHeaders);

    PIMAGE_DOS_HEADER new_dos_header = (PIMAGE_DOS_HEADER)new_image_buffer;
    PIMAGE_NT_HEADERS32 new_nt_header = (PIMAGE_NT_HEADERS32)(new_image_buffer + new_dos_header->e_lfanew);
    PIMAGE_SECTION_HEADER new_section_header = (PIMAGE_SECTION_HEADER)((char*)new_nt_header + sizeof(IMAGE_NT_HEADERS32));

    // dst expand section header
    PIMAGE_SECTION_HEADER new_add_section_header = &new_section_header[dwIdx];

    uint32_t fix_rva = new_add_section_header->VirtualAddress + new_add_section_header->Misc.VirtualSize;
    uint32_t fix_foa = new_add_section_header->PointerToRawData + new_add_section_header->SizeOfRawData;

    // fix headers
    new_nt_header->OptionalHeader.AddressOfEntryPoint += (new_nt_header->OptionalHeader.AddressOfEntryPoint >= fix_rva ? new_rva_size : 0);
    new_nt_header->OptionalHeader.BaseOfCode += (new_nt_header->OptionalHeader.BaseOfCode >= fix_rva ? new_rva_size : 0);
    new_nt_header->OptionalHeader.BaseOfData += (new_nt_header->OptionalHeader.BaseOfData >= fix_rva ? new_rva_size : 0);
    new_nt_header->OptionalHeader.SizeOfImage += (new_nt_header->OptionalHeader.SizeOfImage >= fix_rva ? new_rva_size : 0);
    new_add_section_header->Misc.VirtualSize += new_rva_size;
    new_add_section_header->SizeOfRawData += new_foa_size;

    if(pExtendStartRva != NULL)
        *pExtendStartRva = new_add_section_header->VirtualAddress + old_section_header[dwIdx].Misc.VirtualSize;

    // fix other section headers
    for(int i = dwIdx + 1; i < new_nt_header->FileHeader.NumberOfSections; i++)
    {
        PIMAGE_SECTION_HEADER curr_section_header = new_section_header + i;  
        curr_section_header->VirtualAddress += (curr_section_header->VirtualAddress > 0
            ? new_rva_size : 0);  
        curr_section_header->PointerToRawData += (curr_section_header->PointerToRawData > 0
            ? new_foa_size : 0);    
    }

    printf("[+]expand: fix all headers success\r\n");

    // fix all data directories
    for(int i = 0; i < 15; i++)
    {
        if(new_nt_header->OptionalHeader.DataDirectory[i].VirtualAddress)
        {
            new_nt_header->OptionalHeader.DataDirectory[i].VirtualAddress += (
            new_nt_header->OptionalHeader.DataDirectory[i].VirtualAddress >= fix_rva
            ? new_rva_size : 0);
        }
    }
    printf("[+]expand: fix all directories success\r\n");

    // copy section datas
    for (int i = 0; i < new_nt_header->FileHeader.NumberOfSections; i++)
     {
         PIMAGE_SECTION_HEADER dst_section_header = new_section_header + i;
         PIMAGE_SECTION_HEADER src_section_header = old_section_header + i;
         SIZE_T sCopySize = src_section_header->SizeOfRawData < src_section_header->Misc.VirtualSize ? src_section_header->SizeOfRawData : src_section_header->Misc.VirtualSize;
         memcpy( dst_section_header->VirtualAddress + new_image_buffer, src_section_header->VirtualAddress + pOldImageBuffer, sCopySize);
     }

    // export table
    if ( new_nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress )
    {
        PIMAGE_EXPORT_DIRECTORY pNewExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(new_image_buffer + new_nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
        
        pNewExportDirectory->AddressOfFunctions += (
            pNewExportDirectory->AddressOfFunctions >= fix_rva
            ? new_rva_size : 0);

        pNewExportDirectory->AddressOfNameOrdinals += (
            pNewExportDirectory->AddressOfNameOrdinals >= fix_rva
            ? new_rva_size : 0);

        pNewExportDirectory->AddressOfNames += (
            pNewExportDirectory->AddressOfNames >= fix_rva
            ? new_rva_size : 0);

        pNewExportDirectory->Base += (
            pNewExportDirectory->Base >= fix_rva
            ? new_rva_size : 0);

        uint32_t pNames = (uint32_t)( (size_t)new_image_buffer + pNewExportDirectory->AddressOfNames);

        for ( int i = 0; i < pNewExportDirectory->NumberOfNames; i++)
        {
            pNames += (pNames >= fix_rva ? new_rva_size : 0);
        }

        uint32_t pFuntions = (uint32_t)( (size_t)new_image_buffer + pNewExportDirectory->AddressOfFunctions);
        for ( int i = 0; i < pNewExportDirectory->NumberOfFunctions; i++)
        {
            pFuntions += (pFuntions >= fix_rva ? new_rva_size : 0);
        }
        printf("[+]expand: fix export table success\r\n");
    }

    // fix import table
    if ( new_nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress)
    {
        PMYIMAGE_IMPORT_DESCRIPTOR pNewImpDesciptor = (PMYIMAGE_IMPORT_DESCRIPTOR)(new_image_buffer + new_nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

        while ( pNewImpDesciptor->FirstThunk)
        {
            pNewImpDesciptor->FirstThunk += (pNewImpDesciptor->FirstThunk >= fix_rva
                ? new_rva_size : 0);
            pNewImpDesciptor->Name += (pNewImpDesciptor->Name >= fix_rva
                ? new_rva_size : 0);
            pNewImpDesciptor->OriginalFirstThunk += (pNewImpDesciptor->OriginalFirstThunk >= fix_rva
                ? new_rva_size : 0);

            // 因为在文件状态OtiginalThunk跟FirstThunk指向的是同一个结构，所以只需要修复一次就好了
            PIMAGE_THUNK_DATA pOriginalThunk = (PIMAGE_THUNK_DATA)(new_image_buffer + pNewImpDesciptor->OriginalFirstThunk);
            while ( pOriginalThunk->u1.Function)
            {
                pOriginalThunk->u1.AddressOfData += pOriginalThunk->u1.AddressOfData >= fix_rva
                    ? new_rva_size : 0;
                pOriginalThunk++;
            }

            pNewImpDesciptor++;
        }
        printf("[+]expand: fix import table success\r\n");
    }

    // fix relocation table
    if(new_nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress)
    {
        int iCount = 0;
        PIMAGE_BASE_RELOCATION pBaseRelocal = (PIMAGE_BASE_RELOCATION)( new_image_buffer + new_nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        while ( pBaseRelocal->VirtualAddress && pBaseRelocal->SizeOfBlock)
        {
            typedef struct  
            {
                unsigned short Offset:12;
                unsigned short Type:4;
            }WORD_RELOCAL, *PWORD_RELOCAL;
            if ( pBaseRelocal->VirtualAddress >= fix_rva)
            {
                pBaseRelocal->VirtualAddress += new_rva_size;
            }

            PWORD_RELOCAL pRelocalWord = (PWORD_RELOCAL)((char*)pBaseRelocal + sizeof(IMAGE_BASE_RELOCATION));
            DWORD dwBlockSize = (pBaseRelocal->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD_RELOCAL);

            for ( int i = 0; i < dwBlockSize && pRelocalWord->Type == 0x3; i++)
            {
                char* reloc_addr = new_image_buffer + pBaseRelocal->VirtualAddress + pRelocalWord->Offset;
                ULONG_PTR cmp_rva = (*(ULONG_PTR*)reloc_addr) - new_nt_header->OptionalHeader.ImageBase;
                if(cmp_rva >= fix_rva)
                {
                    iCount++;
                    *(ULONG_PTR*)(reloc_addr) += new_rva_size;   
                }
                pRelocalWord++;
            }
            pBaseRelocal = (PIMAGE_BASE_RELOCATION)( (char*)pBaseRelocal + pBaseRelocal->SizeOfBlock);
        }
        printf("[+]expand: fix reloc table success, total fix: %d\r\n", iCount);
    }
    

    // fix debug table -- debug symbols
    if (new_nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress)
    {
        int nCount = new_nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size / sizeof(IMAGE_DEBUG_DIRECTORY);
        PIMAGE_DEBUG_DIRECTORY pDbgDir = (PIMAGE_DEBUG_DIRECTORY)(new_image_buffer + new_nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress);
        while ( nCount--)
        {
            pDbgDir->AddressOfRawData += pDbgDir->AddressOfRawData >= fix_rva ? new_rva_size : 0;
            pDbgDir->PointerToRawData += pDbgDir->PointerToRawData >= fix_foa ? new_foa_size : 0;
        }
        printf("[-]todo: fix debug table \r\n");
    }

    // fix TLS
    if(new_nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress)
    {
        PIMAGE_TLS_DIRECTORY pTlsDir = (PIMAGE_TLS_DIRECTORY)(new_image_buffer + new_nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
        uint32_t* tmp_pCallBacks = (uint32_t*)( new_image_buffer + pTlsDir->AddressOfCallBacks);
        uint32_t* pCallBacks = (uint32_t*)((char*)tmp_pCallBacks - old_nt_header->OptionalHeader.ImageBase);
        for ( int i = 0; *(pCallBacks++); i++)
        {
            *pCallBacks += (*pCallBacks >= fix_rva + new_nt_header->OptionalHeader.ImageBase ? new_rva_size : 0);
        }
        printf("[+]expand: fix tls table success\r\n");
    }
    

    // fix delay import table
    if ( new_nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress )
    {
        PIMAGE_DELAY_IMPORT_DESCRIPTOR pDelayDes = (PIMAGE_DELAY_IMPORT_DESCRIPTOR)( new_image_buffer + new_nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress);
        int iTheBreakVA = fix_rva + new_nt_header->OptionalHeader.ImageBase;
        int nCount = new_nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size / sizeof(IMAGE_DELAY_IMPORT_DESCRIPTOR);
        while ( nCount--)
        {
            pDelayDes[nCount].BoundIAT += pDelayDes[nCount].BoundIAT >= iTheBreakVA ? new_rva_size : 0;
            pDelayDes[nCount].DLLName += pDelayDes[nCount].DLLName >= iTheBreakVA ? new_rva_size : 0;
            pDelayDes[nCount].Hmod += pDelayDes[nCount].Hmod >= iTheBreakVA ? new_rva_size : 0;
            pDelayDes[nCount].IAT += pDelayDes[nCount].IAT >= iTheBreakVA ? new_rva_size : 0;
            pDelayDes[nCount].INT += pDelayDes[nCount].INT >= iTheBreakVA ? new_rva_size : 0;
            pDelayDes[nCount].UnloadIAT += pDelayDes[nCount].UnloadIAT >= iTheBreakVA ? new_rva_size : 0;
        }
        printf("[+]expand: fix delay import table success\r\n");
    }
    

    // fix load_config -- safe seh

    // fix bound import table

    // fix com -- .net -- todo

    // fix resource table -- todo
    if (new_nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress)
    {
        uint32_t resouce_base = (uint32_t)(new_image_buffer + new_nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress);
        // 解析最顶层，类型（系统类型都是id，自定义类型都是Name）
        PIMAGE_RESOURCE_DIRECTORY first_dir = (PIMAGE_RESOURCE_DIRECTORY)resouce_base;
        uint32_t first_name_num = first_dir->NumberOfNamedEntries;
        uint32_t first_bak_name_num = first_name_num;
        uint32_t first_id_num = first_dir->NumberOfIdEntries;
        // 处理所有的自定义资源（NAME）
        PIMAGE_RESOURCE_DIRECTORY_ENTRY first_name_entry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((uint32_t)first_dir + sizeof(IMAGE_RESOURCE_DIRECTORY));
        while(first_name_num)
        {
            // 打印name，0x7FFFFF
            if(first_name_entry->NameIsString)
            {
                PIMAGE_RESOURCE_DIR_STRING_U wname = (PIMAGE_RESOURCE_DIR_STRING_U)(resouce_base + first_name_entry->NameOffset);
                printf("resource name type: %S\r\n", wname->NameString);
                printf("\r\n");
            }
            if(first_name_entry->DataIsDirectory)
            {
                // 处理第二级，名字
                PIMAGE_RESOURCE_DIRECTORY second_dir = (PIMAGE_RESOURCE_DIRECTORY)(resouce_base + first_name_entry->OffsetToDirectory);
                uint32_t second_name_num = second_dir->NumberOfNamedEntries;
                uint32_t second_bak_name_num = second_name_num;
                uint32_t second_id_num = second_dir->NumberOfIdEntries;

                PIMAGE_RESOURCE_DIRECTORY_ENTRY second_name_entry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((uint32_t)second_dir + sizeof(IMAGE_RESOURCE_DIRECTORY));

                while(second_name_num)
                {
                    // 这个为name的很少见
                    
                    second_name_entry++;
                    second_name_num--;
                }

                PIMAGE_RESOURCE_DIRECTORY_ENTRY second_id_entry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((uint32_t)second_dir + sizeof(IMAGE_RESOURCE_DIRECTORY) + second_bak_name_num * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY));

                while(second_id_num)
                {
                    // printf("resource name: %d\r\n", second_id_entry->Id);
                    if(second_id_entry->DataIsDirectory)
                    {
                        // 处理第三级别，语言
                        PIMAGE_RESOURCE_DIRECTORY third_dir = (PIMAGE_RESOURCE_DIRECTORY)(resouce_base + second_id_entry->OffsetToDirectory);
                        uint32_t third_name_num = third_dir->NumberOfNamedEntries;
                        uint32_t third_bak_name_num = third_name_num;
                        uint32_t third_id_num = third_dir->NumberOfIdEntries;

                        PIMAGE_RESOURCE_DIRECTORY_ENTRY third_name_entry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((uint32_t)third_dir + sizeof(IMAGE_RESOURCE_DIRECTORY));
                        while(third_name_num)
                        {
                            
                            third_name_entry++;
                            third_name_num--;
                        }

                        PIMAGE_RESOURCE_DIRECTORY_ENTRY third_id_entry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((uint32_t)third_dir + sizeof(IMAGE_RESOURCE_DIRECTORY) + third_bak_name_num * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY));
                        while(third_id_num)
                        {

                            // printf("resource language: %d\r\n", third_id_entry->Id);

                            if(!third_id_entry->DataIsDirectory)
                            {
                                PIMAGE_RESOURCE_DATA_ENTRY data = (PIMAGE_RESOURCE_DATA_ENTRY)(resouce_base + third_id_entry->OffsetToData);
                                data->OffsetToData += (data->OffsetToData > fix_rva ? new_rva_size : 0);
                                // printf("data rva: %x, size: %x\r\n", data->OffsetToData, data->Size);
                            }
                            // 是目录就出错了

                            third_id_entry++;
                            third_id_num--;
                        }
                    }
                    // 其他就出错
                    second_id_entry++;
                    second_id_num--;
                }
                second_name_entry++;
                second_id_entry++;
            }
            first_name_entry++;
            first_name_num--;
        }
        // 处理所有系统资源（ID）
        PIMAGE_RESOURCE_DIRECTORY_ENTRY first_id_entry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((uint32_t)first_dir + sizeof(IMAGE_RESOURCE_DIRECTORY) + first_bak_name_num * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY));
        while(first_id_num)
        {
            // printf("resource id type: %d\r\n", first_id_entry->Id);

            if(first_id_entry->DataIsDirectory)
            {
                // 处理第二级，名字
                PIMAGE_RESOURCE_DIRECTORY second_dir = (PIMAGE_RESOURCE_DIRECTORY)(resouce_base + first_id_entry->OffsetToDirectory);
                uint32_t second_name_num = second_dir->NumberOfNamedEntries;
                uint32_t second_bak_name_num = second_name_num;
                uint32_t second_id_num = second_dir->NumberOfIdEntries;

                PIMAGE_RESOURCE_DIRECTORY_ENTRY second_name_entry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((uint32_t)second_dir + sizeof(IMAGE_RESOURCE_DIRECTORY));
                
                while(second_name_num)
                {


                    second_name_entry++;
                    second_name_num--;
                }

                PIMAGE_RESOURCE_DIRECTORY_ENTRY second_id_entry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((uint32_t)second_dir + sizeof(IMAGE_RESOURCE_DIRECTORY) + second_bak_name_num * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY));
                while(second_id_num)
                {

                    // printf("resource name: %d\r\n", second_id_entry->Id);
                    if(second_id_entry->DataIsDirectory)
                    {
                        // 处理第三级别，语言
                        PIMAGE_RESOURCE_DIRECTORY third_dir = (PIMAGE_RESOURCE_DIRECTORY)(resouce_base + second_id_entry->OffsetToDirectory);
                        uint32_t third_name_num = third_dir->NumberOfNamedEntries;
                        uint32_t third_bak_name_num = third_name_num;
                        uint32_t third_id_num = third_dir->NumberOfIdEntries;

                        PIMAGE_RESOURCE_DIRECTORY_ENTRY third_name_entry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((uint32_t)third_dir + sizeof(IMAGE_RESOURCE_DIRECTORY));
                        while(third_name_num)
                        {
                            
                            third_name_entry++;
                            third_name_num--;
                        }

                        PIMAGE_RESOURCE_DIRECTORY_ENTRY third_id_entry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((uint32_t)third_dir + sizeof(IMAGE_RESOURCE_DIRECTORY) + third_bak_name_num * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY));
                        while(third_id_num)
                        {

                            // printf("resource language: %d\r\n", third_id_entry->Id);

                            if(!third_id_entry->DataIsDirectory)
                            {
                                PIMAGE_RESOURCE_DATA_ENTRY data = (PIMAGE_RESOURCE_DATA_ENTRY)(resouce_base + third_id_entry->OffsetToData);
                                data->OffsetToData += (data->OffsetToData > fix_rva ? new_rva_size : 0);
                                // printf("data rva: %x, size: %x\r\n", data->OffsetToData, data->Size);
                            }
                            // 是目录就出错了

                            third_id_entry++;
                            third_id_num--;
                        }

                    }

                    second_id_entry++;
                    second_id_num--;
                }
            
            }

            first_id_entry++;
            first_id_num--;
        }
        printf("[+]expand: fix resource table success, todo\r\n");
    }

    // fix exception table(only x64)


    return new_image_buffer;
}