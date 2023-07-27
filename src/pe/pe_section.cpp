#include <pe.h>
#include <cstdint>
#include <pe_parser.h>
#include <stdlib.h>
#include <Windows.h>

size_t pe_get_section_null_size(pe_t* pe, const char* sec_name)
{
    int i = 0;
    for(; i < pe->number_of_sections; i++)
    {
        if(strcmp(pe->section_header[i]->name, sec_name) == 0)
            break;
    }
    if(i == pe->number_of_sections)
    {
        perror("can't find section");
        return 0;
    }
    
    uint32_t virtual_size = pe->section_header[i]->virtual_size;

    if(i == pe->number_of_sections-1)
    {
        size_t size_of_image = pe->type == MAGIC_32BIT ?  ((pe32_t*)pe)->optional_header->size_of_image : ((pe64_t*)pe)->optional_header->size_of_image;
        return size_of_image - (pe->section_header[i]->virtual_address + virtual_size);
    }

    return pe->section_header[i+1]->virtual_address - (pe->section_header[i]->virtual_address + virtual_size);
}

// 因为32位和64位对异常表支持的不一样，所以需要分别处理
char* pe_extend_section32(pe32_t* pe, uint32_t idx, uint32_t size)
{
    uint32_t new_rva_size = 0;                      // 整体后移的rva值
    uint32_t new_foa_size = 0;                      // 整体后移的foa值

    char* new_image_buffer = NULL;
    uint32_t new_image_size = 0;

    uint32_t section_align = pe->optional_header->section_alignment;
    uint32_t file_align = pe->optional_header->file_alignment;

    new_rva_size = ( (size > section_align ? (size / section_align) : 0)
            + (size % section_align != 0 ? 1 : 0) ) * section_align;
    new_rva_size += (new_rva_size == 0 ? section_align : 0);

    new_foa_size = ( (size > file_align ? (size / file_align) : 0)
            + (size % file_align != 0 ? 1 : 0) ) * file_align;
    new_foa_size += (new_foa_size == 0 ? file_align : 0);

    printf("new aligin rva: %08x, new align foa: %08x\r\n", new_rva_size, new_foa_size);

    new_image_size = pe->optional_header->size_of_image + new_rva_size;
    new_image_buffer = (char*)malloc(new_image_size);
    if(!new_image_buffer)
        return NULL;

    // get image buffer
    char* old_image_buffer = pe_get_image_buffer((pe_t*)pe);
    PIMAGE_DOS_HEADER old_dos_header = (PIMAGE_DOS_HEADER)old_image_buffer;
    PIMAGE_NT_HEADERS32 old_nt_header = (PIMAGE_NT_HEADERS32)(old_image_buffer + old_dos_header->e_lfanew);
    PIMAGE_SECTION_HEADER old_section_header = (PIMAGE_SECTION_HEADER)((char*)old_nt_header + sizeof(PIMAGE_NT_HEADERS32));

    // copy old file headers -> new image buffer
    memcpy(new_image_buffer, old_image_buffer, pe->optional_header->size_of_headers);

    // fix file headers
    PIMAGE_DOS_HEADER new_dos_header = (PIMAGE_DOS_HEADER)new_image_buffer;
    PIMAGE_NT_HEADERS32 new_nt_header = (PIMAGE_NT_HEADERS32)(new_image_buffer + new_dos_header->e_lfanew);
    PIMAGE_SECTION_HEADER new_section_header = (PIMAGE_SECTION_HEADER)((char*)new_nt_header + sizeof(PIMAGE_NT_HEADERS32));

    // 目标节区头
    PIMAGE_SECTION_HEADER new_add_section_header = new_section_header + idx;

    uint32_t fix_rva = new_add_section_header->VirtualAddress + new_add_section_header->Misc.VirtualSize;
    uint32_t fix_foa = new_add_section_header->PointerToRawData + new_add_section_header->SizeOfRawData;

    // fix basic headers
    new_nt_header->OptionalHeader.AddressOfEntryPoint += (new_nt_header->OptionalHeader.AddressOfEntryPoint >= fix_rva ? new_rva_size : 0);
    new_nt_header->OptionalHeader.BaseOfCode += (new_nt_header->OptionalHeader.BaseOfCode >= fix_rva ? new_rva_size : 0);
    new_nt_header->OptionalHeader.BaseOfData += (new_nt_header->OptionalHeader.BaseOfData >= fix_rva ? new_rva_size : 0);
    new_nt_header->OptionalHeader.SizeOfImage += (new_nt_header->OptionalHeader.SizeOfImage >= fix_rva ? new_rva_size : 0);

    // fix dst section header
    new_add_section_header->Misc.VirtualSize += new_rva_size;
    new_add_section_header->SizeOfRawData += new_foa_size;

    // fix other section headers
    for(int i = idx + 1; i < new_nt_header->FileHeader.NumberOfSections; i++)
    {
        PIMAGE_SECTION_HEADER curr_section_header = new_add_section_header + i;  
        curr_section_header->VirtualAddress += (curr_section_header->VirtualAddress > 0
            ? new_rva_size : 0);  
        curr_section_header->PointerToRawData += (curr_section_header->PointerToRawData > 0
            ? new_foa_size : 0);    
    }

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

    // copy section datas
    for (int i = 0; i < new_nt_header->FileHeader.NumberOfSections; i++)
     {
         PIMAGE_SECTION_HEADER dst_section_header = new_section_header + i;
         PIMAGE_SECTION_HEADER src_section_header = old_section_header + i;

         memcpy( dst_section_header->VirtualAddress + new_image_buffer, src_section_header->VirtualAddress + old_image_buffer, src_section_header->SizeOfRawData);
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

        uint32_t pNames = (uint32_t)( new_image_buffer + pNewExportDirectory->AddressOfNames);

        for ( int i = 0; i < pNewExportDirectory->NumberOfNames; i++)
        {
            pNames += (pNames >= fix_rva ? new_rva_size : 0);
        }

        uint32_t pFuntions = (uint32_t)( new_image_buffer + pNewExportDirectory->AddressOfFunctions);
        for ( int i = 0; i < pNewExportDirectory->NumberOfFunctions; i++)
        {
            pFuntions += (pFuntions >= fix_rva ? new_rva_size : 0);
        }
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
    }

    // fix relocation table
    if(new_nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress)
    {
        PIMAGE_BASE_RELOCATION pBaseRelocal = (PIMAGE_BASE_RELOCATION)( new_image_buffer + new_nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        int iCount = new_nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size / sizeof(IMAGE_BASE_RELOCATION);
        while ( pBaseRelocal->VirtualAddress && iCount)
        {
            typedef struct  
            {
                short Offset:12;
                short Type:4;
            }WORD_RELOCAL, *PWORD_RELOCAL;
            if ( pBaseRelocal->VirtualAddress >= fix_rva)
            {
                pBaseRelocal->VirtualAddress += new_rva_size;
                PWORD_RELOCAL pRelocalWord = (PWORD_RELOCAL)((char*)pBaseRelocal + sizeof(IMAGE_BASE_RELOCATION));
                for ( int i = 0; i < pBaseRelocal->SizeOfBlock / sizeof(WORD_RELOCAL); i++)
                {
                    *(short*)(new_image_buffer + pBaseRelocal->VirtualAddress + pRelocalWord->Offset) += (
                        pRelocalWord->Type == IMAGE_REL_BASED_HIGHLOW && pRelocalWord->Offset
                        ? new_rva_size : 0);
                }
            }
            pBaseRelocal = (PIMAGE_BASE_RELOCATION)( (char*)pBaseRelocal + pBaseRelocal->SizeOfBlock);

        }
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
    }

    // fix TLS
    if(new_nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress)
    {
        PIMAGE_TLS_DIRECTORY pTlsDir = (PIMAGE_TLS_DIRECTORY)(new_image_buffer + new_nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
        pTlsDir->AddressOfCallBacks += pTlsDir->AddressOfCallBacks >= fix_rva + new_nt_header->OptionalHeader.ImageBase ? new_rva_size : 0;
        pTlsDir->AddressOfIndex += pTlsDir->AddressOfIndex >= fix_rva + new_nt_header->OptionalHeader.ImageBase ? new_rva_size : 0;
        pTlsDir->StartAddressOfRawData += pTlsDir->StartAddressOfRawData >= fix_rva + new_nt_header->OptionalHeader.ImageBase ? new_rva_size : 0;
        pTlsDir->EndAddressOfRawData += pTlsDir->EndAddressOfRawData >= fix_rva + new_nt_header->OptionalHeader.ImageBase ? new_rva_size : 0;
        uint32_t* pCallBacks = (uint32_t*)( new_image_buffer + pTlsDir->AddressOfCallBacks);
        for ( int i = 0; *pCallBacks; i++)
        {
            *pCallBacks += (*pCallBacks >= fix_rva + new_nt_header->OptionalHeader.ImageBase ? new_rva_size : 0);
        }
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
    }

    // fix load_config -- safe seh

    // fix bound import table -- 遇到了再说

    // fix com -- .net使用的 --遇到了再说

    // fix resource table -- todo
    if (new_nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress)
    {
        PIMAGE_RESOURCE_DIRECTORY pTopResDir = (PIMAGE_RESOURCE_DIRECTORY)(new_image_buffer + new_nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress);
        // MoveTheResource( pTopResDir, pTopResDir, iTheBreakRVA, iExpandVsize);
    }

    // fix exception table(only x64)


    pe_free_buffer(old_image_buffer);
    return new_image_buffer;
}