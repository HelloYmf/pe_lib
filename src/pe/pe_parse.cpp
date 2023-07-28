#include "pe.h"
#include <cstdio>
#include <pe_parser.h>

#include <stdlib.h>
#include <Windows.h>
#include <winnt.h>

static void mem_error(void)
{
  perror("pe_parser: memory allocation error.");
  exit(EXIT_FAILURE);
}

pe_t *pe_parse_headers(FILE *executable)
{
    long int last_position;
    pe_coff_header_t *coff_header;

    if (!executable)
    {
        return NULL;
    }

    long old_pos = ftell(executable);
    fseek(executable, 0, SEEK_END);
    size_t file_size = ftell(executable);
    rewind(executable);
    char* tmp_file_buffer = (char*)malloc(file_size);
    if(!tmp_file_buffer)
    {
        return NULL;
    }
    fread(tmp_file_buffer, 1, file_size, executable);
    fseek(executable, old_pos, SEEK_SET);


    coff_header = (pe_coff_header_t*)malloc(sizeof(pe_coff_header_t));
    if (!coff_header)
    {
        mem_error();
    }

    if (!fread(coff_header, sizeof(pe_coff_header_t), 1, executable))
    {
        free(coff_header);
        return NULL;
    }

    pe_t *pe = (pe_t*)malloc(sizeof *pe + coff_header->number_of_sections * sizeof(pe_section_header_t *));
    pe->pe_file_buffer = tmp_file_buffer;

    if (!pe)
    {
        mem_error();
    }

    pe->coff_header = coff_header;
    pe->number_of_sections = coff_header->number_of_sections;

    // Checking the magic number to determinate the correct optional header struct size
    last_position = ftell(executable);
    if (!fread(&pe->type, sizeof pe->type, 1, executable))
    {
        goto free_and_return_null;
    }

    fseek(executable, last_position, SEEK_SET);
    size_t size;

    switch (pe->type)
    {
        case MAGIC_32BIT:
            size = sizeof(pe32_optional_header_t);
            break;
        case MAGIC_64BIT:
            size = sizeof(pe64_optional_header_t);
            break;
        default:
            goto free_and_return_null;
    }

    pe->optional_header = malloc(size);
    if (!pe->optional_header)
    {
        mem_error();
    }

    if (!fread(pe->optional_header, size, 1, executable))
    {
        free(pe->optional_header);
        goto free_and_return_null;
    }

    for (int i = 0; i < coff_header->number_of_sections; i++)
    {
        pe->section_header[i] = (struct pe_section_header *)malloc(sizeof(pe_section_header_t));
        if (!pe->section_header[i])
        {
            mem_error();
        }

    if (!fread(pe->section_header[i], sizeof(pe_section_header_t), 1, executable))
    {
        for (int n = i; n >= 0; n--)
        {
            free(pe->section_header[n]);
        }

        goto free_and_return_null;
    }
    }

    pe->file = executable;
    return pe;

free_and_return_null:
    free(coff_header);
    free(pe);
    return NULL;
}

void pe_free_headers(pe_t *pe)
{
    if (!pe)
    {
        return;
    }

    fclose(pe->file);
    free(pe->coff_header);
    free(pe->optional_header);

    for (int i = 0; i < pe->number_of_sections; i++)
    {
        free(pe->section_header[i]);
    }

    free(pe);
}

char* pe_get_image_buffer(pe_t* pe)
{
    size_t size_of_image = 0;
    switch (pe->type) 
    {
        case MAGIC_32BIT:
        {
            size_of_image = ((pe32_t*)pe)->optional_header->size_of_image;
            break;
        }
        case MAGIC_64BIT:
        {
            size_of_image = ((pe64_t*)pe)->optional_header->size_of_image;
            break;
        }
        default:
        {
            return NULL;
        }
    }

    char* base = (char*)malloc(size_of_image);
    if(!base) 
    {
        return NULL;
    }

    // copy of headers
    memcpy(base, pe->pe_file_buffer, ((pe32_t*)pe)->optional_header->size_of_headers);

    // copy of sections
    for(int i = 0; i < pe->number_of_sections; i++) 
    {
        memcpy(
            base + pe->section_header[i]->virtual_address, 
            pe->pe_file_buffer + pe->section_header[i]->pointer_to_raw_data,
            pe->section_header[i]->virtual_size
        );
    }
    return base;
}

void pe_free_buffer(char* buffer) 
{
    if(!buffer)
    {
        free(buffer);
        buffer = NULL;
    }
}

char* pe_image_buffer_to_file_buffer32(char* image_buffer, size_t* out_file_size)
{
    PIMAGE_DOS_HEADER image_dos_header = (PIMAGE_DOS_HEADER)image_buffer;
    PIMAGE_NT_HEADERS32 image_nt_headers = (PIMAGE_NT_HEADERS32)(image_buffer + image_dos_header->e_lfanew);
    PIMAGE_SECTION_HEADER image_section_header = (PIMAGE_SECTION_HEADER)((char*)image_nt_headers + sizeof(IMAGE_NT_HEADERS32));
    
    size_t file_size = image_section_header[image_nt_headers->FileHeader.NumberOfSections - 1].PointerToRawData + 
                        image_section_header[image_nt_headers->FileHeader.NumberOfSections - 1].SizeOfRawData;
    *out_file_size = file_size;

    char* file_buffer = (char*)malloc(file_size);
    if(!file_buffer) 
    {
        return NULL;
    }
    memset(file_buffer, 0, file_size);

    // copy file headers
    memcpy(file_buffer, image_buffer, image_nt_headers->OptionalHeader.SizeOfHeaders);

    // copy section datas
    for(int i = 0; i < image_nt_headers->FileHeader.NumberOfSections; i++) 
    {
        memcpy(
            file_buffer + image_section_header[i].PointerToRawData, 
            image_buffer + image_section_header[i].VirtualAddress,
            image_section_header[i].SizeOfRawData
        );
    }

    return file_buffer;
}