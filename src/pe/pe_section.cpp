#include "pe.h"
#include <cstdint>
#include <pe_parser.h>

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