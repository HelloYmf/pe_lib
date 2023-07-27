#ifndef _PEREADER_H
#define _PEREADER_H

#include "pe.h"

// pe file op
FILE* pe_open(const char* filename);
bool pe_check(FILE* executable);
bool pe_write(const char* filename, char* buffer, size_t size);

// pe header op

pe_t* pe_parse_headers(FILE* executable);
void pe_free_headers(pe_t* pe);

char* pe_get_image_buffer(pe_t* pe);
void pe_free_buffer(char* buffer);
char* pe_image_buffer_to_file_buffer32(char* image_buffer, size_t* out_file_size);

// pe section op
size_t pe_get_section_null_size(pe_t* pe, const char* sec_name);
char* pe_extend_section32(pe32_t* pe, uint32_t idx, uint32_t size);

// pe table op
intptr_t pe_get_export_func(pe_t* pe, intptr_t base, int hash);
void pe_get_tls_callback();

#endif
