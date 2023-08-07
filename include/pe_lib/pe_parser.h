#ifndef _PEREADER_H
#define _PEREADER_H

#include "pe.h"

#include <iostream>
#include <string>

// pe文件
FILE* pe_open(const char* filename);
bool pe_check(FILE* executable);
bool pe_write(const char* filename, char* buffer, size_t size);

// pe解析
pe_t* pe_parse_headers(FILE* executable);
void pe_free_headers(pe_t* pe);

// pe拉伸
char* pe_get_image_buffer(char* pBase);
void pe_free_buffer(char* buffer);
char* pe_image_buffer_to_file_buffer32(char* image_buffer, size_t* out_file_size);

// pe节表
DWORD pe_get_section_rva32(PCHAR pBuffer, DWORD dwIdx);
DWORD pe_get_section_idx32(PCHAR pBuffer, PCHAR pSecName);
size_t pe_get_section_null_size(pe_t* pe, const char* sec_name);
PCHAR pe_extend_section32(PCHAR pOldImageBuffer, DWORD dwIdx, DWORD dwSize, DWORD* pExtendStartRva);

// pe目录表
PVOID pe_get_export_func(PCHAR pBase, DWORD dwHash);
void pe_get_tls_callback();
PCHAR pe_add_import_entry(PCHAR pOldImageBuffer, PCHAR pDLLName, std::vector<std::string> pFunNames);

// tls
BOOL pe_insert_tls(PCHAR pImageBuffer, DWORD dwFunRva);

#endif
