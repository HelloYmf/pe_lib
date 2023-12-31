#include <corecrt.h>
#define CATCH_CONFIG_MAIN
#include "catch.hpp"
#include <stdio.h>

#include <pe_parser.h>
#include <utils.h>


// TEST_CASE("test_pe_header") {

//     FILE* fpe32 = pe_open("../../tests/examples/pe_header_32.exe");
//     REQUIRE(fpe32 != NULL);
//     pe32_t* ppe32 = (pe32_t*)pe_parse_headers(fpe32);
//     REQUIRE(ppe32->coff_header->number_of_sections == 9);
//     REQUIRE(ppe32->optional_header->entry_point == 0x11023);
//     REQUIRE(ppe32->optional_header->image_base == 0x400000);
//     REQUIRE(ppe32->optional_header->subsystem == WINDOWS_CUI);
//     REQUIRE(strcmp(ppe32->section_header[0]->name, ".textbss") == 0);
//     REQUIRE(ppe32->section_header[1]->virtual_size == 0x7430);
    
//     FILE* fpe64 = pe_open("../../tests/examples/pe_header_64.exe");
//     REQUIRE(fpe64 != NULL);
//     pe64_t* ppe64 = (pe64_t*)pe_parse_headers(fpe64);
//     REQUIRE(ppe64->coff_header->number_of_sections == 6);
//     REQUIRE(ppe64->optional_header->entry_point == 0x1AF0);
//     REQUIRE(ppe64->optional_header->image_base == 0x140000000);
//     REQUIRE(ppe64->optional_header->subsystem == WINDOWS_CUI);
//     REQUIRE(strcmp(ppe64->section_header[0]->name, ".text") == 0);
//     REQUIRE(ppe64->section_header[1]->virtual_size == 0x18AA);

//     pe_free_headers((pe_t*)ppe32);
//     ppe32= NULL;
//     pe_free_headers((pe_t*)ppe64);
//     ppe64= NULL;
// }

// TEST_CASE("test_export_table") {

//     FILE* fpe64 = pe_open("D:/code/my_github/pe_lib/tests/examples/kernel32_86.dll");
//     REQUIRE(fpe64 != NULL);
//     pe64_t* ppe64 = (pe64_t*)pe_parse_headers(fpe64);
//     char* pimage_buffer = pe_get_image_buffer((pe_t*)ppe64);

//     // 普通名字导出表
//     char* fun1 = (char*)(pe_get_export_func(pimage_buffer, str_hash((char*)"BackupRead")));
//     REQUIRE(*(char*)fun1 == *(char*)BackupRead);
//     REQUIRE(*((char*)fun1+1) == *((char*)BackupRead+1));

//     // 转发导出表
//     char* fun2 = (char*)(pe_get_export_func(pimage_buffer, str_hash((char*)"AddVectoredExceptionHandler")));
//     REQUIRE(*(char*)fun2 == *(char*)AddVectoredExceptionHandler);
//     REQUIRE(*((char*)fun2+1) == *((char*)AddVectoredExceptionHandler+1));

//     // 找不到目标函数
//     char* fun3 = (char*)(pe_get_export_func(pimage_buffer, str_hash((char*)"test")));
//     REQUIRE(fun3 == 0);
// }

TEST_CASE("test_add_import_table") {
    FILE* fpe64 = pe_open("D:/code/my_github/pe_lib/tests/examples/kernel32_86.dll");
    REQUIRE(fpe64 != NULL);
    pe64_t* ppe64 = (pe64_t*)pe_parse_headers(fpe64);
    char* pimage_buffer = pe_get_image_buffer(ppe64->pe_file_buffer);

    // 普通名字导出表
    std::vector<std::string> pFunNames = {"hello", "world"};
    REQUIRE(pe_add_import_entry(pimage_buffer, (PCHAR)"USER32.dll", pFunNames) != NULL);
}

// TEST_CASE("test_sections") {

//     FILE* fpe32 = pe_open("../../tests/examples/pe_header_32.exe");
//     REQUIRE(fpe32 != NULL);
//     pe32_t* ppe32 = (pe32_t*)pe_parse_headers(fpe32);
//     size_t null_size = pe_get_section_null_size((pe_t*)ppe32, ".text");
//     REQUIRE(null_size == 3024);
// }

// TEST_CASE("test_expand_text") {
//     FILE* fpe32 = pe_open("../../tests/examples/expand_text_tls32.exe");
//     REQUIRE(fpe32 != NULL);
//     pe32_t* ppe32 = (pe32_t*)pe_parse_headers(fpe32);
//     char* image_buffer = pe_extend_section32(ppe32, 1, 0x1000);
//     spdlog::info("expand success.");
//     size_t filesize = 0;
//     char* file_buffer = pe_image_buffer_to_file_buffer32(image_buffer, &filesize);
//     REQUIRE(pe_write("expanded_text.exe", file_buffer, filesize) == true);
//     REQUIRE(remove("expanded_text.exe") == 0);
// }

TEST_CASE("test_get_section_idx_by_name")
{
    FILE* fpe32 = pe_open("../../tests/examples/expand_text_tls32.exe");
    REQUIRE(fpe32 != NULL);
    pe32_t* ppe32 = (pe32_t*)pe_parse_headers(fpe32);
    DWORD idx = pe_get_section_idx32(ppe32->pe_file_buffer, (PCHAR)".text");
    REQUIRE(idx == 1);
    pe_free_buffer(ppe32->pe_file_buffer);
}

TEST_CASE("test_search_golang_runtime")
{
    FILE* fpe32 = pe_open("../../tests/examples/search_go_runtime_32.exe");
    REQUIRE(fpe32 != NULL);
    pe32_t* ppe32 = (pe32_t*)pe_parse_headers(fpe32);
    char* pImageBuffer = pe_get_image_buffer(ppe32->pe_file_buffer);
    DWORD dwIdx = pe_get_section_idx32(pImageBuffer, (PCHAR)".text");
    DWORD textRVA = pe_get_section_rva32(pImageBuffer, dwIdx);
    std::string keyword("83 EC ?? 90 8D 05 ?? ?? ?? ?? 89 04 24 E8 ?? ?? ?? ?? 8D 05 ?? ?? ?? ?? 89 04 24 C7 44 24 04 01 00 00 00 E8 ?? ?? ?? ?? 8B 05 ?? ?? ?? ?? 89 04 24 8B 44 24 10 89 44 24 04 E8 ?? ?? ?? ?? 83 C4 ?? C3");
    void* retFind = NULL;
    bool IsFound = SearchCode(
        pImageBuffer + textRVA, 
        pImageBuffer + textRVA + ppe32->section_header[dwIdx]->virtual_size,
        keyword,
        1,
        retFind
    );
    REQUIRE(IsFound == true);
    REQUIRE((char*)retFind - pImageBuffer == 0x30360);
}