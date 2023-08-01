#include <pe_parser.h>

// used to debug
int main()
{
    FILE* fpe32 = pe_open("xxx.exe");
    if(!fpe32)
    {
         printf("open file failed\r\n");
         return -1;
    }
    pe32_t* ppe32 = (pe32_t*)pe_parse_headers(fpe32);
    printf("parse headers suucess.\r\n");
    char* image_buffer = pe_extend_section32(ppe32, 2, 0x50000);
    printf("expand suucess.\r\n");
    size_t filesize = 0;
    char* file_buffer = pe_image_buffer_to_file_buffer32(image_buffer, &filesize);
    pe_write("xxx_expand.exe", file_buffer, filesize);

    return 0;
}