#include <pe_parser.h>

// used to debug
int main(int argc, char* argv[])
{

    if(argc < 5)
    {
        perror("usage: %s <input> <section-index> <size> <output>\r\n");
        return -1;
    }

    printf("input file: %s\r\n", argv[1]);
    FILE* fpe32 = pe_open(argv[1]);
    if(!fpe32)
    {
         printf("open file failed\r\n");
         return -1;
    }
    pe32_t* ppe32 = (pe32_t*)pe_parse_headers(fpe32);
    printf("idx: %x, size: %x\r\n", atoi(argv[2]), atoi(argv[3]));
    char* image_buffer = pe_extend_section32(ppe32, atoi(argv[2]), atoi(argv[3]));
    printf("expand suucess.\r\n");
    size_t filesize = 0;
    char* file_buffer = pe_image_buffer_to_file_buffer32(image_buffer, &filesize);
    pe_write(argv[4], file_buffer, filesize);

    return 0;
}