#include <pe_parser.h>

// used to debug
// int main(int argc, char* argv[])
// {

//     if(argc < 5)
//     {
//         perror("usage: %s <input> <section-index> <size> <output>\r\n");
//         return -1;
//     }

//     printf("input file: %s\r\n", argv[1]);
//     FILE* fpe32 = pe_open(argv[1]);
//     if(!fpe32)
//     {
//          printf("open file failed\r\n");
//          return -1;
//     }
//     pe32_t* ppe32 = (pe32_t*)pe_parse_headers(fpe32);
//     printf("idx: %x, size: %x\r\n", atoi(argv[2]), atoi(argv[3]));
//     char* old_image_buffer = pe_get_image_buffer(ppe32->pe_file_buffer);
//     char* image_buffer = pe_extend_section32(old_image_buffer, atoi(argv[2]), atoi(argv[3]));
//     printf("expand suucess.\r\n");
//     size_t filesize = 0;
//     char* file_buffer = pe_image_buffer_to_file_buffer32(image_buffer, &filesize);
//     pe_write(argv[4], file_buffer, filesize);

//     return 0;
// }

int main()
{
    FILE* fpe32 = pe_open("D:/code/my_github/pe_lib/build/src/input.exe");
    if(!fpe32)
    {
         printf("open file failed\r\n");
         return -1;
    }
    pe32_t* ppe32 = (pe32_t*)pe_parse_headers(fpe32);
    char* old_image_buffer = pe_get_image_buffer(ppe32->pe_file_buffer);

    std::vector<std::string> pFunNames = {"rundll"};
    char* new_image_buffer = pe_add_import_entry(old_image_buffer, (PCHAR)"DemoDll.dll", pFunNames);
    if(!new_image_buffer)
    {
        printf("add import failed\r\n");
        return -1;
    }
    
    size_t filesize = 0;
    char* file_buffer = pe_image_buffer_to_file_buffer32(new_image_buffer, &filesize);
    if(!pe_write("D:/code/my_github/pe_lib/build/src/added_out.exe", file_buffer, filesize))
    {
        printf("save file failed\r\n");
        return -1;
    }

    pe_free_buffer(ppe32->pe_file_buffer);
    pe_free_buffer(old_image_buffer);
    pe_free_buffer(new_image_buffer);

    return 0;
}