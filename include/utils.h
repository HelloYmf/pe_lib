#include <cstdint>
#include <stdlib.h>
#include <string.h>

uint32_t str_hash(char* c);

char** split_string(char* src, char* split, size_t* real_size);

void free_split_string(char** str);