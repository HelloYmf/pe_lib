#include <cstddef>
#include <utils.h>

#define HASH_KEY 13

__attribute__((always_inline)) inline uint32_t ror(uint32_t d)
{
    return (d >> HASH_KEY) | (d << (32 - HASH_KEY));
}

uint32_t str_hash(char* c)
{
    uint32_t h = 0;
    do
    {
        h = ror(h);
        h += *c;
    } while (*++c);

    return h;
}

char** split_string(char* src, char* split, size_t* real_size)
{
    int count = 1;
    char* pos = strstr(src, split);
    while (pos != NULL) {
        count++;
        pos = strstr(pos + 1, split);
    }

    *real_size = count;

    char** result = (char**)malloc((count + 1) * sizeof(char*));
    if (result == NULL) {
        return NULL;
    }

    char* token = strtok(src, split);
    int i = 0;
    while (token != NULL) {
        result[i] = (char*)malloc((strlen(token) + 1) * sizeof(char));
        if (result[i] == NULL) {
            free(result);
            return NULL;
        }
        strcpy(result[i], token);
        i++;
        token = strtok(NULL, split);
    }

    result[i] = NULL;
    return result;
}

void free_split_string(char** str)
{
    if(!str) 
    {
        for(int i = 0; str[i] != NULL; i++)
        {
            free(str[i]);
            str[i] = NULL;
        }
        free(str);
        str = NULL;
    }
}