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

static bool StringReplace(std::string& source, const std::string& delimiters, const std::string& dispose = "", const std::size_t offset = 1)
{
    if (source.empty())
    {
        return false;
    }
 
    if (delimiters.empty())
    {
        return true;
    }
 
    for (std::string::size_type pos = source.find(delimiters); pos != std::string::npos; pos = source.find(delimiters))
    {
        if (source.replace(pos, offset, dispose).size())
        {
            continue;
        }
        return false;
    }
 
    return true;
}
 
static bool Hexadec2xdigit(const std::string& data, std::string& buffer, std::size_t offset)
{
    if (data.empty())
    {
        return false;
    }
 
    for (std::size_t i = 0; i < data.size(); i += offset)
    {
        if (std::isxdigit(data[i]))
        {
            buffer += static_cast<char>(std::stoul(data.substr(i, offset), nullptr, 16));
        }
        else
        {
            buffer += 'X';
        }
    }
 
    return true;
}
 
static bool Hexadec2xdigitEx(const std::string& data, std::string& buffer, unsigned int checkxdigit = 0, unsigned int transform = 1)
{
    if (data.empty())
    {
        return false;
    }
 
    std::string masks(data);
    {
        // 去掉 0x 去掉 空格
        if (StringReplace(masks, "0x") && StringReplace(masks, " "))
        {
            // 大小写转换
            if (masks.end() == (1 == transform ? std::transform(masks.begin(), masks.end(), masks.begin(), [] (unsigned char ch) { return toupper(ch); }) : std::transform(masks.begin(), masks.end(), masks.begin(), [] (unsigned char ch) { return tolower(ch); })))
            {
                // 检查是否是完整的十六进制数
                if (checkxdigit)
                {
                    if (std::string::npos != masks.find_first_not_of(charhexset))
                    {
                        return false;
                    }
                }
 
                return Hexadec2xdigit(static_cast<const std::string&>(masks), buffer, 2);
            }
        }
    }
 
    return false;
}
 
static bool SearchPattern(const unsigned char* pos, const std::string& chars)
{
    for (std::string::const_iterator xdigit = chars.cbegin(); xdigit != chars.cend(); ++xdigit, ++pos)
    {
        if (*pos != static_cast<const unsigned char>(*xdigit) &&     // no match
            'X' != static_cast<const unsigned char>(*xdigit))        // filter out arbitrary characters
        {
            return false;
        }
        else
        {
            // hit character
            continue;
        }
    }
 
    return true;
}
 
bool SearchCode(const void* start,                    // start address
                          const void* end,                      // end address
                          const std::string& keyword,           // characteristic code
                          std::size_t index,                    // take out the serial number
                          void*& address)                       // return to address
{
    if (keyword.empty())
    {
        return false;
    }
 
    if (start != end && static_cast<const unsigned char*>(end) > static_cast<const unsigned char*>(start) && static_cast<std::size_t>(static_cast<const unsigned char*>(end) - static_cast<const unsigned char*>(start)) > keyword.size())
    {
        std::string chars;
        {
            if (Hexadec2xdigitEx(keyword, chars, 0))
            {
                for (auto [pos, i] = std::make_tuple(static_cast<const unsigned char*>(start), static_cast<std::size_t>(0)); pos <= end; ++pos)
                {
                    if (SearchPattern(pos, chars))
                    {
                        if (++i != index)
                        {
                            continue;
                        }
                        else
                        {
                            address = const_cast<void*>(reinterpret_cast<const void*>(pos));
                        }
 
                        return true;
                    }
                }
            }
        }
    }
 
    return false;
}