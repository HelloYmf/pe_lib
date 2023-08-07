#include <cstdint>
#include <stdlib.h>
#include <string>
#include <algorithm>
#include <array>
#include <immintrin.h>
#include <cctype>

uint32_t str_hash(char* c);

char** split_string(char* src, char* split, size_t* real_size);

void free_split_string(char** str);

static constexpr char charhexset[] = "0123456789ABCDEFabcdef";

bool SearchCode(const void* start,                       // start address
                          const void* end,                      // end address
                          const std::string& keyword,           // characteristic code
                          std::size_t index,                    // take out the serial number
                          void*& address);                      // return to address