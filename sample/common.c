#include "common.h"

void print_hex(char pre_str[], unsigned char bytes[], size_t len){
    printf("%s", pre_str);
    for (size_t i = 0; i < len; i++)
    {
        printf("%02x", bytes[i]);
    }
    printf("/n");
}