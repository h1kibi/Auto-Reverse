/* XOR repeating key: 4-byte key */
#include <stdio.h>
#include <string.h>
int main() {
    char in[32]; scanf("%31s", in);
    char key[] = {0x37, 0x52, 0x19, 0x04};
    char expected[] = {0x56,0x32,0x75,0x61,0x57,0x21,0x7c,0x6d,0x43,0x23,0x7d,0x71};
    if (strlen(in) != 12) { printf("Wrong!\n"); return 1; }
    for (int i = 0; i < 12; i++)
        if ((in[i] ^ key[i%4]) != expected[i]) { printf("Wrong!\n"); return 1; }
    printf("Correct!\n"); return 0;
}
