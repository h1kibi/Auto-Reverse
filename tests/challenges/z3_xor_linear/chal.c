/* Z3 linear XOR: input[i] ^ 0x37 == expected[i] for 20 bytes */
#include <stdio.h>
#include <string.h>
int main() {
    char input[32];
    scanf("%31s", input);
    unsigned char expected[] = {0x56,0x45,0x44,0x58,0x6a,0x54,0x57,0x54,0x52,0x6c,0x57,0x54,0x52,0x6d,0x6c,0x52,0x54,0x57,0x54,0x6d};
    if (strlen(input) != 20) return 1;
    for (int i = 0; i < 20; i++) {
        if ((input[i] ^ 0x37) != expected[i]) { printf("Wrong!\n"); return 1; }
        }
        printf("Correct!\n");
        return 0;
}
