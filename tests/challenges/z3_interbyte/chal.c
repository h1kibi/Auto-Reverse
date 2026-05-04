/* Z3 interbyte: input[i] + input[j] == expected */
#include <stdio.h>
#include <string.h>
int main() {
    char in[16]; scanf("%15s", in);
    if (strlen(in) != 8) return 1;
    if (in[0] + in[4] != 200) return 1;
    if (in[1] + in[5] != 210) return 1;
    if (in[2] - in[6] != 10) return 1;
    if (in[3] ^ in[7] != 55) return 1;
    printf("OK\n"); return 0;
}
