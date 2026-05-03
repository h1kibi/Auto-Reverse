#include <stdio.h>
#include <string.h>

unsigned char enc[] = {81,91,86,80,76,86,66,67,88,104,69,82,65,82,69,68,82,104,88,92,74};

int check(char *input) {
    if (strlen(input) != 21) return 0;
    for (int i = 0; i < 21; i++) {
        if ((input[i] ^ 0x37) != enc[i]) return 0;
    }
    return 1;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        puts("wrong");
        return 1;
    }
    if (check(argv[1])) {
        puts("correct");
        return 0;
    }
    puts("wrong");
    return 1;
}
