/* ARGV strcmp Challenge - reads flag from argv and compares */
#include <stdio.h>
#include <string.h>

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("Usage: %s <flag>\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "flag{argv_strcmp_test}") == 0) {
        printf("Correct! You found the flag!\n");
        return 0;
    } else {
        printf("Wrong! Try again.\n");
        return 1;
    }
}
