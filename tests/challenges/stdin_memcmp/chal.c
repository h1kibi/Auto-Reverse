/* STDIN memcmp Challenge - reads flag from stdin and compares */
#include <stdio.h>
#include <string.h>

int main() {
    char input[64] = {0};
    printf("Enter flag: ");
    fgets(input, sizeof(input), stdin);
    input[strcspn(input, "\n")] = 0;

    const char* expected = "flag{stdin_memcmp_test}";

    if (memcmp(input, expected, strlen(expected)) == 0) {
        printf("Correct! You got it!\n");
        return 0;
    } else {
        printf("Wrong answer!\n");
        return 1;
    }
}
