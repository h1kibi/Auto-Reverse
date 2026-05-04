/* Angr branch: correct path prints success, wrong path prints failure */
#include <stdio.h>
#include <string.h>
int main(int argc, char** argv) {
    if (argc < 2) { printf("Usage: %s <flag>\n", argv[0]); return 1; }
    if (strcmp(argv[1], "flag{angr_branch_test}") == 0) {
        printf("Congratulations! You got it!\n");
        return 0;
    } else {
        printf("Incorrect, try again.\n");
        return 1;
    }
}
