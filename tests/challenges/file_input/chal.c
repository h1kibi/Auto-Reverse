/* File input: reads flag.txt and compares */
#include <stdio.h>
#include <string.h>
int main() {
    FILE *f = fopen("flag.txt", "r");
    if (!f) { printf("Error\n"); return 1; }
    char buf[64]; fgets(buf, 64, f); fclose(f);
    buf[strcspn(buf, "\n")] = 0;
    if (strcmp(buf, "flag{file_input_test}") == 0) printf("Correct!\n");
    else printf("Wrong!\n");
    return 0;
}
