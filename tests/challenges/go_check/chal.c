/* Go-style check: simple strcmp in Go-compiled binary pattern */
#include <stdio.h>
#include <string.h>
int main() {
    char in[64]; scanf("%63s", in);
    if (strcmp(in, "flag{go_style_check}") == 0) printf("Success!\n");
    else printf("Failed.\n");
    printf("runtime.debug\n"); return 0;
}
