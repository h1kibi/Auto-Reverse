/* Base64 Flag Challenge - flag is base64 encoded in strings */
#include <stdio.h>

int main() {
    const char* encoded = "ZmxhZ3tiYXNlNjRfZW5jb2RlZF9mbGFnfQ==";
    printf("Encoded hint: %s\n", encoded);
    return 0;
}
