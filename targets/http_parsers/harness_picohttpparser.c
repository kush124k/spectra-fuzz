/*
 * AFL++ harness for picohttpparser — a fast HTTP/1.x parser.
 *
 * Reads raw bytes from a file (@@), parses them as an HTTP request,
 * and prints parsed fields to stdout for differential comparison
 * with the llhttp harness.
 *
 * Build:
 *   afl-clang-fast -fsanitize=address,undefined -g -O1 \
 *     harness_picohttpparser.c picohttpparser.c \
 *     -o harness_picohttpparser
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "picohttpparser.h"

#define MAX_HEADERS 100

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return 1;
    }

    /* Read input file */
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        fprintf(stderr, "Cannot open: %s\n", argv[1]);
        return 1;
    }

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (fsize <= 0 || fsize > 65536) {
        fclose(f);
        return 1;
    }

    char *buf = (char *)malloc(fsize + 1);
    if (!buf) { fclose(f); return 1; }
    fread(buf, 1, fsize, f);
    buf[fsize] = '\0';
    fclose(f);

    /* Parse HTTP request */
    const char *method;
    size_t method_len;
    const char *path;
    size_t path_len;
    int minor_version;
    struct phr_header headers[MAX_HEADERS];
    size_t num_headers = MAX_HEADERS;

    int pret = phr_parse_request(
        buf, fsize,
        &method, &method_len,
        &path, &path_len,
        &minor_version,
        headers, &num_headers,
        0  /* last_len = 0 for non-incremental parse */
    );

    /* Output parsed fields (matching llhttp output format) */
    printf("PARSER: picohttpparser\n");

    if (pret > 0) {
        printf("STATUS: OK\n");

        /* Method */
        printf("METHOD: %.*s\n", (int)method_len, method);

        /* URL/Path */
        printf("URL: %.*s\n", (int)path_len, path);

        /* HTTP version */
        printf("HTTP_VERSION: 1.%d\n", minor_version);

        /* Headers */
        printf("HEADER_COUNT: %zu\n", num_headers);
        printf("HEADERS:\n");
        for (size_t i = 0; i < num_headers; i++) {
            printf("%.*s: %.*s\n",
                   (int)headers[i].name_len, headers[i].name,
                   (int)headers[i].value_len, headers[i].value);
        }

        /* Body: picohttpparser doesn't parse the body, so report what's left */
        size_t body_offset = (size_t)pret;
        size_t body_len = fsize > body_offset ? fsize - body_offset : 0;
        printf("BODY_LENGTH: %zu\n", body_len);
        printf("MESSAGE_COMPLETE: %d\n", body_len > 0 ? 1 : 0);

    } else if (pret == -1) {
        printf("STATUS: ERROR\n");
        printf("METHOD: \n");
        printf("URL: \n");
        printf("HTTP_VERSION: 0.0\n");
        printf("HEADER_COUNT: 0\n");
        printf("HEADERS:\n");
        printf("BODY_LENGTH: 0\n");
        printf("MESSAGE_COMPLETE: 0\n");
    } else {
        /* pret == -2: incomplete request */
        printf("STATUS: INCOMPLETE\n");
        printf("METHOD: \n");
        printf("URL: \n");
        printf("HTTP_VERSION: 0.0\n");
        printf("HEADER_COUNT: 0\n");
        printf("HEADERS:\n");
        printf("BODY_LENGTH: 0\n");
        printf("MESSAGE_COMPLETE: 0\n");
    }

    free(buf);
    return pret > 0 ? 0 : 1;
}
