/*
 * AFL++ harness for llhttp — Node.js's HTTP parser.
 *
 * Reads raw bytes from a file (@@), parses them as an HTTP request,
 * and prints parsed fields to stdout for differential comparison.
 *
 * Build:
 *   afl-clang-fast -fsanitize=address,undefined -g -O1 \
 *     -I/path/to/llhttp/include harness_llhttp.c \
 *     -L/path/to/llhttp/lib -lllhttp -o harness_llhttp
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "llhttp.h"

/* Callback state for collecting parsed fields */
typedef struct {
    char method[32];
    char url[2048];
    char http_version[16];
    char headers[8192];
    size_t header_len;
    int header_count;
    char body[4096];
    size_t body_len;
    int message_complete;
} parse_state_t;

static int on_url(llhttp_t *parser, const char *at, size_t length) {
    parse_state_t *state = (parse_state_t *)parser->data;
    size_t copy_len = length < sizeof(state->url) - 1 ? length : sizeof(state->url) - 1;
    memcpy(state->url, at, copy_len);
    state->url[copy_len] = '\0';
    return 0;
}

static int on_header_field(llhttp_t *parser, const char *at, size_t length) {
    parse_state_t *state = (parse_state_t *)parser->data;
    size_t remaining = sizeof(state->headers) - state->header_len - 1;
    if (remaining > 0 && state->header_len > 0) {
        state->headers[state->header_len++] = '\n';
        remaining--;
    }
    size_t copy_len = length < remaining ? length : remaining;
    memcpy(state->headers + state->header_len, at, copy_len);
    state->header_len += copy_len;
    return 0;
}

static int on_header_value(llhttp_t *parser, const char *at, size_t length) {
    parse_state_t *state = (parse_state_t *)parser->data;
    size_t remaining = sizeof(state->headers) - state->header_len - 1;
    if (remaining > 2) {
        state->headers[state->header_len++] = ':';
        state->headers[state->header_len++] = ' ';
        remaining -= 2;
    }
    size_t copy_len = length < remaining ? length : remaining;
    memcpy(state->headers + state->header_len, at, copy_len);
    state->header_len += copy_len;
    state->header_count++;
    return 0;
}

static int on_body(llhttp_t *parser, const char *at, size_t length) {
    parse_state_t *state = (parse_state_t *)parser->data;
    size_t remaining = sizeof(state->body) - state->body_len;
    size_t copy_len = length < remaining ? length : remaining;
    memcpy(state->body + state->body_len, at, copy_len);
    state->body_len += copy_len;
    return 0;
}

static int on_message_complete(llhttp_t *parser) {
    parse_state_t *state = (parse_state_t *)parser->data;
    state->message_complete = 1;
    return 0;
}

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

    char *buf = (char *)malloc(fsize);
    if (!buf) { fclose(f); return 1; }
    fread(buf, 1, fsize, f);
    fclose(f);

    /* Initialize parser */
    llhttp_t parser;
    llhttp_settings_t settings;
    parse_state_t state;

    memset(&state, 0, sizeof(state));
    llhttp_settings_init(&settings);

    settings.on_url = on_url;
    settings.on_header_field = on_header_field;
    settings.on_header_value = on_header_value;
    settings.on_body = on_body;
    settings.on_message_complete = on_message_complete;

    llhttp_init(&parser, HTTP_REQUEST, &settings);
    parser.data = &state;

    /* Parse */
    enum llhttp_errno err = llhttp_execute(&parser, buf, fsize);

    /* Output parsed fields (for differential comparison) */
    printf("PARSER: llhttp\n");
    printf("STATUS: %s\n", err == HPE_OK ? "OK" : llhttp_errno_name(err));
    printf("METHOD: %s\n", llhttp_method_name(llhttp_get_method(&parser)));
    printf("URL: %s\n", state.url);
    printf("HTTP_VERSION: %d.%d\n", parser.http_major, parser.http_minor);
    printf("HEADER_COUNT: %d\n", state.header_count);
    state.headers[state.header_len] = '\0';
    printf("HEADERS:\n%s\n", state.headers);
    printf("BODY_LENGTH: %zu\n", state.body_len);
    printf("MESSAGE_COMPLETE: %d\n", state.message_complete);

    free(buf);
    return err == HPE_OK ? 0 : 1;
}
