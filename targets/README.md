# Example Fuzzing Targets

This directory contains example differential fuzzing targets for spectra-fuzz.

## HTTP Parsers (`http_parsers/`)

Two independent HTTP/1.x parser implementations:

| Target | Library | Description |
|--------|---------|-------------|
| `harness_llhttp` | [llhttp](https://github.com/nicholasbradford/llhttp) | Node.js's HTTP parser (successor to http_parser) |
| `harness_picohttpparser` | [picohttpparser](https://github.com/h2o/picohttpparser) | H2O's fast HTTP/1.x parser |

Both harnesses read raw bytes from a file, parse them as HTTP requests, and output structured fields in a consistent format for differential comparison:

```
PARSER: <name>
STATUS: OK|ERROR|INCOMPLETE
METHOD: GET|POST|...
URL: /path
HTTP_VERSION: 1.1
HEADER_COUNT: N
HEADERS:
<key>: <value>
...
BODY_LENGTH: N
MESSAGE_COMPLETE: 0|1
```

### Building

```bash
# In WSL2
cd targets/http_parsers

# Fetch picohttpparser source
make deps

# Build both with AFL++ instrumentation + ASAN
make all

# Or build individually
make harness_llhttp
make harness_picohttpparser
```

### Seeds

The `seeds/` directory contains initial HTTP request seeds covering:
- Simple GET/POST requests
- Chunked transfer encoding
- HTTP pipelining
- Complex headers (empty values, multi-value, special characters)
- OPTIONS method
- HTTP/1.0 vs HTTP/1.1

The LLM will generate additional seeds during fuzzing to target uncovered branches.

### Adding New Target Pairs

To add a new differential target pair:

1. Create harness source files that read from `argv[1]` and output structured fields to stdout
2. Ensure both harnesses use the **same output format** for the same input
3. Build with `afl-clang-fast -fsanitize=address,undefined`
4. Add seed inputs representative of the target format
5. Update `config/default.toml` with the new target paths
