/*
 * Standalone unit test for the AFLNet Matter parser (extract_requests_matter /
 * extract_response_codes_matter in aflnet.c). Builds on any platform (no libcap
 * / graphviz needed) so the parser logic can be validated without a full AFLNet
 * build.
 *
 * Build (from examples/fuzzers/aflnet/):
 *   cc -c -w -I. aflnet.c -o /tmp/aflnet.o
 *   cc -w -I. matter/test_matter_parser.c /tmp/aflnet.o -o /tmp/test_matter_parser
 *   /tmp/test_matter_parser matter/seeds/read_basicinfo_datamodelrev.raw
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "types.h"
#include "alloc-inl.h"
#include "aflnet.h"

static unsigned char * read_file(const char * path, unsigned int * size_out)
{
    FILE * f = fopen(path, "rb");
    if (!f) { perror("fopen"); exit(2); }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char * buf = (unsigned char *) malloc((size_t) n);
    if (fread(buf, 1, (size_t) n, f) != (size_t) n) { perror("fread"); exit(2); }
    fclose(f);
    *size_out = (unsigned int) n;
    return buf;
}

int main(int argc, char ** argv)
{
    if (argc < 2) { fprintf(stderr, "usage: %s <seed.raw> [more.raw...]\n", argv[0]); return 2; }

    int failures = 0;

    for (int a = 1; a < argc; a++) {
        unsigned int size = 0;
        unsigned char * buf = read_file(argv[a], &size);
        printf("\n=== %s (%u bytes) ===\n", argv[a], size);

        /* Requests: expect exactly one region covering the whole datagram. */
        unsigned int region_count = 0;
        region_t * regions = extract_requests_matter(buf, size, &region_count);
        printf("extract_requests_matter -> %u region(s)\n", region_count);
        for (unsigned int i = 0; i < region_count; i++) {
            printf("  region[%u]: bytes %d..%d (len %d)\n", i, regions[i].start_byte,
                   regions[i].end_byte, regions[i].end_byte - regions[i].start_byte + 1);
        }
        if (region_count != 1) {
            printf("  FAIL: expected 1 region for a single datagram\n");
            failures++;
        } else if ((unsigned int) (regions[0].end_byte + 1) != size) {
            printf("  FAIL: region does not cover whole datagram\n");
            failures++;
        } else {
            printf("  OK: single contiguous region covers the datagram\n");
        }

        /* Treat the same bytes as a response and show the derived state codes.
         * State feedback is the IM status code ONLY (never opcode/protocol). A
         * ReadRequest carries no StatusIB, so the decoder yields the no-status
         * sentinel 0x100 rather than any opcode-derived value. */
        unsigned int state_count = 0;
        unsigned int * states = extract_response_codes_matter(buf, size, &state_count);
        printf("extract_response_codes_matter -> %u state(s):", state_count);
        for (unsigned int i = 0; i < state_count; i++) printf(" 0x%04x", states[i]);
        printf("\n");
        /* state[0] is the seeded 0; state[1] is the no-status sentinel 0x100
         * (no IM status in a request) — must NOT encode the opcode/protocol. */
        if (state_count >= 2 && states[1] == 0x100) {
            printf("  OK: first parsed state 0x%04x = no-status sentinel\n", states[1]);
        } else {
            printf("  FAIL: expected first state 0x100 (no-status sentinel)\n");
            failures++;
        }

        /* regions/states are ck_realloc'd (AFLNet allocator) — release with ck_free. */
        ck_free(regions);
        ck_free(states);
        free(buf);
    }

    printf("\n%s\n", failures ? "SOME TESTS FAILED" : "ALL TESTS PASSED");
    return failures ? 1 : 0;
}
