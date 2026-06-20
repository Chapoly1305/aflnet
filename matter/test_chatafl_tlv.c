/*
   Standalone unit test for the ChatAFL-for-Matter TLV + catalog layer.
   Compiles WITHOUT libcurl/json-c (only chat-llm-tlv.c).

     cc -I.. -o /tmp/t test_chatafl_tlv.c ../chat-llm-tlv.c && /tmp/t
*/

#include "../chat-llm-tlv.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* The checked-in read_onoff.raw seed: read OnOff(0x06) attr 0 on EP1. */
static const unsigned char READ_ONOFF[] = {
    /* msg hdr  */ 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    /* pl  hdr  */ 0x05, 0x02, 0x03, 0x00, 0x01, 0x00,
    /* TLV      */ 0x15, 0x36, 0x00, 0x17, 0x24, 0x02, 0x01, 0x24, 0x03, 0x06,
                   0x24, 0x04, 0x00, 0x18, 0x18, 0x28, 0x03, 0x24, 0xff, 0x0c,
                   0x18,
    /* MIC (16) */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

static int failures = 0;
#define CHECK(cond, msg)                                                       \
  do {                                                                         \
    if (!(cond)) { printf("  FAIL: %s\n", msg); failures++; }                  \
    else printf("  ok:   %s\n", msg);                                          \
  } while (0)

static void test_ranges(void) {
  printf("[matter_get_mutable_ranges]\n");
  unsigned int n = 0;
  mrange_t *r = matter_get_mutable_ranges(READ_ONOFF, sizeof(READ_ONOFF), &n);
  CHECK(n == 4, "exactly 4 value-byte ranges (ep, cluster, attr, im-rev)");
  if (n == 4) {
    CHECK(r[0].start == 20 && r[0].len == 1, "endpoint value @20 len1");
    CHECK(r[1].start == 23 && r[1].len == 1, "cluster  value @23 len1");
    CHECK(r[2].start == 26 && r[2].len == 1, "attr     value @26 len1");
    CHECK(r[3].start == 33 && r[3].len == 1, "im-rev   value @33 len1");
  }
  /* Every range must lie inside the TLV body, never in headers or MIC. */
  unsigned int tlv_start = 14, tlv_end = sizeof(READ_ONOFF) - 16;
  for (unsigned int i = 0; i < n; i++)
    CHECK((unsigned)r[i].start >= tlv_start &&
              (unsigned)(r[i].start + r[i].len) <= tlv_end,
          "range within TLV body (not header/MIC)");
  free(r);
}

static void test_garbage(void) {
  printf("[matter_get_mutable_ranges on garbage]\n");
  unsigned char junk[4] = {0xff, 0xff, 0xff, 0xff};
  unsigned int n = 123;
  mrange_t *r = matter_get_mutable_ranges(junk, sizeof(junk), &n);
  CHECK(n == 0, "garbage yields zero ranges (no crash)");
  free(r);
}

static void test_catalog(void) {
  printf("[catalog build / decode]\n");
  char dir[] = "/tmp/chatafl_tlv_test_XXXXXX";
  assert(mkdtemp(dir));
  char seed[512];
  snprintf(seed, sizeof(seed), "%s/read_onoff.raw", dir);
  FILE *f = fopen(seed, "wb");
  fwrite(READ_ONOFF, 1, sizeof(READ_ONOFF), f);
  fclose(f);

  matter_catalog_t *cat = matter_catalog_build(dir);
  CHECK(matter_catalog_size(cat) == 1, "one distinct message type");
  if (cat->count == 1) {
    catalog_entry_t *e = &cat->entries[0];
    CHECK(e->opcode == 0x02, "opcode = ReadRequest (0x02)");
    CHECK(e->endpoint == 1, "endpoint = 1");
    CHECK(e->cluster_id == 6, "cluster = 6 (OnOff)");
    CHECK(e->target_id == 0, "target attr = 0");
    CHECK(strcmp(e->key, "02:1:6:0") == 0, "identity key 02:1:6:0");
  }

  printf("[clone_with_ids — synthesize a novel type]\n");
  catalog_entry_t clone =
      catalog_clone_with_ids(&cat->entries[0], 1, 0x08 /*LevelControl*/, 0);
  CHECK(clone.cluster_id == 8, "cloned cluster rewritten to 8");
  CHECK(clone.len == cat->entries[0].len, "clone preserves length (in-place)");
  CHECK(strcmp(clone.key, "02:1:8:0") == 0, "clone identity 02:1:8:0");
  int added = catalog_add_unique(cat, clone);
  CHECK(added == 1, "clone added as new type");
  CHECK(matter_catalog_size(cat) == 2, "catalog now has 2 types");

  printf("[seed_has_type]\n");
  CHECK(seed_has_type(READ_ONOFF, sizeof(READ_ONOFF), &cat->entries[0]) == 1,
        "seed contains its own type");
  CHECK(seed_has_type(READ_ONOFF, sizeof(READ_ONOFF), &cat->entries[1]) == 0,
        "seed does NOT contain the cloned type");

  printf("[write_enriched]\n");
  int w = matter_catalog_write_enriched(cat, dir);
  CHECK(w >= 1, "at least one enriched seed written");
  /* enriched seed must re-parse into >1 datagram (original + appended) */
  char enr[600];
  snprintf(enr, sizeof(enr), "%s/enriched_0_read_onoff.raw", dir);
  FILE *ef = fopen(enr, "rb");
  if (ef) {
    unsigned char buf[512];
    size_t got = fread(buf, 1, sizeof(buf), ef);
    fclose(ef);
    CHECK(got > sizeof(READ_ONOFF), "enriched seed longer than original");
    /* the appended datagram's cluster=8 type must now be present */
    CHECK(seed_has_type(buf, (unsigned)got, &cat->entries[1]) == 1,
          "enriched seed now contains the appended type");
    unsigned int en = 0;
    mrange_t *er = matter_get_mutable_ranges(buf, (unsigned)got, &en);
    CHECK(en == 8, "enriched seed has 8 value ranges (2 datagrams x 4)");
    free(er);
  } else {
    CHECK(0, "could not open enriched seed");
  }

  matter_catalog_free(cat);
  /* cleanup temp dir */
  char cmd[600];
  snprintf(cmd, sizeof(cmd), "rm -rf %s", dir);
  if (system(cmd)) { /* ignore */ }
}

/* Same read as READ_ONOFF but cluster encoded as uint16 (0x25) = 0x0300 (768),
   one byte longer. Exercises width-aware decode. */
static const unsigned char READ_C16[] = {
    0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x05, 0x02, 0x03, 0x00, 0x01, 0x00,
    0x15, 0x36, 0x00, 0x17, 0x24, 0x02, 0x01,
    0x25, 0x03, 0x00, 0x03,             /* cluster = uint16 0x0300 = 768 */
    0x24, 0x04, 0x00, 0x18, 0x18, 0x28, 0x03, 0x24, 0xff, 0x0c, 0x18,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

static void test_wide_ids(void) {
  printf("[width-aware decode — uint16 cluster]\n");
  char dir[] = "/tmp/chatafl_w_test_XXXXXX";
  assert(mkdtemp(dir));
  char seed[512];
  snprintf(seed, sizeof(seed), "%s/read_c16.raw", dir);
  FILE *f = fopen(seed, "wb");
  fwrite(READ_C16, 1, sizeof(READ_C16), f);
  fclose(f);
  matter_catalog_t *cat = matter_catalog_build(dir);
  CHECK(matter_catalog_size(cat) == 1, "one type from uint16 seed");
  if (cat->count == 1) {
    CHECK(cat->entries[0].cluster_id == 768, "uint16 cluster decoded as 768 (not truncated)");
    CHECK(cat->entries[0].endpoint == 1, "endpoint still 1");
    CHECK(cat->entries[0].target_id == 0, "attr still 0");
  }
  /* every value range must still lie in the TLV body */
  unsigned int n = 0;
  mrange_t *r = matter_get_mutable_ranges(READ_C16, sizeof(READ_C16), &n);
  CHECK(n == 4, "uint16 seed still yields 4 value ranges");
  free(r);
  matter_catalog_free(cat);
  char cmd[600]; snprintf(cmd, sizeof(cmd), "rm -rf %s", dir);
  if (system(cmd)) {}

  printf("[clone widening — uint8 cluster -> uint16/uint32]\n");
  /* Build a uint8-cluster catalog entry, then clone to a >255 cluster. */
  matter_catalog_t base = {0};
  catalog_entry_t seed_e; memset(&seed_e, 0, sizeof(seed_e));
  seed_e.bytes = malloc(sizeof(READ_ONOFF));
  memcpy(seed_e.bytes, READ_ONOFF, sizeof(READ_ONOFF));
  seed_e.len = sizeof(READ_ONOFF);
  entry_decode(&seed_e);
  catalog_add_unique(&base, seed_e);

  /* fits in uint8: in-place, no growth */
  catalog_entry_t c8 = catalog_clone_with_ids(&base.entries[0], 1, 8, 0);
  CHECK(c8.cluster_id == 8, "clone to cluster 8 decodes as 8");
  CHECK(c8.len == sizeof(READ_ONOFF), "uint8-fit clone keeps length");
  free(c8.bytes);

  /* needs uint16: widen by 1 byte */
  catalog_entry_t c16 = catalog_clone_with_ids(&base.entries[0], 1, 0x0300, 0);
  CHECK(c16.cluster_id == 768, "clone to cluster 768 decodes as 768");
  CHECK(c16.len == sizeof(READ_ONOFF) + 1, "uint16 clone grew by 1 byte");
  unsigned int wn = 0;
  mrange_t *wr = matter_get_mutable_ranges(c16.bytes, c16.len, &wn);
  CHECK(wn == 4, "widened clone re-parses to 4 value ranges (valid TLV)");
  free(wr);
  free(c16.bytes);

  /* needs uint32: widen by 3 bytes */
  catalog_entry_t c32 = catalog_clone_with_ids(&base.entries[0], 1, 0x10000, 0);
  CHECK(c32.cluster_id == 0x10000, "clone to cluster 0x10000 decodes correctly");
  CHECK(c32.len == sizeof(READ_ONOFF) + 3, "uint32 clone grew by 3 bytes");
  unsigned int wn2 = 0;
  mrange_t *wr2 = matter_get_mutable_ranges(c32.bytes, c32.len, &wn2);
  CHECK(wn2 == 4, "uint32 clone still valid TLV (4 ranges)");
  free(wr2);
  free(c32.bytes);

  /* `base` is a stack catalog — free its members directly (matter_catalog_free
     also free()s the catalog struct, which is only valid for heap catalogs). */
  free(base.entries[0].bytes);
  free(base.entries);
}

int main(void) {
  test_ranges();
  test_garbage();
  test_catalog();
  test_wide_ids();
  printf("\n%s (%d failure%s)\n", failures ? "TESTS FAILED" : "ALL TESTS PASSED",
         failures, failures == 1 ? "" : "s");
  return failures ? 1 : 0;
}
