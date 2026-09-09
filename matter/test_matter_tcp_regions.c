/* Regression: a mutated TCP length field must never produce an inverted or
   out-of-bounds region. AFLNet sizes buffers with end_byte - start_byte + 1,
   so an inverted region becomes a ~4 GB ck_alloc and abort(). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"
#include "types.h"
#include "alloc-inl.h"
#include "aflnet.h"

static int check(const char *name, unsigned char *buf, unsigned int n) {
  unsigned int rc = 0, cover = 0; int bad = 0;
  region_t *r = extract_requests_matter_tcp(buf, n, &rc);
  for (unsigned int i = 0; i < rc; i++) {
    u32 len = r[i].end_byte - r[i].start_byte + 1;   /* what AFLNet computes */
    if (r[i].end_byte < r[i].start_byte) { printf("  %-28s INVERTED region[%u] %u..%u\n", name, i, r[i].start_byte, r[i].end_byte); bad = 1; }
    if (r[i].end_byte >= n)              { printf("  %-28s OOB region[%u] end=%u n=%u\n", name, i, r[i].end_byte, n); bad = 1; }
    if (len > n)                         { printf("  %-28s HUGE len=%u (n=%u)\n", name, len, n); bad = 1; }
    if (r[i].start_byte != cover)        { printf("  %-28s GAP at region[%u]\n", name, i); bad = 1; }
    cover = r[i].end_byte + 1;
  }
  if (cover != n) { printf("  %-28s INCOMPLETE cover=%u n=%u\n", name, cover, n); bad = 1; }
  printf("  %-28s %u regions  %s\n", name, rc, bad ? "*** FAIL ***" : "ok");
  return bad;
}

int main(void) {
  int bad = 0;
  unsigned char buf[256];
  /* the exact killer: msg_len = 0xFFFFFFF9 -> frame_len 0xFFFFFFFD -> end = pos-4 */
  u32 evil[] = { 0xFFFFFFF9u, 0xFFFFFFFDu, 0xFFFFFFFFu, 0xFFFFFFFCu, 0x80000000u, 0u, 1u, 0xFFu };
  for (unsigned e = 0; e < sizeof(evil)/sizeof(evil[0]); e++) {
    char nm[64];
    memset(buf, 0x41, sizeof buf);
    /* a valid first frame, then the malicious one at pos = 55 (>3) */
    buf[0]=51; buf[1]=0; buf[2]=0; buf[3]=0;
    buf[55]= evil[e] & 0xFF; buf[56]=(evil[e]>>8)&0xFF; buf[57]=(evil[e]>>16)&0xFF; buf[58]=(evil[e]>>24)&0xFF;
    snprintf(nm, sizeof nm, "len=0x%08X", evil[e]);
    bad |= check(nm, buf, sizeof buf);
  }
  /* truncated: fewer than 4 bytes left */
  memset(buf, 0x42, 3); bad |= check("3-byte buffer", buf, 3);
  printf("%s\n", bad ? "RESULT: FAIL" : "RESULT: ALL PASS");
  return bad;
}
