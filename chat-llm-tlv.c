/*
   ChatAFL-for-Matter — dependency-free TLV + catalog implementation.
   No libcurl / json-c here. See chat-llm-tlv.h.
*/

#include "chat-llm-tlv.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>

/* ===================================================================== *
 *  Matter wire-format helpers                                            *
 * ===================================================================== */

int mm_msg_header_len(const unsigned char *buf, unsigned int off,
                      unsigned int size) {
  if (off + 8 > size) return -1;
  unsigned char msg_flags = buf[off];
  int len = 8; /* flags(1)+sessionId(2)+secFlags(1)+counter(4) */
  if (msg_flags & 0x04) len += 8;   /* Source Node ID */
  unsigned char dsiz = msg_flags & 0x03;
  if (dsiz == 0x01) len += 8;       /* Dest Node ID */
  else if (dsiz == 0x02) len += 2;  /* Dest Group ID */
  else if (dsiz == 0x03) return -1; /* reserved */
  if (off + (unsigned int)len > size) return -1;
  return len;
}

int mm_payload_header_len(const unsigned char *buf, unsigned int off,
                          unsigned int size) {
  if (off + 6 > size) return -1;
  unsigned char ex_flags = buf[off];
  int len = 6; /* exFlags(1)+opcode(1)+exchangeId(2)+protocolId(2) */
  if (ex_flags & 0x10) len += 2;    /* Vendor ID */
  if (ex_flags & 0x02) len += 4;    /* Ack counter */
  if (off + (unsigned int)len > size) return -1;
  return len;
}

static void range_push(mrange_t **out, unsigned int *count, unsigned int *cap,
                       unsigned int start, unsigned int len) {
  if (*count == *cap) {
    *cap = *cap ? *cap * 2 : 8;
    *out = (mrange_t *)realloc(*out, *cap * sizeof(mrange_t));
  }
  (*out)[*count].start = (int)start;
  (*out)[*count].len = (int)len;
  (*count)++;
}

long tlv_collect_ranges(const unsigned char *buf, unsigned int off,
                        unsigned int size, mrange_t **out, unsigned int *count,
                        unsigned int *cap) {
  unsigned int i = off;
  int depth = 0;

  do {
    if (i >= size) return -1;
    unsigned char ctrl = buf[i++];
    unsigned char elem_type = ctrl & 0x1F;

    if (elem_type == 0x18) { /* EndOfContainer */
      if (depth == 0) return -1;
      depth--;
      continue;
    }

    unsigned int tag_len;
    switch (ctrl & 0xE0) {
      case 0x00: tag_len = 0; break; /* anonymous */
      case 0x20: tag_len = 1; break; /* context */
      case 0x40: tag_len = 2; break; /* common 2-byte */
      case 0x60: tag_len = 4; break; /* common 4-byte */
      case 0x80: tag_len = 2; break; /* implicit 2-byte */
      case 0xA0: tag_len = 4; break; /* implicit 4-byte */
      case 0xC0: tag_len = 6; break; /* fully-qualified 6-byte */
      case 0xE0: tag_len = 8; break; /* fully-qualified 8-byte */
      default: return -1;
    }
    i += tag_len;
    if (i > size) return -1;

    if (elem_type <= 0x07) {
      unsigned int vlen = 1u << (elem_type & 0x03); /* int value bytes */
      if (i + vlen > size) return -1;
      range_push(out, count, cap, i, vlen);
      i += vlen;
    } else if (elem_type == 0x08 || elem_type == 0x09) {
      /* boolean: encoded in type, no value bytes */
    } else if (elem_type == 0x0A) {
      if (i + 4 > size) return -1;
      range_push(out, count, cap, i, 4); /* float32 */
      i += 4;
    } else if (elem_type == 0x0B) {
      if (i + 8 > size) return -1;
      range_push(out, count, cap, i, 8); /* double */
      i += 8;
    } else if (elem_type >= 0x0C && elem_type <= 0x13) {
      /* UTF8 (0x0C-0F) / byte (0x10-13) string. length field = 1<<(low2). */
      unsigned int len_field = 1u << ((elem_type - 0x0C) & 0x03);
      if (i + len_field > size) return -1;
      unsigned long long str_len = 0;
      unsigned int k;
      for (k = 0; k < len_field; k++)
        str_len |= ((unsigned long long)buf[i + k]) << (8 * k);
      i += len_field; /* length bytes NOT mutable (would reframe) */
      if (i + (unsigned int)str_len > size) return -1;
      if (str_len > 0) range_push(out, count, cap, i, (unsigned int)str_len);
      i += (unsigned int)str_len; /* mutate string content only */
    } else if (elem_type == 0x14) {
      /* null: no value bytes */
    } else if (elem_type >= 0x15 && elem_type <= 0x17) {
      depth++; /* structure / array / list */
    } else {
      return -1; /* unknown */
    }
    if (i > size) return -1;
  } while (depth > 0);

  return (long)(i - off);
}

mrange_t *matter_get_mutable_ranges(const unsigned char *buf, unsigned int len,
                                    unsigned int *count) {
  mrange_t *out = NULL;
  unsigned int n = 0, cap = 0;
  unsigned int pos = 0;
  *count = 0;

  while (pos < len) {
    int mh = mm_msg_header_len(buf, pos, len);
    if (mh < 0) break;
    int ph = mm_payload_header_len(buf, pos + (unsigned int)mh, len);
    if (ph < 0) break;
    unsigned int tlv_off = pos + (unsigned int)mh + (unsigned int)ph;
    long consumed = tlv_collect_ranges(buf, tlv_off, len, &out, &n, &cap);
    if (consumed < 0) break;
    unsigned int msg_len = (unsigned int)mh + (unsigned int)ph +
                           (unsigned int)consumed + MATTER_MIC_LEN;
    if (pos + msg_len > len) break; /* last datagram may omit MIC */
    pos += msg_len;
  }

  *count = n;
  return out;
}

/* ===================================================================== *
 *  Catalog                                                               *
 * ===================================================================== */

int tlv_find_ctx_u8(const unsigned char *buf, unsigned int off, unsigned int end,
                    unsigned char want_tag, int *val_off) {
  unsigned int i = off;
  while (i + 3 <= end) {
    if (buf[i] == 0x24 /* ctx tag, uint8 */ && buf[i + 1] == want_tag) {
      if (val_off) *val_off = (int)(i + 2);
      return buf[i + 2];
    }
    i++;
  }
  if (val_off) *val_off = -1;
  return -1;
}

void entry_decode(catalog_entry_t *e) {
  e->opcode = 0;
  e->endpoint = e->cluster_id = e->target_id = -1;
  int mh = mm_msg_header_len(e->bytes, 0, e->len);
  if (mh < 0) return;
  int ph = mm_payload_header_len(e->bytes, (unsigned int)mh, e->len);
  if (ph < 0) return;
  e->opcode = e->bytes[mh + 1];
  unsigned int tlv_off = (unsigned int)mh + (unsigned int)ph;
  unsigned int tlv_end =
      e->len > MATTER_MIC_LEN ? e->len - MATTER_MIC_LEN : e->len;
  e->endpoint = tlv_find_ctx_u8(e->bytes, tlv_off, tlv_end, 0x02, NULL);
  e->cluster_id = tlv_find_ctx_u8(e->bytes, tlv_off, tlv_end, 0x03, NULL);
  e->target_id = tlv_find_ctx_u8(e->bytes, tlv_off, tlv_end, 0x04, NULL);
  snprintf(e->key, sizeof(e->key), "%02x:%d:%d:%d", e->opcode, e->endpoint,
           e->cluster_id, e->target_id);
}

int catalog_add_unique(matter_catalog_t *cat, catalog_entry_t e) {
  for (unsigned int j = 0; j < cat->count; j++)
    if (strcmp(cat->entries[j].key, e.key) == 0) {
      free(e.bytes);
      return 0;
    }
  if (cat->count == cat->cap) {
    cat->cap = cat->cap ? cat->cap * 2 : 8;
    cat->entries =
        realloc(cat->entries, cat->cap * sizeof(catalog_entry_t));
  }
  cat->entries[cat->count++] = e;
  return 1;
}

catalog_entry_t *catalog_find_by_opcode(matter_catalog_t *cat, unsigned char op) {
  for (unsigned int i = 0; i < cat->count; i++)
    if (cat->entries[i].opcode == op) return &cat->entries[i];
  return NULL;
}

catalog_entry_t catalog_clone_with_ids(const catalog_entry_t *src, int endpoint,
                                       int cluster, int target) {
  catalog_entry_t e;
  memset(&e, 0, sizeof(e));
  e.bytes = malloc(src->len);
  memcpy(e.bytes, src->bytes, src->len);
  e.len = src->len;
  int mh = mm_msg_header_len(e.bytes, 0, e.len);
  int ph = mm_payload_header_len(e.bytes, (unsigned int)mh, e.len);
  unsigned int tlv_off = (unsigned int)mh + (unsigned int)ph;
  unsigned int tlv_end =
      e.len > MATTER_MIC_LEN ? e.len - MATTER_MIC_LEN : e.len;
  int off;
  if (endpoint >= 0 &&
      tlv_find_ctx_u8(e.bytes, tlv_off, tlv_end, 0x02, &off) >= 0 && off >= 0)
    e.bytes[off] = (unsigned char)endpoint;
  if (cluster >= 0 &&
      tlv_find_ctx_u8(e.bytes, tlv_off, tlv_end, 0x03, &off) >= 0 && off >= 0)
    e.bytes[off] = (unsigned char)cluster;
  if (target >= 0 &&
      tlv_find_ctx_u8(e.bytes, tlv_off, tlv_end, 0x04, &off) >= 0 && off >= 0)
    e.bytes[off] = (unsigned char)target;
  entry_decode(&e);
  return e;
}

static void catalog_ingest(matter_catalog_t *cat, const unsigned char *buf,
                           unsigned int len) {
  unsigned int pos = 0;
  while (pos < len) {
    int mh = mm_msg_header_len(buf, pos, len);
    if (mh < 0) break;
    int ph = mm_payload_header_len(buf, pos + (unsigned int)mh, len);
    if (ph < 0) break;
    mrange_t *tmp = NULL;
    unsigned int n = 0, cap = 0;
    long tlv = tlv_collect_ranges(
        buf, pos + (unsigned int)mh + (unsigned int)ph, len, &tmp, &n, &cap);
    free(tmp);
    if (tlv < 0) break;
    unsigned int msg_len = (unsigned int)mh + (unsigned int)ph +
                           (unsigned int)tlv + MATTER_MIC_LEN;
    if (pos + msg_len > len) msg_len = len - pos; /* last datagram clamp */
    if (msg_len == 0) break;

    catalog_entry_t e;
    memset(&e, 0, sizeof(e));
    e.bytes = malloc(msg_len);
    memcpy(e.bytes, buf + pos, msg_len);
    e.len = msg_len;
    entry_decode(&e);
    catalog_add_unique(cat, e);
    pos += msg_len;
  }
}

static unsigned char *read_file(const char *path, unsigned int *out_len) {
  FILE *f = fopen(path, "rb");
  if (!f) return NULL;
  fseek(f, 0, SEEK_END);
  long sz = ftell(f);
  fseek(f, 0, SEEK_SET);
  if (sz <= 0) { fclose(f); return NULL; }
  unsigned char *b = malloc((size_t)sz);
  size_t got = fread(b, 1, (size_t)sz, f);
  fclose(f);
  if (got != (size_t)sz) { free(b); return NULL; }
  *out_len = (unsigned int)sz;
  return b;
}

matter_catalog_t *matter_catalog_build(const char *seed_dir) {
  matter_catalog_t *cat = calloc(1, sizeof(matter_catalog_t));
  DIR *d = opendir(seed_dir);
  if (!d) return cat;
  struct dirent *de;
  while ((de = readdir(d))) {
    if (de->d_name[0] == '.') continue;
    if (strncmp(de->d_name, "enriched_", 9) == 0) continue; /* avoid feedback */
    char path[2048];
    snprintf(path, sizeof(path), "%s/%s", seed_dir, de->d_name);
    unsigned int len = 0;
    unsigned char *b = read_file(path, &len);
    if (!b) continue;
    catalog_ingest(cat, b, len);
    free(b);
  }
  closedir(d);
  return cat;
}

void matter_catalog_free(matter_catalog_t *cat) {
  if (!cat) return;
  for (unsigned int i = 0; i < cat->count; i++) free(cat->entries[i].bytes);
  free(cat->entries);
  free(cat);
}

unsigned int matter_catalog_size(const matter_catalog_t *cat) {
  return cat ? cat->count : 0;
}

int seed_has_type(const unsigned char *seed, unsigned int len,
                  const catalog_entry_t *e) {
  unsigned int pos = 0;
  while (pos < len) {
    int mh = mm_msg_header_len(seed, pos, len);
    if (mh < 0) break;
    int ph = mm_payload_header_len(seed, pos + (unsigned int)mh, len);
    if (ph < 0) break;
    mrange_t *tmp = NULL;
    unsigned int n = 0, cap = 0;
    long tlv = tlv_collect_ranges(
        seed, pos + (unsigned int)mh + (unsigned int)ph, len, &tmp, &n, &cap);
    free(tmp);
    if (tlv < 0) break;
    unsigned int msg_len = (unsigned int)mh + (unsigned int)ph +
                           (unsigned int)tlv + MATTER_MIC_LEN;
    if (pos + msg_len > len) msg_len = len - pos;
    if (msg_len == 0) break;

    catalog_entry_t probe;
    memset(&probe, 0, sizeof(probe));
    probe.bytes = malloc(msg_len);
    memcpy(probe.bytes, seed + pos, msg_len);
    probe.len = msg_len;
    entry_decode(&probe);
    int match = strcmp(probe.key, e->key) == 0;
    free(probe.bytes);
    if (match) return 1;
    pos += msg_len;
  }
  return 0;
}

char *render_catalog(const matter_catalog_t *cat) {
  size_t cap = 256 + (size_t)cat->count * 64;
  char *s = malloc(cap);
  size_t used = 0;
  s[0] = 0;
  for (unsigned int i = 0; i < cat->count; i++) {
    const catalog_entry_t *e = &cat->entries[i];
    const char *act = e->opcode == 0x08 ? "invoke"
                      : e->opcode == 0x06 ? "write"
                                          : "read";
    int w = snprintf(s + used, cap - used,
                     "- action=%s endpoint=%d cluster=%d target=%d\\n", act,
                     e->endpoint, e->cluster_id, e->target_id);
    if (w < 0 || (size_t)w >= cap - used) break;
    used += (size_t)w;
    if (used > cap - 80) break;
  }
  return s;
}

int matter_catalog_write_enriched(matter_catalog_t *cat, const char *seed_dir) {
  if (cat->count == 0) return 0;
  int written = 0;
  DIR *d = opendir(seed_dir);
  if (!d) return 0;

  /* snapshot existing seed names (we add files while iterating) */
  char names[256][256];
  int nnames = 0;
  struct dirent *de;
  while ((de = readdir(d)) && nnames < 256) {
    if (de->d_name[0] == '.') continue;
    if (strncmp(de->d_name, "enriched_", 9) == 0) continue;
    snprintf(names[nnames++], 256, "%s", de->d_name);
  }
  closedir(d);

  for (int s = 0; s < nnames; s++) {
    char path[2048];
    snprintf(path, sizeof(path), "%s/%s", seed_dir, names[s]);
    unsigned int len = 0;
    unsigned char *b = read_file(path, &len);
    if (!b) continue;

    unsigned int appended = 0;
    unsigned char *acc = malloc(len);
    memcpy(acc, b, len);
    unsigned int acc_len = len;
    for (unsigned int i = 0; i < cat->count && appended < 2; i++) {
      if (seed_has_type(b, len, &cat->entries[i])) continue;
      acc = realloc(acc, acc_len + cat->entries[i].len);
      memcpy(acc + acc_len, cat->entries[i].bytes, cat->entries[i].len);
      acc_len += cat->entries[i].len;
      appended++;
    }
    if (appended > 0) {
      char outp[2200];
      snprintf(outp, sizeof(outp), "%s/enriched_%d_%s", seed_dir, s, names[s]);
      FILE *f = fopen(outp, "wb");
      if (f) {
        fwrite(acc, 1, acc_len, f);
        fclose(f);
        written++;
      }
    }
    free(acc);
    free(b);
  }
  return written;
}
