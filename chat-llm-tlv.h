/*
   ChatAFL-for-Matter — dependency-free TLV + message-catalog internals.

   This translation unit has NO external dependencies (stdlib + dirent only) so
   it compiles and unit-tests standalone, without libcurl/json-c. The LLM
   transport and prompt/JSON code lives in chat-llm.c and consumes these.

   See chat-llm.h for the public API and the integration rationale.
*/

#ifndef __CHAT_LLM_TLV_H
#define __CHAT_LLM_TLV_H

#include "chat-llm.h" /* mrange_t, matter_catalog_t, public prototypes */

#define MATTER_MIC_LEN 16
#define MATTER_PROTOCOL_ID_IM 0x0001

/* A representative Matter datagram and its decoded identity. */
typedef struct {
  unsigned char *bytes; /* full datagram incl. headers + MIC placeholder */
  unsigned int len;
  unsigned char opcode; /* IM opcode: 0x02 read, 0x06 write, 0x08 invoke ... */
  int endpoint;         /* context tag 2, or -1 */
  int cluster_id;       /* context tag 3, or -1 */
  int target_id;        /* context tag 4 (attr/cmd), or -1 */
  char key[48];         /* "op:ep:cl:tg" identity */
} catalog_entry_t;

struct matter_catalog {
  catalog_entry_t *entries;
  unsigned int count;
  unsigned int cap;
};

/* Wire-format helpers (mirror aflnet.c's Matter parser). */
int mm_msg_header_len(const unsigned char *buf, unsigned int off, unsigned int size);
int mm_payload_header_len(const unsigned char *buf, unsigned int off, unsigned int size);

/* Walk TLV at [off,size), append primitive value-byte ranges to *out (grown via
   realloc). Returns end-offset consumed, or -1 on malformed TLV. */
long tlv_collect_ranges(const unsigned char *buf, unsigned int off,
                        unsigned int size, mrange_t **out, unsigned int *count,
                        unsigned int *cap);

/* Decode an entry's identity (opcode/endpoint/cluster/target/key) from bytes.
   Handles context-tagged uint8/16/32/64 ids (e.g. cluster 0x0300 = two bytes). */
void entry_decode(catalog_entry_t *e);

/* Catalog helpers used by both TUs. */
catalog_entry_t *catalog_find_by_opcode(matter_catalog_t *cat, unsigned char op);
catalog_entry_t catalog_clone_with_ids(const catalog_entry_t *src, int endpoint,
                                        int cluster, int target);
/* Add e if its identity key is new; returns 1 if added, 0 if dup (e freed). */
int catalog_add_unique(matter_catalog_t *cat, catalog_entry_t e);
/* 1 iff `seed` contains a datagram with e's identity. */
int seed_has_type(const unsigned char *seed, unsigned int len, const catalog_entry_t *e);
/* Compact human/LLM-readable listing (malloc'd). */
char *render_catalog(const matter_catalog_t *cat);

#endif /* __CHAT_LLM_TLV_H */
