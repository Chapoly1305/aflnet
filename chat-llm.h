/*
   ChatAFL-for-Matter — LLM-guided protocol fuzzing layer.

   This is a TLV-aware reimplementation of the ChatAFL (NDSS'24) LLM layer,
   ported onto AFLNet's Matter parser. Where upstream ChatAFL represents a
   protocol message as ASCII lines with `<<VALUE>>` markers and finds mutable
   spans with PCRE2 regexes, Matter messages are binary TLV. We therefore:

     * find mutable spans by *walking the TLV* (matter_get_mutable_ranges),
       not by regex — mutation stays inside primitive value bytes so framing
       and TLV length/control bytes are never corrupted (in-place mutation);

     * keep the LLM operating at the message-type / sequence level (grammar
       discovery, seed enrichment, stall/plateau breaking) over a compact
       Matter "notation", and encode its choices back to wire bytes with a
       deterministic template encoder (matter_catalog_*).

   The three LLM roles of ChatAFL are preserved:
     1. grammar      -> matter_catalog_build + matter_catalog_llm_augment
     2. enrichment   -> matter_catalog_write_enriched
     3. stall/plateau-> matter_llm_next_seed

   INDEPENDENCE: this module reads ONLY the AFLNet seed corpus + the Matter
   spec/cluster names baked into prompts. It must never read EclipseFuzz's FSM
   catalogs, proto seeds, mutator, or oracles — that would make the baseline a
   re-derivation of the system under test. See ai_docs/benchmark-fuzzers.md.

   The whole file is gated by the caller behind -DCHATAFL; the symbols here are
   plain C with no dependency on afl-fuzz internals so they can be unit-tested
   standalone (see matter/test_chatafl_tlv.c).
*/

#ifndef __CHAT_LLM_MATTER_H
#define __CHAT_LLM_MATTER_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* A mutable byte span within a Matter message buffer (value bytes only). */
typedef struct {
  int start; /* offset into the message buffer */
  int len;   /* number of value bytes (>= 1) */
} mrange_t;

/* ----------------------------------------------------------------------- *
 *  TLV-aware mutable-range extraction (deterministic, no LLM, no network)  *
 * ----------------------------------------------------------------------- */

/* Walk a single Matter datagram ([msg-hdr][payload-hdr][TLV][MIC]) and return
   an array of value-byte spans for every primitive TLV element (signed/
   unsigned int, float, double, and the *content* bytes of UTF8/byte strings).
   Control/tag/length bytes, the headers and the MIC are never included, so
   mutating within these ranges keeps the message structurally valid TLV.

   Returns a malloc'd array (free with free()); *count receives the length.
   Returns NULL with *count==0 if the buffer does not parse as Matter. */
mrange_t *matter_get_mutable_ranges(const unsigned char *buf, unsigned int len,
                                    unsigned int *count);

/* ----------------------------------------------------------------------- *
 *  LLM transport (libcurl + json-c). API key from env CHATAFL_OPENAI_KEY   *
 *  (falls back to OPENAI_API_KEY). Endpoint overridable via                *
 *  CHATAFL_OPENAI_BASE (default https://api.openai.com).                   *
 * ----------------------------------------------------------------------- */

/* 1 iff LLM calls are enabled: env CHATAFL_LLM=1 AND an API key is present.
   When 0, the catalog/enrichment/stall paths degrade to deterministic,
   corpus-only behaviour (no network) so the fuzzer still runs offline. */
int matter_llm_enabled(void);

/* POST `prompt` (already a JSON messages array for chat models, or a raw
   string for "instruct") and return the model's text (malloc'd, free with
   free()), or NULL on failure after `tries` attempts. */
char *chat_with_llm(const char *prompt, const char *model, int tries,
                    float temperature);

/* ----------------------------------------------------------------------- *
 *  Message-type catalog (grammar) + deterministic encoder                  *
 * ----------------------------------------------------------------------- */

typedef struct matter_catalog matter_catalog_t;

/* Parse every seed under `seed_dir`, split into Matter datagrams, and build a
   catalog of distinct message *types* keyed by (action, endpoint, cluster_id,
   target_id), each holding a representative wire template. */
matter_catalog_t *matter_catalog_build(const char *seed_dir);

/* Ask the LLM to name additional valid Matter message types missing from the
   corpus; synthesize templates for them by cloning the closest same-action
   template and rewriting its endpoint/cluster/target TLV fields. No-op (returns
   0) when matter_llm_enabled()==0. Returns number of types added. */
int matter_catalog_llm_augment(matter_catalog_t *cat);

/* ChatAFL seed enrichment: for each seed, ask the LLM (or, offline, pick
   deterministically) which catalog message types are missing, then write
   enriched seeds (original datagrams + appended templates) into `seed_dir` so
   they are loaded as initial seeds. Returns number of enriched seeds written. */
int matter_catalog_write_enriched(matter_catalog_t *cat, const char *seed_dir);

/* Stall/plateau response: given the current seed's bytes, choose the next
   message type to append (LLM when enabled, else a catalog type not present in
   the seed) and produce a new seed = current bytes + encoded message.
   Returns 1 and sets out / out_len (malloc'd) on success, 0 otherwise. */
int matter_llm_next_seed(const matter_catalog_t *cat, const unsigned char *cur,
                         unsigned int cur_len, unsigned char **out,
                         unsigned int *out_len);

void matter_catalog_free(matter_catalog_t *cat);

/* Number of distinct message types in the catalog (for stats/logging). */
unsigned int matter_catalog_size(const matter_catalog_t *cat);

#ifdef __cplusplus
}
#endif

#endif /* __CHAT_LLM_MATTER_H */
