/*
   ChatAFL-for-Matter — LLM transport + prompt/JSON layer.

   Build deps: libcurl, json-c.  (PCRE2 intentionally NOT used — the upstream
   ChatAFL regex-on-text mutable-range finder is replaced by the TLV walker in
   chat-llm-tlv.c.)   apt install libcurl4-openssl-dev libjson-c-dev

   The dependency-free TLV + catalog internals live in chat-llm-tlv.c; this file
   adds the three LLM roles of ChatAFL on top: grammar augmentation, seed
   enrichment selection, and stall/plateau next-message selection.
*/

#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* asprintf */
#endif

#include "chat-llm.h"
#include "chat-llm-tlv.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <curl/curl.h>
#include <json-c/json.h>

#define MATTER_MAX_TOKENS 2048

/* ===================================================================== *
 *  LLM transport                                                         *
 * ===================================================================== */

static const char *llm_api_key(void) {
  const char *k = getenv("CHATAFL_OPENAI_KEY");
  if (k && *k) return k;
  k = getenv("OPENAI_API_KEY");
  if (k && *k) return k;
  return NULL;
}

static const char *llm_api_base(void) {
  const char *b = getenv("CHATAFL_OPENAI_BASE");
  if (b && *b) return b;
  return "https://api.openai.com";
}

int matter_llm_enabled(void) {
  const char *e = getenv("CHATAFL_LLM");
  if (!e || strcmp(e, "1") != 0) return 0;
  return llm_api_key() != NULL;
}

struct mem_chunk {
  char *memory;
  size_t size;
};

static size_t write_cb(void *contents, size_t size, size_t nmemb, void *userp) {
  size_t realsize = size * nmemb;
  struct mem_chunk *mem = (struct mem_chunk *)userp;
  char *p = realloc(mem->memory, mem->size + realsize + 1);
  if (!p) return 0;
  mem->memory = p;
  memcpy(&mem->memory[mem->size], contents, realsize);
  mem->size += realsize;
  mem->memory[mem->size] = 0;
  return realsize;
}

char *chat_with_llm(const char *prompt, const char *model, int tries,
                    float temperature) {
  const char *key = llm_api_key();
  if (!key) return NULL;

  CURL *curl = curl_easy_init();
  if (!curl) return NULL;

  char url[512];
  int is_instruct = (strcmp(model, "instruct") == 0);
  snprintf(url, sizeof(url), "%s/v1/%s", llm_api_base(),
           is_instruct ? "completions" : "chat/completions");

  char auth_header[4096];
  snprintf(auth_header, sizeof(auth_header), "Authorization: Bearer %s", key);

  char *answer = NULL;
  do {
    char *data = NULL;
    if (is_instruct) {
      json_object *jstr = json_object_new_string(prompt);
      const char *esc = json_object_to_json_string(jstr); /* quoted+escaped */
      asprintf(&data,
               "{\"model\": \"gpt-3.5-turbo-instruct\", \"prompt\": %s, "
               "\"max_tokens\": %d, \"temperature\": %f}",
               esc, MATTER_MAX_TOKENS, temperature);
      json_object_put(jstr);
    } else {
      asprintf(&data,
               "{\"model\": \"gpt-3.5-turbo\", \"messages\": %s, "
               "\"max_tokens\": %d, \"temperature\": %f}",
               prompt, MATTER_MAX_TOKENS, temperature);
    }

    struct mem_chunk chunk = {.memory = malloc(1), .size = 0};
    chunk.memory[0] = 0;

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, auth_header);
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, "Accept: application/json");

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 60L);

    CURLcode res = curl_easy_perform(curl);

    if (res == CURLE_OK && chunk.size > 0) {
      json_object *jobj = json_tokener_parse(chunk.memory);
      if (jobj) {
        json_object *choices = NULL;
        if (json_object_object_get_ex(jobj, "choices", &choices) &&
            json_object_get_type(choices) == json_type_array &&
            json_object_array_length(choices) > 0) {
          json_object *first = json_object_array_get_idx(choices, 0);
          const char *txt = NULL;
          if (is_instruct) {
            json_object *t = NULL;
            if (json_object_object_get_ex(first, "text", &t))
              txt = json_object_get_string(t);
          } else {
            json_object *m = NULL, *c = NULL;
            if (json_object_object_get_ex(first, "message", &m) &&
                json_object_object_get_ex(m, "content", &c))
              txt = json_object_get_string(c);
          }
          if (txt) {
            while (*txt == '\n') txt++;
            answer = strdup(txt);
          }
        }
        json_object_put(jobj);
      }
    }

    curl_slist_free_all(headers);
    free(chunk.memory);
    free(data);

    if (answer) break;
    if (--tries > 0) sleep(2);
  } while (tries > 0);

  curl_easy_cleanup(curl);
  return answer;
}

/* ===================================================================== *
 *  Role 1: grammar augmentation                                          *
 * ===================================================================== */

/* Parse [{"action":..,"endpoint":N,"cluster":N,"target":N}, ...] and add
   synthesized entries by cloning same-action templates. */
static int augment_from_json(matter_catalog_t *cat, const char *json_txt) {
  int added = 0;
  json_object *arr = json_tokener_parse(json_txt);
  if (!arr || json_object_get_type(arr) != json_type_array) {
    if (arr) json_object_put(arr);
    return 0;
  }
  size_t n = json_object_array_length(arr);
  for (size_t i = 0; i < n; i++) {
    json_object *o = json_object_array_get_idx(arr, i);
    if (!o || json_object_get_type(o) != json_type_object) continue;
    json_object *jo;
    const char *action = "read";
    if (json_object_object_get_ex(o, "action", &jo))
      action = json_object_get_string(jo);
    int ep = -1, cl = -1, tg = -1;
    if (json_object_object_get_ex(o, "endpoint", &jo)) ep = json_object_get_int(jo);
    if (json_object_object_get_ex(o, "cluster", &jo)) cl = json_object_get_int(jo);
    if (json_object_object_get_ex(o, "target", &jo)) tg = json_object_get_int(jo);

    unsigned char op = 0x02; /* read */
    if (strcmp(action, "invoke") == 0) op = 0x08;
    else if (strcmp(action, "write") == 0) op = 0x06;

    catalog_entry_t *tmpl = catalog_find_by_opcode(cat, op);
    if (!tmpl) tmpl = cat->count ? &cat->entries[0] : NULL;
    if (!tmpl) continue;

    catalog_entry_t e = catalog_clone_with_ids(tmpl, ep, cl, tg);
    added += catalog_add_unique(cat, e);
  }
  json_object_put(arr);
  return added;
}

int matter_catalog_llm_augment(matter_catalog_t *cat) {
  if (!matter_llm_enabled() || cat->count == 0) return 0;

  char *have = render_catalog(cat);
  char *user = NULL;
  asprintf(&user,
      "You are a Matter (CHIP) protocol fuzzing assistant. A device under test "
      "exposes Matter clusters over the Interaction Model. The fuzzer already "
      "has seeds for these message types:\\n%s\\n"
      "List up to 8 ADDITIONAL valid Matter message types (different cluster or "
      "attribute/command ids on the same endpoints) that would exercise new "
      "server code paths. Reply ONLY with a JSON array; each item is "
      "{\\\"action\\\":\\\"read|write|invoke\\\",\\\"endpoint\\\":N,"
      "\\\"cluster\\\":N,\\\"target\\\":N} with decimal ids.",
      have);
  free(have);

  char *prompt = NULL;
  asprintf(&prompt,
      "[{\"role\": \"system\", \"content\": \"You are a helpful assistant.\"}, "
      "{\"role\": \"user\", \"content\": \"%s\"}]",
      user);
  free(user);

  char *answer = chat_with_llm(prompt, "turbo", 3, 0.5);
  free(prompt);
  if (!answer) return 0;

  /* model may wrap the array in prose; extract first '[' .. last ']' */
  char *lb = strchr(answer, '[');
  char *rb = strrchr(answer, ']');
  int added = 0;
  if (lb && rb && rb > lb) {
    char saved = rb[1];
    rb[1] = 0;
    added = augment_from_json(cat, lb);
    rb[1] = saved;
  }
  free(answer);
  return added;
}

/* ===================================================================== *
 *  Role 3: stall / plateau — choose next message to append               *
 *  (Role 2 enrichment is deterministic and lives in chat-llm-tlv.c;      *
 *   the LLM augments the catalog it draws from via Role 1.)              *
 * ===================================================================== */

int matter_llm_next_seed(const matter_catalog_t *cat, const unsigned char *cur,
                         unsigned int cur_len, unsigned char **out,
                         unsigned int *out_len) {
  if (!cat || cat->count == 0) return 0;

  /* Default: first catalog type absent from the current seed. */
  int chosen = -1;
  for (unsigned int i = 0; i < cat->count; i++)
    if (!seed_has_type(cur, cur_len, &cat->entries[i])) { chosen = (int)i; break; }
  if (chosen < 0) chosen = (int)(cur_len % cat->count); /* all present: vary */

  if (matter_llm_enabled()) {
    char *have = render_catalog(cat);
    char *user = NULL;
    asprintf(&user,
        "The Matter fuzzer is stuck. Known message types (0-indexed in order):"
        "\\n%s\\nReply with ONLY the integer index of the single next message "
        "type most likely to drive the server into a new state.",
        have);
    free(have);
    char *prompt = NULL;
    asprintf(&prompt,
        "[{\"role\": \"system\", \"content\": \"You are a helpful assistant.\"},"
        " {\"role\": \"user\", \"content\": \"%s\"}]",
        user);
    free(user);
    char *ans = chat_with_llm(prompt, "turbo", 2, 1.0);
    free(prompt);
    if (ans) {
      int idx = atoi(ans);
      if (idx >= 0 && (unsigned)idx < cat->count) chosen = idx;
      free(ans);
    }
  }

  const catalog_entry_t *e = &cat->entries[chosen];
  unsigned int nl = cur_len + e->len;
  unsigned char *nb = malloc(nl);
  memcpy(nb, cur, cur_len);
  memcpy(nb + cur_len, e->bytes, e->len);
  *out = nb;
  *out_len = nl;
  return 1;
}
