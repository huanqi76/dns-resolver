#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include "cache.h"
#include "dns.h"

#define CACHE_SLOTS 1024

typedef struct {
    int used;
    char name[256];
    uint16_t qtype, qclass;
    time_t stored;      // when we saved it
    uint32_t ttl;       // smallest answer TTL at that time
    uint8_t *msg;       // copy of the full response
    size_t len;
} entry_t;

static entry_t cache[CACHE_SLOTS];

static unsigned slot_for(const char *name, uint16_t qtype, uint16_t qclass) {
    unsigned h = 5381;
    for (const char *p = name; *p; p++)
        h = h * 33 + (unsigned char)tolower((unsigned char)*p);   // names are case-insensitive
    h = h * 33 + qtype;
    h = h * 33 + qclass;
    return h % CACHE_SLOTS;
}

// Offset of the first record, just past the question section; -1 if invalid.
static int records_start(const uint8_t *msg, size_t len) {
    char tmp[256];
    size_t off = 12;
    int qd = read16(msg + 4);
    for (int i = 0; i < qd; i++) {
        int r = parse_name(msg, len, off, tmp, sizeof tmp);
        if (r < 0 || (size_t)r + 4 > len) return -1;
        off = r + 4;
    }
    return (int)off;
}

// Smallest TTL among the answer records; -1 if the message doesn't parse.
static long min_answer_ttl(const uint8_t *msg, size_t len) {
    int off = records_start(msg, len);
    if (off < 0) return -1;
    int an = read16(msg + 6);
    long min = -1;
    rr_t rr;
    for (int i = 0; i < an; i++) {
        int r = parse_rr(msg, len, off, &rr);
        if (r < 0) return -1;
        if (min < 0 || rr.ttl < (uint32_t)min) min = rr.ttl;
        off = r;
    }
    return min;
}

// Subtract `elapsed` seconds from every record's TTL (skipping the OPT record).
static void age_ttls(uint8_t *msg, size_t len, uint32_t elapsed) {
    int off = records_start(msg, len);
    if (off < 0) return;
    int total = read16(msg + 6) + read16(msg + 8) + read16(msg + 10);
    rr_t rr;
    for (int i = 0; i < total; i++) {
        int r = parse_rr(msg, len, off, &rr);
        if (r < 0) return;
        if (rr.type != 41) {                                  // OPT's "TTL" field holds flags
            uint32_t t = rr.ttl > elapsed ? rr.ttl - elapsed : 0;
            write32(msg + rr.rdata_off - 6, t);               // TTL sits 6 bytes before the RDATA
        }
        off = r;
    }
}

void cache_put(const char *name, uint16_t qtype, uint16_t qclass,
               const uint8_t *resp, size_t len) {
    if (len < 12 || strlen(name) >= 256) return;
    if ((read16(resp + 2) & 0xF) != 0) return;     // errors (NXDOMAIN, ...) aren't cached
    if (read16(resp + 6) == 0) return;             // empty answers aren't cached
    long ttl = min_answer_ttl(resp, len);
    if (ttl <= 0) return;

    entry_t *e = &cache[slot_for(name, qtype, qclass)];
    free(e->msg);
    e->msg = malloc(len);
    if (!e->msg) { e->used = 0; return; }
    memcpy(e->msg, resp, len);
    e->len = len;
    strcpy(e->name, name);
    e->qtype = qtype;
    e->qclass = qclass;
    e->stored = time(NULL);
    e->ttl = (uint32_t)ttl;
    e->used = 1;
}

int cache_get(const char *name, uint16_t qtype, uint16_t qclass,
              uint8_t *out, size_t cap) {
    entry_t *e = &cache[slot_for(name, qtype, qclass)];
    if (!(e->used && e->qtype == qtype && e->qclass == qclass &&
          strcasecmp(e->name, name) == 0))
        return 0;

    time_t elapsed = time(NULL) - e->stored;
    if (elapsed < 0) elapsed = 0;
    if (elapsed >= (time_t)e->ttl) {               // expired: delete it
        free(e->msg);
        e->msg = NULL;
        e->used = 0;
        return 0;
    }
    if (e->len > cap) return 0;
    memcpy(out, e->msg, e->len);
    age_ttls(out, e->len, (uint32_t)elapsed);
    return (int)e->len;
}