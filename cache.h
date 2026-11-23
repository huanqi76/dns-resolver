#ifndef CACHE_H
#define CACHE_H
#include <stdint.h>

typedef struct {
    int used;
    char name[256];
    uint16_t qtype, qclass;
    time_t stored;      // when we saved it
    uint32_t ttl;       // smallest answer TTL at that time
    uint8_t *msg;       // copy of the full response
    size_t len;
} entry_t;

// Returns the response length copied into out (TTLs already reduced), or 0 on a miss.
int cache_get(const char *name, uint16_t qtype, uint16_t qclass, uint8_t *out, size_t cap);
void cache_put(const char *name, uint16_t qtype, uint16_t qclass, const uint8_t *resp, size_t len);

#endif