#ifndef CACHE_H
#define CACHE_H
#include <stdint.h>
#include <stddef.h>

// Returns the response length copied into out (TTLs already reduced), or 0 on a miss.
int cache_get(const char *name, uint16_t qtype, uint16_t qclass, uint8_t *out, size_t cap);
void cache_put(const char *name, uint16_t qtype, uint16_t qclass, const uint8_t *resp, size_t len);

#endif