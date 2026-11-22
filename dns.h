#ifndef DNS_H
#define DNS_H

#include <stdint.h>

uint16_t read16(const uint8_t *p);
void write16(uint8_t *p, uint16_t v);
void write32(uint8_t*p, uint32_t v);

// Reads a name starting at msg[offset]. Write it into out. 
// Returns the offset of the first byte after the name, or -1 if invalid
int parse_name(const uint8_t *msg, size_t msglen, size_t offset, char* out, size_t outlen);

#endif