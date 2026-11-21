#include <stdint.h>
#include "dns.h"

uint16_t read16(const uint8_t *p) {
    return (p[0] << 8) | p[1];
}

