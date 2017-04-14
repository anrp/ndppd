#pragma once

#include <stdint.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>

uint16_t checksum (uint16_t *addr, int len);
uint16_t icmp6_checksum (struct ip6_hdr, struct icmp6_hdr, uint8_t *, int);


