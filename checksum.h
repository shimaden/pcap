#if !defined(CHECKSUM_H__)
#define CHECKSUM_H__

#include <netinet/in.h>

extern uint16_t icmpv6checksum(
                        const struct in6_addr *src,
                        const struct in6_addr *dst,
                        uint32_t dataLength,
                        const uint16_t *data);
extern int is_icmp6_cksum_ok(const uint8_t *pkt);

#endif
