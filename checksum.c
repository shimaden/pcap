#include "checksum.h"

#include <netinet/ip6.h>

uint16_t icmpv6checksum(
                    const struct in6_addr *src,
                    const struct in6_addr *dst,
                    uint32_t dataLength,
                    const uint16_t *data)
{
    uint32_t sum = 0;
    int pos;

    /* src */
    for(pos = 0; pos < sizeof(struct in6_addr) / 2; pos++)
    {
        sum += ntohs(src->s6_addr16[pos]);
    }
    /* dst */
    for(pos = 0; pos < sizeof(struct in6_addr) / 2; pos++)
    {
        sum += ntohs(dst->s6_addr16[pos]);
    }
    /* Upper-Layer Packet Length */
    sum += dataLength >> 16;
    sum += dataLength & 0x0000FFFF;
    /* Next Header */
    sum += IPPROTO_ICMPV6;

    /* ICMP */
    for(pos = 0; pos < dataLength / 2; pos++)
    {
        sum += ntohs(data[pos]);
    }
    if(dataLength % 2)
        sum += *(u_int8_t *) & (data[pos]);

    sum = (sum & 0xffff) + (sum >> 16); /* add overflow counts */
    sum = (sum & 0xffff) + (sum >> 16); /* once again */
    return ~sum;
}

int is_icmp6_cksum_ok(const uint8_t *pkt)
{
    const struct ip6_hdr *ip6_hdr = (struct ip6_hdr *)pkt;
    const struct icmp6_hdr *icmp6_hdr = (struct icmp6_hdr *)(pkt + sizeof(struct ip6_hdr));
    uint16_t cksum;
    int is_cksum_ok;

    cksum = ntohs(
                icmpv6checksum(
                    &ip6_hdr->ip6_src,
                    &ip6_hdr->ip6_dst,
                    htons(ip6_hdr->ip6_plen),
                    (uint16_t *)icmp6_hdr
                )
            );
    is_cksum_ok = cksum == 0;

    return is_cksum_ok;
}
