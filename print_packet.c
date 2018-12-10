#include "print_packet.h"

#include <stdio.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <net/ethernet.h>
#include <netdb.h>
#include <arpa/inet.h>

#include "checksum.h"

#define FULL_IP6_ADDR 1

#define TS_BUF_SIZE sizeof("0000000000.000000000")

/* 
 * RFC 4620 IPv6 Node Information Queries
 */
#define ND_INFORMATION_QUERY    139   /* Neighbor Information Query */
#define ND_INFORMATION_REPLY    140   /* Neighbor Information Reply */

struct nd_node_addr
{
    uint32_t      ttl;
    uint8_t       ip6_addr[16];
};

int g_timezone_offset;
unsigned int g_packets_captured;

static int is_ipv6(const uint8_t *pkt)
{
    const struct ip6_hdr *ip6_hdr = (struct ip6_hdr *)pkt;
    return (ip6_hdr->ip6_vfc >> 4) == 6;
}

static int is_icmp6(const uint8_t *pkt)
{
    const struct ip6_hdr *ip6_hdr;

    ip6_hdr = (struct ip6_hdr *)pkt;
    return ip6_hdr->ip6_nxt == IPPROTO_ICMPV6;
}

int is_echo(const uint8_t *pkt)
{
    const struct icmp6_hdr *icmp6_hdr;

    if(is_icmp6(pkt))
    {
        icmp6_hdr = (struct icmp6_hdr *)(pkt + sizeof(struct ip6_hdr));
        return icmp6_hdr->icmp6_type == ICMP6_ECHO_REQUEST
            || icmp6_hdr->icmp6_type == ICMP6_ECHO_REPLY;
    }
    return 0;
}

static int is_node_information_queries(const uint8_t *pkt)
{
    const struct icmp6_hdr *icmp6_hdr;

    if(is_icmp6(pkt))
    {
        icmp6_hdr = (struct icmp6_hdr *)(pkt + sizeof(struct ip6_hdr));
        return icmp6_hdr->icmp6_type == ND_INFORMATION_QUERY
            || icmp6_hdr->icmp6_type == ND_INFORMATION_REPLY;
    }
    return 0;
}

static int is_node_information_query(const uint8_t *pkt)
{
    const struct icmp6_hdr *icmp6_hdr;

    if(is_icmp6(pkt))
    {
        icmp6_hdr = (struct icmp6_hdr *)(pkt + sizeof(struct ip6_hdr));
        return icmp6_hdr->icmp6_type == ND_INFORMATION_QUERY;
    }
    return 0;
}

static int is_node_information_reply(const uint8_t *pkt)
{
    const struct icmp6_hdr *icmp6_hdr;

    if(is_icmp6(pkt))
    {
        icmp6_hdr = (struct icmp6_hdr *)(pkt + sizeof(struct ip6_hdr));
        return icmp6_hdr->icmp6_type == ND_INFORMATION_REPLY;
    }
    return 0;
}

char *bin_str(char dest[20], uint16_t data)
{
    int i;

    i = 0;
    dest[i++] = (data & 0x8000) ? '1' : '0';
    dest[i++] = (data & 0x4000) ? '1' : '0';
    dest[i++] = (data & 0x2000) ? '1' : '0';
    dest[i++] = (data & 0x1000) ? '1' : '0';
    dest[i++] = ' ';

    dest[i++] = (data & 0x0800) ? '1' : '0';
    dest[i++] = (data & 0x0400) ? '1' : '0';
    dest[i++] = (data & 0x0200) ? '1' : '0';
    dest[i++] = (data & 0x0100) ? '1' : '0';
    dest[i++] = ' ';

    dest[i++] = (data & 0x0080) ? '1' : '0';
    dest[i++] = (data & 0x0040) ? '1' : '0';
    dest[i++] = (data & 0x0020) ? '1' : '0';
    dest[i++] = (data & 0x0010) ? '1' : '0';
    dest[i++] = ' ';

    dest[i++] = (data & 0x0008) ? '1' : '0';
    dest[i++] = (data & 0x0004) ? '1' : '0';
    dest[i++] = (data & 0x0002) ? '1' : '0';
    dest[i++] = (data & 0x0001) ? '1' : '0';
    dest[i++] = '\0';

    return dest;
}

static const char *full_format_ip6_addr(char full_ip6_addr[40], const uint8_t ip6_addr[16])
{
    const int IP6_ADDR_SIZE = 16;
    int offset;
    int i;

    sprintf(full_ip6_addr, "%02x%02x", ip6_addr[0], ip6_addr[1]);
    offset = 4;
    for(i = 2 ; i < IP6_ADDR_SIZE ; i += 2)
    {
        sprintf(full_ip6_addr + offset, ":%02x%02x", ip6_addr[i], ip6_addr[i + 1]);
        offset += 5;
    }

    return full_ip6_addr;
}

static const char *icmp6_type_name(int type)
{
    switch(type) 
    {
        case ICMP6_DST_UNREACH:       /*   1 */
            return "ICMP6_DST_UNREACH";
        case ICMP6_ECHO_REQUEST:      /* 128 */
            return "ICMP6_ECHO_REQUEST";
        case ICMP6_ECHO_REPLY:        /* 129 */
            return "ICMP6_ECHO_REPLY";
        case ND_ROUTER_SOLICIT:       /* 133 */
            return "ND_ROUTER_SOLICIT";
        case ND_ROUTER_ADVERT:        /* 134 */
            return "ND_ROUTER_ADVERT";
        case ND_NEIGHBOR_SOLICIT:     /* 135 */
            return "ND_NEIGHBOR_SOLICIT";
        case ND_NEIGHBOR_ADVERT:      /* 136 */
            return "ND_NEIGHBOR_ADVERT";
        case ND_REDIRECT:             /* 137 */
            return "ND_REDIRECT";
        case 139:                     /* 139 */
            return "ND_INFORMATION_QUERY";
        case 140:                     /* 140 */
            return "ND_INFORMATION_REPLY";
        default:
            return "Other Type";
    }
}

static void print_ip6_header(const uint8_t *pkt)
{
    const struct ip6_hdr *ip6_hdr = (struct ip6_hdr *)pkt;
    const struct protoent *proto_info;
#if FULL_IP6_ADDR
    char full_src_addr_buf[40];
    char full_dest_addr_buf[40];
#else
    char src_addr_buf[INET6_ADDRSTRLEN];
    char dest_addr_buf[INET6_ADDRSTRLEN];
#endif

    printf("Version            : 0x%d\n", (int)(ip6_hdr->ip6_vfc >> 4));
    printf("Traffic Class      : 0x%02X\n", (ntohl(ip6_hdr->ip6_flow) >> 20) & 0xFF);
    printf("Flow Label         : 0x%06X\n", ntohl(ip6_hdr->ip6_flow) & 0x000FFFFF);
    printf("Payload Length     : %d\n",     ntohs(ip6_hdr->ip6_plen));

    if((proto_info = getprotobynumber(ip6_hdr->ip6_nxt)) != NULL)
    {
        printf("Next Header        : 0x%0X (%s)\n", ip6_hdr->ip6_nxt,
               ip6_hdr->ip6_nxt == 0 ? "HOPOPT" : proto_info->p_name);
    }
    else
    {
        printf("Next Header        : 0x%02X (unknown)\n", ip6_hdr->ip6_nxt);
    }

    printf("Hop Limit          : 0x%02X\n", ip6_hdr->ip6_hops);

#if FULL_IP6_ADDR
    printf("Source Address     : %s\n", full_format_ip6_addr(full_src_addr_buf, ip6_hdr->ip6_src.s6_addr));
    printf("Destination Address: %s\n", full_format_ip6_addr(full_dest_addr_buf, ip6_hdr->ip6_dst.s6_addr));
#else
    inet_ntop(AF_INET6, ip6_hdr->ip6_src.s6_addr, src_addr_buf, sizeof src_addr_buf);
    printf("Source Address     : %s\n", src_addr_buf);
    inet_ntop(AF_INET6, ip6_hdr->ip6_dst.s6_addr, dest_addr_buf, sizeof dest_addr_buf);
    printf("Destination Address: %s\n", dest_addr_buf);
#endif

}

static const char *qtype_name(const struct icmp6_hdr *icmp6_hdr)
{
    uint16_t qtype;
    qtype = ntohs(*(uint16_t *)(icmp6_hdr->icmp6_dataun.icmp6_un_data16 + 0));
    switch(qtype)
    {
        case 0:
            return "NOOP";
        case 1:
            return "unused";
        case 2:
            return "Node name";
        case 3:
            return "Node address";
        case 4:
            return "IPv4 address";
        default:
            return "unknown qtype";
    }
}

static void print_icmp6_header(const uint8_t *pkt)
{
    const struct icmp6_hdr *icmp6_hdr;
    uint16_t qtype;
    uint16_t flags;
    uint16_t buf;
    uint64_t buf64;
    uint64_t nonce;
    char flags_str[20];
    int is_cksum_ok;

    icmp6_hdr = (struct icmp6_hdr *)(pkt + sizeof(struct ip6_hdr));

    is_cksum_ok = is_icmp6_cksum_ok(pkt);

    printf("Type               : %d (%s)\n", icmp6_hdr->icmp6_type,
                                   icmp6_type_name(icmp6_hdr->icmp6_type));
    printf("Code               : %0d\n", ntohs(icmp6_hdr->icmp6_code));
    printf("Check sum          : 0x%04X %s\n", ntohs(icmp6_hdr->icmp6_cksum),
                                               is_cksum_ok ? "OK" : "Mismatch");
    if(is_echo(pkt))
    {
        printf("ID                 : 0x%04X\n", ntohs(icmp6_hdr->icmp6_id));
        printf("Sequence           : 0x%04X\n", ntohs(icmp6_hdr->icmp6_seq));
    }
    else if(is_node_information_queries(pkt))
    {
        memcpy(&buf, icmp6_hdr->icmp6_dataun.icmp6_un_data16 + 0, sizeof qtype);
        qtype = ntohs(buf);
        memcpy(&buf, icmp6_hdr->icmp6_dataun.icmp6_un_data16 + 1, sizeof flags);
        flags = ntohs(buf);
        memcpy(&buf64, icmp6_hdr->icmp6_dataun.icmp6_un_data16 + 2, sizeof buf64);
        nonce = ntohl(buf64);
        printf("QType              : 0x%04X (%s)\n", qtype, qtype_name(icmp6_hdr));
        printf("Flags              : 0x%04X, (%s)\n", flags, bin_str(flags_str, flags));
        printf("Nonce              : 0x%016lX\n", nonce);
    }
}

void print_payload(const uint8_t *pkt)
{
    int i;
    const uint8_t *start;
    uint16_t size;
    struct ip6_hdr *ip6_hdr;
/*    char addr_str[INET6_ADDRSTRLEN]; */
    char full_ip6_addr[40];

    ip6_hdr = (struct ip6_hdr *)pkt;
    start = pkt + sizeof(struct ip6_hdr);
    size = ntohs(ip6_hdr->ip6_plen);
    for(i = 0; i < size; i++)
    {
        if(i != 0 && i % 16 == 0)
        {
            printf("\n");
        }
        printf("%02x ", *(start + i));
    }
    printf("\n\n");

    if(is_node_information_reply(pkt))
    {
        int step;
        uint16_t ip6_len = ntohs(ip6_hdr->ip6_plen);
        const uint8_t *cur_pos;
        const uint8_t *end_pos = pkt + sizeof(struct ip6_hdr) + ip6_len;
        const uint8_t *addr_bin 
            = pkt
            + sizeof(struct ip6_hdr)   /* IPv6 header */
            + sizeof(uint8_t)          /* Type */
            + sizeof(uint8_t)          /* Code */
            + sizeof(uint16_t)         /* Checksum */
            + sizeof(uint16_t)         /* QType */
            + sizeof(uint16_t)         /* Flags */
            + sizeof(uint64_t);        /* Nonce */
/*
        inet_ntop(AF_INET6, addr_bin, addr_str, sizeof addr_str);
        printf("Src: %s\n", addr_str);
*/
        step = sizeof(struct nd_node_addr); /* TTL + IP6v address size. */
        cur_pos = addr_bin;
        while(cur_pos < end_pos)
        {
            const struct nd_node_addr *nd_node_addr = (struct nd_node_addr *)cur_pos;
            full_format_ip6_addr(full_ip6_addr, nd_node_addr->ip6_addr);
            printf("Src : 0x%08X %s\n", ntohl(nd_node_addr->ttl), full_ip6_addr);
            cur_pos += step;
        }

        printf("\n");
    }
    else if(is_node_information_query(pkt))
    {
        int step;
        uint16_t ip6_len = ntohs(ip6_hdr->ip6_plen);
        const uint8_t *cur_pos;
        const uint8_t *end_pos = pkt + sizeof(struct ip6_hdr) + ip6_len;
        const uint8_t *addr_bin 
            = pkt
            + sizeof(struct ip6_hdr)   /* IPv6 header */
            + sizeof(uint8_t)          /* Type */
            + sizeof(uint8_t)          /* Code */
            + sizeof(uint16_t)         /* Checksum */
            + sizeof(uint16_t)         /* QType */
            + sizeof(uint16_t)         /* Flags */
            + sizeof(uint64_t);        /* Nonce */

        step = sizeof(struct in6_addr); /* IP6v address size. */
        cur_pos = addr_bin;
        while(cur_pos < end_pos)
        {
            const uint8_t *ip6_addr = (uint8_t *)cur_pos;
            full_format_ip6_addr(full_ip6_addr, ip6_addr);
            printf("Dest: %s\n", full_ip6_addr);
            cur_pos += step;
        }

        printf("\n");
    }
}

static void print_nd_information_reply(const uint8_t *data)
{
    const struct ip6_hdr *ip6_hdr;
    int step;
    uint16_t ip6_len;
    const uint8_t *cur_pos;
    const uint8_t *end_pos;
    const uint8_t *addr_bin; 
    char full_ip6_addr[40];

    ip6_hdr   = (struct ip6_hdr *)(data + sizeof(struct ether_header));
    ip6_len = ntohs(ip6_hdr->ip6_plen);
    end_pos = (uint8_t *)ip6_hdr + sizeof(struct ip6_hdr) + ip6_len;
    addr_bin= (uint8_t *)ip6_hdr 
            + sizeof(struct ip6_hdr)   /* IPv6 header */
            + sizeof(uint8_t)          /* Type */
            + sizeof(uint8_t)          /* Code */
            + sizeof(uint16_t)         /* Checksum */
            + sizeof(uint16_t)         /* QType */
            + sizeof(uint16_t)         /* Flags */
            + sizeof(uint64_t);        /* Nonce */

    step = sizeof(struct nd_node_addr); /* TTL + IP6v address size. */
    cur_pos = addr_bin;
    while(cur_pos < end_pos)
    {
        const struct nd_node_addr *nd_node_addr = (struct nd_node_addr *)cur_pos;
        full_format_ip6_addr(full_ip6_addr, nd_node_addr->ip6_addr);
        printf("%d: Src : 0x%08X %s\n", g_packets_captured, ntohl(nd_node_addr->ttl), full_ip6_addr);
        cur_pos += step;
    }

}

/*
 * user : pass a user argument
 * h    : the packet time stamp and lengths
 * data: data from packet
 * struct pcap_pkthdr {
 *     struct timeval ts;  time stamp
 *     bpf_u_int32 caplen; length of portion present actually captured.
 *     bpf_u_int32 len;    length of the packet off the wire.
 * };
 */
void print_packet(uint8_t *user, const struct pcap_pkthdr *h, const uint8_t *data)
{
    const char *fmt = "%02d:%02d:%02d.%06u";
    char tsbuf[TS_BUF_SIZE];
    register long sec;
    register long usec = h->ts.tv_usec;
    int   ip_ver;
    const char *proto;
    const char *icmp6_type;
    const struct ip6_hdr *ip6_hdr;
    const struct icmp6_hdr *icmp6_hdr;
    int is_icmp6_pkt;
    int is_nd_information_reply = user[0];

    ++g_packets_captured;

    if(h->caplen != h->len)
    {
        fprintf(stderr, "h->caplen (%d) != h->len (%d). Currently not supported.\n",
                h->caplen, h->len);
        return;
    }

    ip6_hdr   = (struct ip6_hdr *)(data + sizeof(struct ether_header));
    icmp6_hdr = (struct icmp6_hdr *)(data + sizeof(struct ether_header) + sizeof(struct ip6_hdr));

    sec = (h->ts.tv_sec + g_timezone_offset) % 86400;
    sprintf(tsbuf, fmt, sec / 3600, (sec % 3600) / 60, sec % 60, usec);

    ip_ver = is_ipv6((const uint8_t *)ip6_hdr) ? 6 : 4;
    is_icmp6_pkt = is_icmp6((const uint8_t *)ip6_hdr);
    proto = is_icmp6_pkt ? "ICMPv6" : "Other";
    icmp6_type = icmp6_type_name(icmp6_hdr->icmp6_type);

    if(is_nd_information_reply)
    {
        if(is_node_information_reply((uint8_t *)ip6_hdr))
        {
            print_nd_information_reply(data);
        }
        return;
    }

    printf("[[[ PACKET ]]]\n");
    printf("%s: %s %s (caplen: %d)\n", tsbuf, proto, icmp6_type, h->caplen);

    if(ip_ver == 6)
    {
        printf("===== IPv6 =====\n");
        print_ip6_header((uint8_t *)ip6_hdr);
        if(is_icmp6_pkt)
        {
            printf("----- ICMPv6 -----\n");
            print_icmp6_header((uint8_t *)ip6_hdr);
        }
        printf("----- Payload -----\n");
        print_payload((uint8_t *)ip6_hdr);
    }
    printf("\n");
}

