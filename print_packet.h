#if !defined(PRINT_PACKET__)
#define PRINT_PACKET__

#include <nettle/nettle-stdint.h>
#include <pcap/pcap.h>

extern int g_timezone_offset;

extern void print_packet(uint8_t *user, const struct pcap_pkthdr *h, const uint8_t *bytes);

#endif
