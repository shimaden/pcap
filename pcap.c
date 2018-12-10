#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap/pcap.h>
#include "tz_offset.h"
#include "print_packet.h"

#define TS_BUF_SIZE sizeof("0000000000.000000000")


static void usage(const char *cmd)
{
    printf("Usage: %s [option] <iface>\n"
           "  ND_INFORMATION_REPLY\n"
           "  Ex) %s eth0\n", cmd, cmd);
}

int main(int argc, char *argv[])
{
    const char *device;
    uint8_t is_nd_information_reply;
    const char cmdbuf[] = "icmp6";
    bpf_u_int32 netmask = 0;
    int oflag = 1;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap;
    struct bpf_program fcode;
    int result;
    int snapshot_len;
    int link_layer_header_type;
    uint8_t user[32]; /* Maybe enough size for now. */
    int cnt = -1; /* infinity */

    switch(argc)
    {
        case 2:
            device = argv[1];
            is_nd_information_reply = 0;     /* ND_INFORMATION_REPLY */
            break;
        case 3:
            is_nd_information_reply = strcmp(argv[1], "ND_INFORMATION_REPLY") == 0;
            device = argv[2];
            break;
        default:
            usage(argv[0]);
            return EXIT_FAILURE;
    }

    g_timezone_offset = tz_offset();

    pcap = pcap_create(device, errbuf);

    if(pcap == NULL)
    {
        fprintf(stderr, "error: %s\n", errbuf);
    }

    result = pcap_activate(pcap);
    if(result == 0)
    {
        fprintf(stderr, "pcap_activate: success\n");
    }
    else if(result > 0 )
    {
        fprintf(stderr, "pcap_activate: success with warnings\n");
        pcap_perror(pcap, "pcap_activate");
    }
    else
    {
        fprintf(stderr, "pcap_activate: failure\n");
        pcap_perror(pcap, "pcap_activate");
        return EXIT_FAILURE;
    }

    snapshot_len = pcap_snapshot(pcap);
    fprintf(stderr, "snapshot len: %d\n", snapshot_len);
    if(snapshot_len == PCAP_ERROR_NOT_ACTIVATED)
    {
        pcap_perror(pcap, "pcap_snapshot");
        return EXIT_FAILURE;
    }

    result = pcap_compile(pcap, &fcode, cmdbuf, oflag, netmask);
    if(result != 0)
    {
        pcap_perror(pcap, "pcap_compile");
        return EXIT_FAILURE;
    }

    result = pcap_setfilter(pcap, &fcode);
    if(result != 0)
    {
        pcap_perror(pcap, "pcap_setfilter");
        return EXIT_FAILURE;
    }

    link_layer_header_type = pcap_datalink(pcap);
    if(result == PCAP_ERROR_NOT_ACTIVATED)
    {
        pcap_perror(pcap, "pcap_datalink");
        return EXIT_FAILURE;
    }
    fprintf(stderr, "Link layer header type: %d\n", link_layer_header_type);

    user[0] = is_nd_information_reply;

    result = pcap_loop(pcap, cnt, print_packet, user);
    fprintf(stderr, "pcap_loop() exited with status %d\n.", result);
    if(result != 0)
    {
        pcap_perror(pcap, "pcap_datalink");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
