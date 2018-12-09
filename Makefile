OBJS = pcap.o print_packet.o tz_offset.o checksum.o

all: pcap

pcap: $(OBJS)
	gcc -o pcap -lpcap $(OBJS)

.c.o:
	gcc -Wall -o $@ -c $<

clean:
	rm -f *~
	rm -f pcap $(OBJS)
