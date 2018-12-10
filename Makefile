SHELL = /bin/sh
OBJS = pcap.o print_packet.o tz_offset.o checksum.o
DEST = /usr/local2/bin
EXE = pcap

all: $(EXE)

pcap: $(OBJS)
	gcc -o $(EXE) -lpcap $(OBJS)

.c.o:
	gcc -Wall -o $@ -c $<

install:
	install -o root -g root -m 4755 $(EXE) $(DEST)

uninstall:
	test -e $(DEST)/$(EXE) && rm $(DEST)/$(EXE)

clean:
	rm -f *~
	rm -f pcap $(OBJS)
