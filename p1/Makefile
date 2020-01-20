CC = gcc
CFLAGS = -g -Wall 

all:  trace

trace: trace.c
	$(CC) $(CFLAGS) -o trace trace.c checksum.c ethernet.c arp.c ip.c tcp.c udp.c icmp.c -lpcap 

clean:
	rm -f trace

c: clean trace
