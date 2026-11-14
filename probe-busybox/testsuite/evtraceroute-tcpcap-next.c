/*
 * Copyright (c) 2026 RIPE NCC <atlas@ripe.net>
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 *
 * FreeBSD: tcpcap_next(), the walk through the packets of one read() of a
 * BPF capture of TCP traceroute.  The reads go to one static buffer, as
 * in ready_tcp_bpf(), and the kernel does not pad the last packet of a
 * read to a word.  Prints the number of packets found in each read.
 */

#include <stdio.h>
#include <stdint.h>
#include "freebsd_tcpcap.h"

static unsigned char buf[4096];

/* Store a packet with caplen bytes at off, return the offset after it,
 * unpadded
 */
static size_t put(size_t off, unsigned caplen)
{
	struct bpf_hdr bh;

	memset(&bh, '\0', sizeof(bh));
	bh.bh_caplen= caplen;
	bh.bh_datalen= caplen;
	bh.bh_hdrlen= TCPCAP_HDR_MIN;
	memcpy(buf + off, &bh, TCPCAP_HDR_MIN);
	memset(buf + off + TCPCAP_HDR_MIN, 0x45, caplen);
	return off + TCPCAP_HDR_MIN + caplen;
}

static void walk(const char *what, size_t n)
{
	int count;
	const unsigned char *p;
	struct bpf_hdr bh;

	count= 0;
	p= buf;
	while (tcpcap_next(&p, buf + n, &bh) != NULL)
		count++;
	printf("%s: %d\n", what, count);
}

int main(void)
{
	size_t n;

	/* Two replies of 58 bytes in one read, the first padded */
	n= put(0, 58);
	n= put(BPF_WORDALIGN(n), 58);
	walk("two replies", n);

	/* Then one reply: the second one of the last read is still in the
	 * buffer just after the padding of this one
	 */
	n= put(0, 58);
	walk("one reply after two", n);

	/* A packet that claims more bytes than were read */
	n= put(0, 58);
	walk("truncated", n - 1);

	/* Less than a header */
	walk("short", TCPCAP_HDR_MIN - 1);
	return 0;
}
