/*
 * Copyright (c) 2026 RIPE NCC <atlas@ripe.net>
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 *
 * FreeBSD does not pass TCP segments to raw sockets, so a TCP traceroute
 * cannot receive the replies of the destination that way.  These
 * functions capture them through BPF instead: a read-only, locked BPF
 * descriptor on each interface the replies may arrive on, with a filter
 * for exactly the flow of the traceroute.
 */
#ifndef FREEBSD_TCPCAP_H
#define FREEBSD_TCPCAP_H

#include <sys/types.h>
#include <sys/socket.h>
#include <stddef.h>
#include <string.h>
#include <net/if.h>
#include <net/bpf.h>

/* Size of the BPF buffers of a capture; read() needs exactly this.  The
 * kernel keeps two per capture.  Replies are SYN-ACKs and RSTs; this
 * holds a whole frame of a 1500 byte MTU with a VLAN tag and the BPF
 * header, larger frames are truncated and dropped.
 */
#define TCPCAP_BUFSIZE	2048

/* Most interfaces a traceroute captures on.  With more candidates it
 * fails rather than miss replies on the others; -i names the one to use.
 */
#define TCPCAP_MAXIF	64

/* Source ports of TCP traceroute, the only local ports of a capture: the
 * base plus the index of the measurement.  Nothing limits the index, but
 * above 4095 it no longer fits the 12 bits the ICMP id has for it
 * (TRT_ICMP4_INSTANCE_ID_SHIFT).
 */
#define TCPCAP_SRC_BASE_PORT	20480
#define TCPCAP_SRC_PORTS	4096

/* A flow to capture: TCP segments from raddr/rport to laddr/lport */
struct tcpcap_flow
{
	int32_t af;			/* AF_INET or AF_INET6 */
	uint8_t laddr[16];		/* Local address, 4 bytes for IPv4 */
	uint8_t raddr[16];		/* Remote address */
	uint16_t lport;			/* Network byte order */
	uint16_t rport;			/* Network byte order */
};

/* The interfaces to capture on: n names, each nul-terminated, no two the
 * same
 */
struct tcpcap_ifs
{
	uint32_t n;
	char name[TCPCAP_MAXIF][IFNAMSIZ];
};

/* Open the captures for TCP segments from remote to local.  tcpfd is a
 * TCP socket bound to local, a TCP traceroute source port that no TCP
 * socket of another user uses; it proves that the caller owns that
 * address and port and has to stay open while the captures are in use.
 * ifname names the one interface to capture on, or is NULL or an address
 * for all that the replies may arrive on.  fds and dlts have room for
 * TCPCAP_MAXIF descriptors and their link types.  Returns the number of
 * captures, or -1 with errno set (EPROTONOSUPPORT for a link type we
 * cannot parse, E2BIG for more than TCPCAP_MAXIF interfaces, ENETDOWN for
 * none).
 */
extern int freebsd_tcp_capture(const struct sockaddr *local,
	const struct sockaddr *remote, int tcpfd, const char *ifname,
	int *fds, unsigned *dlts);

/* Open the captures for flow on the interfaces in ifs, see
 * freebsd_tcp_capture.  Interfaces with a link type we cannot parse are
 * left out.  bpf is the path of the BPF device.  Run by the raw socket
 * broker, chrooted to /dev, or by freebsd_tcp_capture without one.
 * Returns 0 and the number of captures in np, or an errno value.
 */
extern int tcpcap_open(const char *bpf, const struct tcpcap_flow *flow,
	const struct tcpcap_ifs *ifs, int tcpfd, int *fds, unsigned *dlts,
	int *np);

/* Have the raw socket broker open the captures for flow, in one request.
 * Returns 0 or an errno value, or -1 if there is no broker.
 */
extern int freebsd_broker_tcpcap(const struct tcpcap_flow *flow,
	const struct tcpcap_ifs *ifs, int tcpfd, int *fds, unsigned *dlts,
	int *np);

/* Step through the packets of one read() of a capture: *pp starts at the
 * buffer, end is where the data read ends.  Returns the next frame, with
 * its BPF header in bh, and advances *pp; NULL when there is no complete
 * packet left.  The kernel does not pad the last packet to a word, so the
 * word-aligned advance after it can go past end.
 */
#define TCPCAP_HDR_MIN	(offsetof(struct bpf_hdr, bh_hdrlen) + \
			 sizeof(((struct bpf_hdr *)0)->bh_hdrlen))

static inline const unsigned char *tcpcap_next(const unsigned char **pp,
	const unsigned char *end, struct bpf_hdr *bh)
{
	const unsigned char *p;

	p= *pp;
	if (p >= end || (size_t)(end - p) < TCPCAP_HDR_MIN)
		return NULL;
	/* bh_hdrlen does not count the tail padding of the struct */
	memset(bh, '\0', sizeof(*bh));
	memcpy(bh, p, TCPCAP_HDR_MIN);
	if (bh->bh_hdrlen < TCPCAP_HDR_MIN ||
		(size_t)(end - p) < bh->bh_hdrlen ||
		(size_t)(end - p) - bh->bh_hdrlen < bh->bh_caplen)
	{
		return NULL;
	}
	*pp= p + BPF_WORDALIGN(bh->bh_hdrlen + bh->bh_caplen);
	return p + bh->bh_hdrlen;
}

/* Find the IP packet in a captured frame of link type dlt.  Returns
 * AF_INET or AF_INET6, points ipp at the packet and sets lenp to its IP
 * length (without link layer padding).  Returns -1 for anything else.
 */
extern int tcpcap_ip(unsigned dlt, const unsigned char *frame,
	size_t caplen, const unsigned char **ipp, size_t *lenp);

#endif /* FREEBSD_TCPCAP_H */
