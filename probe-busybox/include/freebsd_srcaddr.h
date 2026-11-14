/*
 * Copyright (c) 2026 RIPE NCC <atlas@ripe.net>
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 *
 * On Linux, connect() on a raw socket selects the source address that
 * getsockname() then reports.  FreeBSD does that for IPv6 but not for
 * IPv4, where getsockname() keeps returning 0.0.0.0.
 */
#ifndef FREEBSD_SRCADDR_H
#define FREEBSD_SRCADDR_H

#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>

/*
 * If loc, the address of a raw socket connected to dst, is 0.0.0.0,
 * replace it with the source address that a UDP socket connected to dst
 * gets.  Leaves loc alone if that fails.
 */
static inline void freebsd_raw_srcaddr(const struct sockaddr *dst,
	socklen_t dstlen, void *loc, socklen_t *loclen)
{
	int s;
	socklen_t len;
	struct sockaddr_in sin, *locp;

	locp= loc;
	if (dst->sa_family != AF_INET || dstlen < sizeof(sin) ||
		locp->sin_addr.s_addr != INADDR_ANY)
	{
		return;
	}

	s= socket(AF_INET, SOCK_DGRAM, 0);
	if (s == -1)
		return;
	memcpy(&sin, dst, sizeof(sin));
	sin.sin_port= htons(9);	/* Any port, nothing is sent */
	len= sizeof(sin);
	if (connect(s, (struct sockaddr *)&sin, sizeof(sin)) == 0 &&
		getsockname(s, (struct sockaddr *)&sin, &len) == 0)
	{
		locp->sin_addr= sin.sin_addr;
		*loclen= sizeof(sin);
	}
	close(s);
}

#endif /* FREEBSD_SRCADDR_H */
