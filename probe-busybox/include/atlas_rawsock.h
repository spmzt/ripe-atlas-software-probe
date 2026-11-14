/*
 * Copyright (c) 2026 RIPE NCC <atlas@ripe.net>
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 *
 * Raw sockets of the measurement code.
 *
 * Every raw socket the measurement code opens is created through these, so
 * that a system without file capabilities can hand them out another way.
 * Except on FreeBSD, atlas_rawsocket(af, proto) is socket(af, SOCK_RAW,
 * proto) and xatlas_rawsocket(af, proto) is xsocket(af, SOCK_RAW, proto).
 */
#ifndef ATLAS_RAWSOCK_H
#define ATLAS_RAWSOCK_H

#ifdef __FreeBSD__
/* FreeBSD has no file capabilities.  busybox is setuid root and, for the
 * applets that need raw sockets, forks a broker that keeps root while the
 * applet drops to the measurement user.  These then ask the broker; see
 * freebsd_rawsock.c.
 */
#include <sys/types.h>

extern int atlas_rawsocket(int af, int proto);
extern int xatlas_rawsocket(int af, int proto);

/* Raw sockets the applet may get from the broker, 0 for none */
extern unsigned freebsd_rawsock_mask(int applet_no);

/* Run as setuid root before the applet: start a broker if mask is not 0,
 * then drop effective and saved ids to uid and gid for good, keeping the
 * real ids of the caller.  Dies on failure.
 */
extern void freebsd_privsep(unsigned mask, uid_t uid, gid_t gid);
#else
#define atlas_rawsocket(af, proto)	socket(af, SOCK_RAW, proto)
#define xatlas_rawsocket(af, proto)	xsocket(af, SOCK_RAW, proto)
#endif

#endif /* ATLAS_RAWSOCK_H */
