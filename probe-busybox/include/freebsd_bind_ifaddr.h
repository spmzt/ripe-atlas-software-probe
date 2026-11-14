/*
 * Copyright (c) 2026 RIPE NCC <atlas@ripe.net>
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 *
 * FreeBSD has no SO_BINDTODEVICE.  bind_ifaddr() binds a socket to an
 * address of the interface instead.  This fixes the source address only:
 * the kernel still picks the outgoing interface from the routing table.
 *
 * Used by libbb's bind_interface() and by evdns in the bundled libevent,
 * so it only depends on libc.
 */
#ifndef FREEBSD_BIND_IFADDR_H
#define FREEBSD_BIND_IFADDR_H

#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <ifaddrs.h>
#include <string.h>
#include <net/if.h>
#include <netinet/in.h>

/*
 * Bind socket s to an address of family af on interface ifname.  IPv6
 * link-local addresses are only tried when no other address can be
 * bound, and get the interface as their scope.
 *
 * Returns 0, or -1 with errno set: ENXIO if there is no such interface,
 * EADDRNOTAVAIL if it has no address of that family, otherwise the error
 * of the last bind() tried.
 */
static int bind_ifaddr(int s, int af, const char *ifname)
{
	struct ifaddrs *ifap, *ifa;
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;
	unsigned int ifindex;
	int linklocal, found, r;

	ifindex= if_nametoindex(ifname);
	if (ifindex == 0)
	{
		errno= ENXIO;
		return -1;
	}
	if (getifaddrs(&ifap) == -1)
		return -1;

	found= 0;
	r= -1;
	for (linklocal= 0; r == -1 && linklocal <= 1; linklocal++)
	{
		for (ifa= ifap; r == -1 && ifa != NULL; ifa= ifa->ifa_next)
		{
			if (ifa->ifa_addr == NULL ||
				ifa->ifa_addr->sa_family != af ||
				strcmp(ifa->ifa_name, ifname) != 0)
			{
				continue;
			}
			if (af == AF_INET)
			{
				if (linklocal)
					continue;
				found= 1;
				memcpy(&sin, ifa->ifa_addr, sizeof(sin));
				sin.sin_port= 0;
				r= bind(s, (struct sockaddr *)&sin,
					sizeof(sin));
				continue;
			}
			memcpy(&sin6, ifa->ifa_addr, sizeof(sin6));
			if (!IN6_IS_ADDR_LINKLOCAL(&sin6.sin6_addr) != !linklocal)
				continue;
			found= 1;
			sin6.sin6_port= 0;
			sin6.sin6_flowinfo= 0;
			if (linklocal)
			{
				/* Clear the KAME embedded scope */
				sin6.sin6_addr.s6_addr[2]= 0;
				sin6.sin6_addr.s6_addr[3]= 0;
				sin6.sin6_scope_id= ifindex;
			}
			r= bind(s, (struct sockaddr *)&sin6, sizeof(sin6));
		}
	}
	freeifaddrs(ifap);

	if (!found)
		errno= EADDRNOTAVAIL;
	return r;
}

#endif /* FREEBSD_BIND_IFADDR_H */
