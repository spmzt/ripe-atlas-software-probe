/*
 * Copyright (c) 2014 RIPE NCC <atlas@ripe.net>
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 */

#include "libbb.h"

#ifdef __FreeBSD__
#include "freebsd_bind_ifaddr.h"

/*
 * FreeBSD has no SO_BINDTODEVICE (see freebsd_bind_ifaddr.h), and its
 * bind() wants the exact length of the address.
 */
int bind_interface(int socket, int af, char *name)
{
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;

	if (af == AF_INET)
	{
		memset(&sin, '\0', sizeof(sin));
		sin.sin_family= AF_INET;
		if (inet_pton(af, name, &sin.sin_addr) == 1)
		{
			return bind(socket, (struct sockaddr *)&sin,
				sizeof(sin));
		}
	}
	else
	{
		memset(&sin6, '\0', sizeof(sin6));
		sin6.sin6_family= AF_INET6;
		if (inet_pton(af, name, &sin6.sin6_addr) == 1)
		{
			return bind(socket, (struct sockaddr *)&sin6,
				sizeof(sin6));
		}
	}

	return bind_ifaddr(socket, af, name);
}
#else
int bind_interface(int socket, int af, char *name)
{
	struct sockaddr_storage sa;

	memset(&sa, '\0', sizeof(sa));

	if (af == AF_INET)
	{
		sa.ss_family= AF_INET;
		if (inet_pton(af, name,
			&((struct sockaddr_in *)&sa)->sin_addr) == 1)
		{
			return bind(socket, (struct sockaddr *)&sa,
				sizeof(sa));
		}
	}
	else
	{
		sa.ss_family= AF_INET6;
		if (inet_pton(af, name,
			&((struct sockaddr_in6 *)&sa)->sin6_addr) == 1)
		{
			return bind(socket, (struct sockaddr *)&sa,
				sizeof(sa));
		}
	}
	if (setsockopt(socket, SOL_SOCKET, SO_BINDTODEVICE, name,
		strlen(name)+1) == -1)
	{
		return -1;
	}

	return 0;
}

#endif
