/*
 * Copyright (c) 2026 RIPE NCC <atlas@ripe.net>
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 *
 * FreeBSD has no sysinfo().  The applets only use its uptime.
 */
#ifndef FREEBSD_SYSINFO_H
#define FREEBSD_SYSINFO_H

#include <time.h>

struct sysinfo
{
	long uptime;	/* Seconds since boot */
};

static inline int sysinfo(struct sysinfo *info)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_UPTIME, &ts) == -1)
		return -1;
	info->uptime= ts.tv_sec;
	return 0;
}

#endif /* FREEBSD_SYSINFO_H */
