/* vi: set sw=2 ts=2: 
 *
 * 2010-2013  Copyright (c) 2013 RIPE NCC <atlas@ripe.net> 
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 * read /cat/proc/buddyinfo and print out.
 * if env variable LOWMEM_REBOOT is set KBytes same as buddyinfo reboot
 *
 */
//config:config BUDDYINFO
//config:       bool "buddyinfo"
//config:       default n
//config:       help
//config:         buddyinfo reports on the amount of free memory

//applet:IF_CONDMV(APPLET(buddyinfo, BB_DIR_ROOT, BB_SUID_DROP))

//kbuild:lib-$(CONFIG_BUDDYINFO) += buddyinfo.o

//usage:#define buddyinfo_trivial_usage
//usage:       ""
//usage:#define buddyinfo_full_usage "\n\n"
//usage:       ""

#include "libbb.h"

#ifdef __FreeBSD__
#include <sys/sysctl.h>
#include "freebsd_sysinfo.h"
#else
#include <sys/sysinfo.h>
#endif

#define DBQ(str) "\"" #str "\""

/* This is a NOFORK applet. Be very careful! */

int buddyinfo_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
#ifdef __FreeBSD__
/*
 * FreeBSD has no /proc/buddyinfo.  Report the free memory in KB as
 * freemem, with an empty buddyinfo list.  The check for a free block of at
 * least lowmem KB becomes a check for lowmem KB of free memory.
 */
int buddyinfo_main(int argc UNUSED_PARAM, char **argv)
{
	char *lowmemChar;
	unsigned lowmem = 0;
	char *my_mac ;
	u_int free_count, page_size;
	size_t len;
	unsigned long freeMem;
	struct sysinfo info; 

	lowmemChar =  argv[1];

	if(lowmemChar) 
		lowmem = xatou(lowmemChar);

	len = sizeof(free_count);
	if (sysctlbyname("vm.stats.vm.v_free_count", &free_count, &len,
		NULL, 0) == -1)
	{
		bb_perror_msg("vm.stats.vm.v_free_count");
		return (EXIT_FAILURE);
	}
	len = sizeof(page_size);
	if (sysctlbyname("vm.stats.vm.v_page_size", &page_size, &len,
		NULL, 0) == -1)
	{
		bb_perror_msg("vm.stats.vm.v_page_size");
		return (EXIT_FAILURE);
	}
	freeMem = (unsigned long)free_count * (page_size / 1024);

        my_mac = getenv("ETHER_SCANNED");

        printf ("RESULT { " DBQ(id) ": " DBQ(9001) ", " DBQ(time) ": %lld",
		(long long)time(0));
	if (my_mac !=  NULL)
		printf(", " DBQ(macaddr) ": " DBQ(%s), my_mac);

	/* get uptime and print it */
	sysinfo(&info);
 	printf (", " DBQ(uptime) ": %ld", info.uptime );

	printf (", " DBQ(buddyinfo) ": [ ], " DBQ(freemem) ": %lu }\n",
		freeMem);

	if (lowmem >= 4 && freeMem < lowmem)
	{
		fprintf(stderr, "buddyinfo: less than %u KB free\n", lowmem);
		return (EXIT_FAILURE);
	}
	return 0;
}
#else
int buddyinfo_main(int argc UNUSED_PARAM, char **argv)
{
	char *lowmemChar;
	unsigned lowmem = 0;
	FILE *fp = xfopen_for_read("/proc/buddyinfo");
	char aa[10];
	char *my_mac ;
	int i = 0;
	int j = 0;
	int memBlock = 4;
	int need_reboot = 0; // don't reboot 
	int freeMem = 0;
	int jMax = 64; // enough
	struct sysinfo info; 

	lowmemChar =  argv[1];

	if(lowmemChar) 
		lowmem = xatou(lowmemChar);
        fscanf(fp, "%s", aa); 
        fscanf(fp, "%s", aa);
        fscanf(fp, "%s", aa);
        fscanf(fp, "%s", aa);

        my_mac = getenv("ETHER_SCANNED");

	if (lowmem >= 4 ) 
	{
		/* We need to reboot unless we find a big enough chunk
		 * of memory.
		 */
		need_reboot = 1;
	}
        printf ("RESULT { " DBQ(id) ": " DBQ(9001) ", " DBQ(time) ": %lld",
		(long long)time(0));
	if (my_mac !=  NULL)
		printf(", " DBQ(macaddr) ": " DBQ(%s), my_mac);

	/* get uptime and print it */
	sysinfo(&info);
 	printf (", " DBQ(uptime) ": %ld", info.uptime );
	
	printf(", " DBQ(buddyinfo) ": [ ");
        for (j=0; j < jMax; j++)  
        {
                if (fscanf(fp, "%d", &i) != 1)
			break;
		printf("%s%d", j == 0 ? "" : ", ", i);
		freeMem += ( memBlock * i);
		if (i > 0 && lowmem >= 4 && memBlock >= lowmem)
		{
			/* Found a big enough chunk */
			need_reboot = 0;
		}
		memBlock  *= 2; 
        }

	/* now print it */
	printf (" ], " DBQ(freemem) ": %d }\n" ,  freeMem);

	fclose (fp);

	if(need_reboot)
	{
		fprintf(stderr, "buddyinfo: nothing found for size %d\n", lowmem);
		return (EXIT_FAILURE);
	}
	return 0;
}
#endif
