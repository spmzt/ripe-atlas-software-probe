/*
 * Copyright (c) 2026 RIPE NCC <atlas@ripe.net>
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 *
 * BPF capture of the replies to a TCP traceroute on FreeBSD, see
 * freebsd_tcpcap.h.
 */

#include "libbb.h"
#include "freebsd_tcpcap.h"

#include <sys/capsicum.h>
#include <sys/ioctl.h>
#include <sys/socketvar.h>
#include <sys/sysctl.h>
#include <ifaddrs.h>
#include <net/bpf.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/in_pcb.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp_var.h>

/* BPF program builder.  Tests that fail jump to the final "ret 0". */
#define FB_MAX		64
#define FB_REJECT	0xff	/* jt/jf placeholder: jump to reject */

struct fbuild
{
	struct bpf_insn insn[FB_MAX];
	int n;
};

static void fb_stmt(struct fbuild *fb, u_short code, bpf_u_int32 k)
{
	if (fb->n < FB_MAX)
	{
		struct bpf_insn i= BPF_STMT(code, k);
		fb->insn[fb->n]= i;
	}
	fb->n++;
}

static void fb_jump(struct fbuild *fb, u_short code, bpf_u_int32 k,
	u_char jt, u_char jf)
{
	if (fb->n < FB_MAX)
	{
		struct bpf_insn i= BPF_JUMP(code, k, jt, jf);
		fb->insn[fb->n]= i;
	}
	fb->n++;
}

/* Fall through if A == k, else reject */
static void fb_eq(struct fbuild *fb, bpf_u_int32 k)
{
	fb_jump(fb, BPF_JMP|BPF_JEQ|BPF_K, k, 0, FB_REJECT);
}

static bpf_u_int32 fb_word(const uint8_t *p)
{
	uint32_t w;

	memcpy(&w, p, sizeof(w));
	return ntohl(w);
}

/* Match the IP header of the flow at offset b, then accept */
static void fb_ip(struct fbuild *fb, const struct tcpcap_flow *flow, u_int b)
{
	int i;

	if (flow->af == AF_INET)
	{
		fb_stmt(fb, BPF_LD|BPF_B|BPF_ABS, b);
		fb_stmt(fb, BPF_ALU|BPF_AND|BPF_K, 0xf0);
		fb_eq(fb, 0x40);
		fb_stmt(fb, BPF_LD|BPF_B|BPF_ABS, b + 9);
		fb_eq(fb, IPPROTO_TCP);
		/* No fragments other than the first */
		fb_stmt(fb, BPF_LD|BPF_H|BPF_ABS, b + 6);
		fb_jump(fb, BPF_JMP|BPF_JSET|BPF_K, 0x1fff, FB_REJECT, 0);
		fb_stmt(fb, BPF_LD|BPF_W|BPF_ABS, b + 12);
		fb_eq(fb, fb_word(flow->raddr));
		fb_stmt(fb, BPF_LD|BPF_W|BPF_ABS, b + 16);
		fb_eq(fb, fb_word(flow->laddr));
		fb_stmt(fb, BPF_LDX|BPF_B|BPF_MSH, b);
		fb_stmt(fb, BPF_LD|BPF_H|BPF_IND, b);
		fb_eq(fb, ntohs(flow->rport));
		fb_stmt(fb, BPF_LD|BPF_H|BPF_IND, b + 2);
		fb_eq(fb, ntohs(flow->lport));
	}
	else
	{
		fb_stmt(fb, BPF_LD|BPF_B|BPF_ABS, b);
		fb_stmt(fb, BPF_ALU|BPF_AND|BPF_K, 0xf0);
		fb_eq(fb, 0x60);
		/* TCP directly after the IPv6 header, no extension headers */
		fb_stmt(fb, BPF_LD|BPF_B|BPF_ABS, b + 6);
		fb_eq(fb, IPPROTO_TCP);
		for (i= 0; i < 4; i++)
		{
			fb_stmt(fb, BPF_LD|BPF_W|BPF_ABS, b + 8 + 4*i);
			fb_eq(fb, fb_word(flow->raddr + 4*i));
		}
		for (i= 0; i < 4; i++)
		{
			fb_stmt(fb, BPF_LD|BPF_W|BPF_ABS, b + 24 + 4*i);
			fb_eq(fb, fb_word(flow->laddr + 4*i));
		}
		fb_stmt(fb, BPF_LD|BPF_H|BPF_ABS, b + 40);
		fb_eq(fb, ntohs(flow->rport));
		fb_stmt(fb, BPF_LD|BPF_H|BPF_ABS, b + 42);
		fb_eq(fb, ntohs(flow->lport));
	}
	fb_stmt(fb, BPF_RET|BPF_K, (u_int)-1);
}

/* Build the filter for link type dlt.  Returns the number of instructions
 * or -1 for a link type we cannot parse.
 */
static int build_filter(unsigned dlt, const struct tcpcap_flow *flow,
	struct bpf_insn *insn)
{
	int i, untagged_jump;
	u_int ethertype;
	struct fbuild fb;

	fb.n= 0;
	ethertype= (flow->af == AF_INET ? ETHERTYPE_IP : ETHERTYPE_IPV6);
	switch (dlt)
	{
	case DLT_EN10MB:
		/* Untagged, or with one 802.1Q tag */
		fb_stmt(&fb, BPF_LD|BPF_H|BPF_ABS, 12);
		untagged_jump= fb.n;
		fb_jump(&fb, BPF_JMP|BPF_JEQ|BPF_K, ethertype, 0, 0);
		fb_eq(&fb, ETHERTYPE_VLAN);
		fb_stmt(&fb, BPF_LD|BPF_H|BPF_ABS, 16);
		fb_eq(&fb, ethertype);
		fb_ip(&fb, flow, ETHER_HDR_LEN + ETHER_VLAN_ENCAP_LEN);
		/* Untagged starts here */
		if (fb.n < FB_MAX)
			fb.insn[untagged_jump].jt= fb.n - (untagged_jump + 1);
		fb_ip(&fb, flow, ETHER_HDR_LEN);
		break;
	case DLT_NULL:
		/* Address family in host byte order */
		fb_stmt(&fb, BPF_LD|BPF_W|BPF_ABS, 0);
		fb_eq(&fb, htonl(flow->af));
		fb_ip(&fb, flow, 4);
		break;
	case DLT_LOOP:
		/* Address family in network byte order */
		fb_stmt(&fb, BPF_LD|BPF_W|BPF_ABS, 0);
		fb_eq(&fb, flow->af);
		fb_ip(&fb, flow, 4);
		break;
	case DLT_RAW:
		fb_ip(&fb, flow, 0);
		break;
	default:
		return -1;
	}
	fb_stmt(&fb, BPF_RET|BPF_K, 0);
	if (fb.n > FB_MAX)
		return -1;

	/* Point the rejecting jumps at the final instruction */
	for (i= 0; i < fb.n; i++)
	{
		if (BPF_CLASS(fb.insn[i].code) != BPF_JMP)
			continue;
		if (fb.insn[i].jt == FB_REJECT)
			fb.insn[i].jt= fb.n - 1 - (i + 1);
		if (fb.insn[i].jf == FB_REJECT)
			fb.insn[i].jf= fb.n - 1 - (i + 1);
	}
	memcpy(insn, fb.insn, fb.n * sizeof(*insn));
	return fb.n;
}

static int get_intopt(int fd, int opt, int *val)
{
	socklen_t len;

	len= sizeof(*val);
	if (getsockopt(fd, SOL_SOCKET, opt, val, &len) == -1)
		return errno;
	if (len != sizeof(*val))
		return EINVAL;
	return 0;
}

/* Check that no TCP socket of another user than the owner of tcpfd uses
 * local port lport.  Sockets without a file (TIME_WAIT) do not count.
 */
static int check_port_users(int tcpfd, uint16_t lport)
{
	int r;
	size_t len, off;
	char *buf;
	struct stat st;
	struct xinpgen *xig;
	struct xtcpcb *xt;
	static const char name[]= "net.inet.tcp.pcblist";

	if (fstat(tcpfd, &st) == -1)
		return errno;
	buf= NULL;
	do
	{
		free(buf);
		if (sysctlbyname(name, NULL, &len, NULL, 0) == -1)
			return errno;
		len += len / 8;
		buf= malloc(len);
		if (buf == NULL)
			return ENOMEM;
		r= sysctlbyname(name, buf, &len, NULL, 0);
	} while (r == -1 && errno == ENOMEM);
	if (r == -1)
		r= errno;

	/* A header, the sockets, a trailer like the header */
	xig= (struct xinpgen *)buf;
	if (r == 0 && (len < sizeof(*xig) || xig->xig_len != sizeof(*xig)))
		r= EINVAL;
	for (off= sizeof(*xig); r == 0; off += sizeof(*xt))
	{
		xig= (struct xinpgen *)(buf + off);
		xt= (struct xtcpcb *)xig;
		if (off + sizeof(*xig) > len)
			r= EINVAL;
		else if (xig->xig_len == sizeof(*xig))
			break;
		else if (xt->xt_len != sizeof(*xt) || off + sizeof(*xt) > len)
			r= EINVAL;
		else if (xt->xt_inp.inp_lport == lport &&
			xt->xt_inp.xi_socket.xso_so != 0 &&
			xt->xt_inp.xi_socket.so_uid != st.st_uid)
		{
			r= EPERM;
		}
	}
	free(buf);
	return r;
}

/* Check that tcpfd is a TCP socket bound to the local address and port of
 * the flow, that is, that the caller owns them, and that the port is one
 * TCP traceroute uses.  A successful bind() does not show that no other
 * user holds the port: the kernel compares the uid only with a socket that
 * is not connected, so with SO_REUSEPORT an unprivileged bind() can share
 * the address and port of a connection of any user.  check_port_users
 * refuses that.  SO_REUSEPORT itself is allowed: eperd and eooqd run as
 * the same user and may both trace over TCP at the same time from the
 * same source port.
 *
 * The check holds only when the capture starts: a connect() of another
 * user made later may pick the same port towards the same destination,
 * and the capture then sees the inbound half of that one connection.
 * That takes a compromised measurement process, a destination guessed in
 * advance and a port collision in the 4096 traceroute ports; we accept
 * it.  On Linux the measurement user has cap_net_raw and sees all
 * inbound TCP.
 */
static int check_owner(int tcpfd, const struct tcpcap_flow *flow)
{
	int r, v;
	unsigned i, port;
	socklen_t len;
	union
	{
		struct sockaddr sa;
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
		struct sockaddr_storage ss;
	} a;
	static const int zero_opts[]= { SO_ACCEPTCONN, SO_REUSEPORT_LB };

	port= ntohs(flow->lport);
	if (port < TCPCAP_SRC_BASE_PORT ||
		port >= TCPCAP_SRC_BASE_PORT + TCPCAP_SRC_PORTS)
	{
		return EPERM;
	}
	if ((r= get_intopt(tcpfd, SO_DOMAIN, &v)) != 0)
		return r;
	if (v != flow->af)
		return EPERM;
	if ((r= get_intopt(tcpfd, SO_TYPE, &v)) != 0)
		return r;
	if (v != SOCK_STREAM)
		return EPERM;
	if ((r= get_intopt(tcpfd, SO_PROTOCOL, &v)) != 0)
		return r;
	if (v != IPPROTO_TCP)
		return EPERM;
	for (i= 0; i < ARRAY_SIZE(zero_opts); i++)
	{
		if ((r= get_intopt(tcpfd, zero_opts[i], &v)) != 0)
			return r;
		if (v != 0)
			return EPERM;
	}

	memset(&a, '\0', sizeof(a));
	len= sizeof(a);
	if (getsockname(tcpfd, &a.sa, &len) == -1)
		return errno;
	if (a.sa.sa_family != flow->af)
		return EPERM;
	if (flow->af == AF_INET)
	{
		if (len < sizeof(a.sin) ||
			a.sin.sin_port != flow->lport ||
			memcmp(&a.sin.sin_addr, flow->laddr, 4) != 0 ||
			a.sin.sin_addr.s_addr == htonl(INADDR_ANY))
		{
			return EPERM;
		}
	}
	else
	{
		if (len < sizeof(a.sin6) ||
			a.sin6.sin6_port != flow->lport ||
			memcmp(&a.sin6.sin6_addr, flow->laddr, 16) != 0 ||
			IN6_IS_ADDR_UNSPECIFIED(&a.sin6.sin6_addr) ||
			IN6_IS_ADDR_V4MAPPED(&a.sin6.sin6_addr))
		{
			return EPERM;
		}
	}
	return check_port_users(tcpfd, flow->lport);
}

/* Is addr, of family af, a loopback address or one of the addresses of
 * the interfaces in ifap?
 */
static int local_addr(struct ifaddrs *ifap, int af, const uint8_t *addr)
{
	const void *a;
	struct ifaddrs *ifa;

	if (af == AF_INET ? IN_LOOPBACK(fb_word(addr)) :
		IN6_IS_ADDR_LOOPBACK((const struct in6_addr *)addr))
	{
		return 1;
	}
	for (ifa= ifap; ifa; ifa= ifa->ifa_next)
	{
		if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != af)
			continue;
		if (af == AF_INET)
			a= &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
		else
			a= &((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr;
		if (memcmp(a, addr, af == AF_INET ? 4 : 16) == 0)
			return 1;
	}
	return 0;
}

/* Names of the interfaces the replies of the flow may arrive on.  Replies
 * from an address of our own come over a loopback interface.  Others may
 * come back over another interface than the probes left on, so take every
 * interface that is up, not a loopback, and has an address of the family
 * of the flow; for IPv6 a link-local one is enough.  That leaves out most
 * bridge members, lagg ports and other interfaces without addresses: what
 * arrives there for us passes the bridge or lagg interface as well.  A
 * VLAN parent, or a member or port with addresses of its own, sees the
 * reply along with the interface above it; the traceroute drops such
 * copies.  In a jail without vnet getifaddrs shows only the addresses of
 * the jail, so only the interfaces that carry them are used.  An
 * interface that appears or comes up later is not captured on.  Returns
 * 0 or an errno value: E2BIG for more than TCPCAP_MAXIF interfaces,
 * ENETDOWN for none.
 */
static int capture_ifnames(const struct tcpcap_flow *flow,
	struct tcpcap_ifs *ifs)
{
	unsigned i, n;
	int r, local;
	struct ifaddrs *ifap, *ifa;

	if (getifaddrs(&ifap) == -1)
		return errno;
	local= local_addr(ifap, flow->af, flow->raddr);
	n= 0;
	r= 0;
	for (ifa= ifap; ifa && r == 0; ifa= ifa->ifa_next)
	{
		if (!(ifa->ifa_flags & IFF_UP))
			continue;
		if (local)
		{
			if (!(ifa->ifa_flags & IFF_LOOPBACK))
				continue;
		}
		else if ((ifa->ifa_flags & IFF_LOOPBACK) ||
			ifa->ifa_addr == NULL ||
			ifa->ifa_addr->sa_family != flow->af)
		{
			continue;
		}
		for (i= 0; i < n; i++)
		{
			if (strcmp(ifs->name[i], ifa->ifa_name) == 0)
				break;
		}
		if (i < n)
			continue;
		if (n >= TCPCAP_MAXIF)
			r= E2BIG;
		else
			strlcpy(ifs->name[n++], ifa->ifa_name, IFNAMSIZ);
	}
	freeifaddrs(ifap);
	if (r == 0 && n == 0)
		r= ENETDOWN;
	ifs->n= n;
	return r;
}

/* Fill in a flow from socket addresses.  Returns 0 or an errno value. */
static int tcpcap_flow(struct tcpcap_flow *flow, const struct sockaddr *local,
	const struct sockaddr *remote)
{
	memset(flow, '\0', sizeof(*flow));
	if (remote->sa_family != local->sa_family)
		return EINVAL;
	flow->af= local->sa_family;
	if (local->sa_family == AF_INET)
	{
		const struct sockaddr_in *l= (const void *)local;
		const struct sockaddr_in *f= (const void *)remote;

		memcpy(flow->laddr, &l->sin_addr, 4);
		memcpy(flow->raddr, &f->sin_addr, 4);
		flow->lport= l->sin_port;
		flow->rport= f->sin_port;
	}
	else if (local->sa_family == AF_INET6)
	{
		const struct sockaddr_in6 *l= (const void *)local;
		const struct sockaddr_in6 *f= (const void *)remote;

		memcpy(flow->laddr, &l->sin6_addr, 16);
		memcpy(flow->raddr, &f->sin6_addr, 16);
		flow->lport= l->sin6_port;
		flow->rport= f->sin6_port;
	}
	else
		return EAFNOSUPPORT;
	return 0;
}

/* Open the capture for flow on interface ifname.  Returns 0 or an errno
 * value.
 */
static int open_capture(const char *bpf, const struct tcpcap_flow *flow,
	const char *ifname, int *fdp, unsigned *dltp)
{
	int r, fd, n;
	u_int v;
	struct ifreq ifr;
	struct bpf_program prog;
	struct bpf_insn insn[FB_MAX];
	cap_rights_t rights;

	fd= open(bpf, O_RDONLY | O_CLOEXEC);
	if (fd == -1)
		return errno;

	v= TCPCAP_BUFSIZE;
	if (ioctl(fd, BIOCSBLEN, &v) == -1)
		goto err;
	memset(&ifr, '\0', sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(fd, BIOCSETIF, &ifr) == -1)
		goto err;
	if (ioctl(fd, BIOCGDLT, &v) == -1)
		goto err;
	*dltp= v;
	n= build_filter(v, flow, insn);
	if (n < 0)
	{
		close(fd);
		return EPROTONOSUPPORT;
	}
	prog.bf_len= n;
	prog.bf_insns= insn;
	/* Setting the filter also drops what was captured so far */
	if (ioctl(fd, BIOCSETF, &prog) == -1)
		goto err;
	v= BPF_D_IN;
	if (ioctl(fd, BIOCSDIRECTION, &v) == -1)
		goto err;
	v= 1;
	if (ioctl(fd, BIOCIMMEDIATE, &v) == -1)
		goto err;
	if (ioctl(fd, BIOCGBLEN, &v) == -1)
		goto err;
	if (v != TCPCAP_BUFSIZE)
	{
		close(fd);
		return ENOBUFS;
	}
	if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1)
		goto err;
	if (ioctl(fd, BIOCFLUSH) == -1)
		goto err;
	/* No more changes to interface, filter, direction or promiscuity */
	if (ioctl(fd, BIOCLOCK) == -1)
		goto err;
	/* Reading and polling is all the traceroute needs */
	cap_rights_init(&rights, CAP_READ, CAP_EVENT, CAP_FSTAT);
	if (cap_rights_limit(fd, &rights) == -1 && errno != ENOSYS)
		goto err;

	*fdp= fd;
	return 0;

err:
	r= errno;
	close(fd);
	return r;
}

int tcpcap_open(const char *bpf, const struct tcpcap_flow *flow,
	const struct tcpcap_ifs *ifs, int tcpfd, int *fds, unsigned *dlts,
	int *np)
{
	unsigned i, j;
	int r, n;

	if (flow->af != AF_INET && flow->af != AF_INET6)
		return EAFNOSUPPORT;
	if (ifs->n == 0 || ifs->n > TCPCAP_MAXIF)
		return EINVAL;
	for (i= 0; i < ifs->n; i++)
	{
		if (memchr(ifs->name[i], '\0', IFNAMSIZ) == NULL ||
			ifs->name[i][0] == '\0')
		{
			return EINVAL;
		}
		for (j= 0; j < i; j++)
		{
			if (strcmp(ifs->name[i], ifs->name[j]) == 0)
				return EINVAL;
		}
	}

	r= check_owner(tcpfd, flow);
	if (r != 0)
		return r;

	n= 0;
	for (i= 0; r == 0 && i < ifs->n; i++)
	{
		r= open_capture(bpf, flow, ifs->name[i], &fds[n], &dlts[n]);
		/* Leave out a link type we cannot parse */
		if (r == 0)
			n++;
		else if (r == EPROTONOSUPPORT)
			r= 0;
	}
	if (r == 0 && n == 0)
		r= EPROTONOSUPPORT;
	if (r != 0)
	{
		while (n > 0)
			close(fds[--n]);
		return r;
	}
	*np= n;
	return 0;
}

int freebsd_tcp_capture(const struct sockaddr *local,
	const struct sockaddr *remote, int tcpfd, const char *ifname,
	int *fds, unsigned *dlts)
{
	int n, r;
	struct tcpcap_flow flow;
	struct tcpcap_ifs ifs;
	uint8_t addr[16];

	memset(&ifs, '\0', sizeof(ifs));
	r= tcpcap_flow(&flow, local, remote);
	/* -i with an address, which bind_interface accepts as well, only
	 * sets the local address of the flow.  As a raw socket bound to an
	 * address on Linux, capture what comes to it on any interface.
	 */
	if (ifname && inet_pton(flow.af, ifname, addr) == 1)
		ifname= NULL;
	if (r == 0 && ifname)
	{
		ifs.n= 1;
		if (strlcpy(ifs.name[0], ifname, IFNAMSIZ) >= IFNAMSIZ)
			r= ENAMETOOLONG;
	}
	else if (r == 0)
		r= capture_ifnames(&flow, &ifs);

	/* The broker opens them if the applet dropped root, else we try
	 * ourselves (root, or failing like raw sockets do)
	 */
	n= 0;
	if (r == 0)
		r= freebsd_broker_tcpcap(&flow, &ifs, tcpfd, fds, dlts, &n);
	if (r == -1)
		r= tcpcap_open("/dev/bpf", &flow, &ifs, tcpfd, fds, dlts, &n);
	if (r != 0)
	{
		errno= r;
		return -1;
	}
	return n;
}

int tcpcap_ip(unsigned dlt, const unsigned char *frame, size_t caplen,
	const unsigned char **ipp, size_t *lenp)
{
	int af;
	size_t off, len;
	uint16_t type;
	uint32_t fam;

	switch (dlt)
	{
	case DLT_EN10MB:
		if (caplen < ETHER_HDR_LEN)
			return -1;
		off= ETHER_HDR_LEN;
		type= (frame[12] << 8) | frame[13];
		if (type == ETHERTYPE_VLAN)
		{
			off += ETHER_VLAN_ENCAP_LEN;
			if (caplen < off)
				return -1;
			type= (frame[16] << 8) | frame[17];
		}
		if (type == ETHERTYPE_IP)
			af= AF_INET;
		else if (type == ETHERTYPE_IPV6)
			af= AF_INET6;
		else
			return -1;
		break;
	case DLT_NULL:
	case DLT_LOOP:
		if (caplen < 4)
			return -1;
		memcpy(&fam, frame, sizeof(fam));
		if (dlt == DLT_LOOP)
			fam= ntohl(fam);
		if (fam == AF_INET)
			af= AF_INET;
		else if (fam == AF_INET6)
			af= AF_INET6;
		else
			return -1;
		off= 4;
		break;
	case DLT_RAW:
		if (caplen < 1)
			return -1;
		off= 0;
		af= ((frame[0] >> 4) == 4 ? AF_INET : AF_INET6);
		break;
	default:
		return -1;
	}

	frame += off;
	caplen -= off;
	if (af == AF_INET)
	{
		const struct ip *ip= (const void *)frame;

		if (caplen < sizeof(*ip) || ip->ip_v != 4 || ip->ip_hl < 5)
			return -1;
		len= ntohs(ip->ip_len);
		if (len < (size_t)ip->ip_hl * 4 || len > caplen)
			return -1;
	}
	else
	{
		const struct ip6_hdr *ip6= (const void *)frame;

		if (caplen < sizeof(*ip6) || (frame[0] >> 4) != 6)
			return -1;
		len= sizeof(*ip6) + ntohs(ip6->ip6_plen);
		if (len > caplen)
			return -1;
	}
	*ipp= frame;
	*lenp= len;
	return af;
}
