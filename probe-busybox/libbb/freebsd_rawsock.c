/*
 * Copyright (c) 2026 RIPE NCC <atlas@ripe.net>
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 *
 * Raw sockets for the measurement code on FreeBSD, see atlas_rawsock.h.
 *
 * FreeBSD has no file capabilities, so busybox is setuid root.  For an
 * applet that needs raw sockets, check_suid() calls freebsd_privsep()
 * before the applet runs: it forks a broker that keeps root and drops the
 * applet itself to the measurement user for good, with the caller's real
 * ids as on Linux.  The broker creates the raw sockets the applet may have
 * and opens the BPF captures of TCP traceroute, and does nothing else.
 *
 * The applet and the broker share a SOCK_SEQPACKET socketpair, so every
 * request and every reply is exactly one record.  A request is one struct
 * rs_req; a capture request names all the interfaces of a traceroute and
 * carries one descriptor, a TCP socket bound to the local address and
 * port of the flow, a socket request none.  Anything else is refused.  The
 * reply is one struct rs_rep plus, on success, the new descriptors: one
 * raw socket, or a capture for each interface with a link type we can
 * parse.
 */

#include "libbb.h"
#include "atlas_rawsock.h"
#include "freebsd_tcpcap.h"

#include <sys/capsicum.h>
#include <sys/procctl.h>
#include <sys/resource.h>
#include <sys/uio.h>
#include <netinet/in.h>

/* What an applet may ask for */
#define RS_ICMP4	0x01	/* AF_INET, IPPROTO_ICMP */
#define RS_ICMP6	0x02	/* AF_INET6, IPPROTO_ICMPV6 */
#define RS_TCP4		0x04	/* AF_INET, IPPROTO_TCP */
#define RS_TCP6		0x08	/* AF_INET6, IPPROTO_TCP */
#define RS_TCPCAP	0x10	/* BPF capture of TCP replies */
#define RS_ALL		(RS_ICMP4 | RS_ICMP6 | RS_TCP4 | RS_TCP6 | RS_TCPCAP)

#define RS_MAGIC	0x41525331	/* "ARS1" */
#define RS_OP_SOCKET	1		/* Raw socket: af, proto */
#define RS_OP_TCPCAP	2		/* BPF captures: flow, ifs */

/* Most descriptors a request may carry, more are closed and refused */
#define RS_INFDS	8

struct rs_req
{
	uint32_t magic;
	uint32_t op;
	int32_t af;
	int32_t proto;
	struct tcpcap_flow flow;
	struct tcpcap_ifs ifs;
};

struct rs_rep
{
	uint32_t magic;
	int32_t error;			/* errno value, 0 on success */
	uint32_t nfd;			/* Number of descriptors */
	uint32_t dlt[TCPCAP_MAXIF];	/* Captures: their link types */
};

static const struct
{
	int af;
	int proto;
	unsigned bit;
} rs_sockets[] =
{
	{ AF_INET,	IPPROTO_ICMP,	RS_ICMP4 },
	{ AF_INET6,	IPPROTO_ICMPV6,	RS_ICMP6 },
	{ AF_INET,	IPPROTO_TCP,	RS_TCP4 },
	{ AF_INET6,	IPPROTO_TCP,	RS_TCP6 },
};

static const struct
{
	const char *applet;
	unsigned mask;
} rs_applets[] =
{
	{ "eooqd",		RS_ALL },
	{ "eperd",		RS_ALL },
	{ "evping",		RS_ICMP4 | RS_ICMP6 },
	{ "evtraceroute",	RS_ALL },
	{ "rptra6",		RS_ICMP6 },
};

/* The applet's end of the socketpair, -1 without a broker */
static int rs_fd= -1;

unsigned freebsd_rawsock_mask(int applet_no)
{
	unsigned i;

	for (i= 0; i < ARRAY_SIZE(rs_applets); i++)
	{
		if (find_applet_by_name(rs_applets[i].applet) == applet_no)
			return rs_applets[i].mask;
	}
	return 0;
}

/* ---- The broker */

/* Reply with error, or with the nfd descriptors in fds and, for
 * captures, their link types in dlts
 */
static void broker_reply(int sp, int error, int nfd, const int *fds,
	const unsigned *dlts)
{
	int i;
	struct rs_rep rep;
	struct iovec iov;
	struct msghdr msg;
	struct cmsghdr *cmsg;
	union
	{
		struct cmsghdr hdr;
		char buf[CMSG_SPACE(TCPCAP_MAXIF * sizeof(int))];
	} cbuf;

	memset(&rep, '\0', sizeof(rep));
	rep.magic= RS_MAGIC;
	rep.error= error;
	if (error == 0)
	{
		rep.nfd= nfd;
		for (i= 0; dlts && i < nfd; i++)
			rep.dlt[i]= dlts[i];
	}
	iov.iov_base= &rep;
	iov.iov_len= sizeof(rep);
	memset(&msg, '\0', sizeof(msg));
	msg.msg_iov= &iov;
	msg.msg_iovlen= 1;
	if (error == 0 && nfd > 0)
	{
		memset(&cbuf, '\0', sizeof(cbuf));
		msg.msg_control= cbuf.buf;
		msg.msg_controllen= CMSG_SPACE(nfd * sizeof(int));
		cmsg= CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_level= SOL_SOCKET;
		cmsg->cmsg_type= SCM_RIGHTS;
		cmsg->cmsg_len= CMSG_LEN(nfd * sizeof(int));
		memcpy(CMSG_DATA(cmsg), fds, nfd * sizeof(int));
	}
	if (sendmsg(sp, &msg, MSG_NOSIGNAL) != (ssize_t)sizeof(rep))
		_exit(1);
}

static int broker_socket(const struct rs_req *req, unsigned mask, int *fdp)
{
	unsigned i;
	int fd;

	for (i= 0; i < ARRAY_SIZE(rs_sockets); i++)
	{
		if (rs_sockets[i].af == req->af &&
			rs_sockets[i].proto == req->proto)
		{
			break;
		}
	}
	if (i >= ARRAY_SIZE(rs_sockets) || !(mask & rs_sockets[i].bit))
		return EPERM;
	fd= socket(req->af, SOCK_RAW | SOCK_CLOEXEC, req->proto);
	if (fd == -1)
		return errno;
	*fdp= fd;
	return 0;
}

static void NORETURN broker_serve(int sp, unsigned mask)
{
	int i, nfds, nout, r, fd;
	int fds[RS_INFDS], outfds[TCPCAP_MAXIF];
	ssize_t n;
	unsigned dlts[TCPCAP_MAXIF];
	struct rs_req req;
	struct iovec iov;
	struct msghdr msg;
	struct cmsghdr *cmsg;
	union
	{
		struct cmsghdr hdr;
		char buf[CMSG_SPACE(sizeof(fds))];
	} cbuf;
	/* Much larger than a request: FreeBSD's SOCK_SEQPACKET does not
	 * discard the rest of a record that does not fit, it returns it
	 * with the next read.  An oversized record is thus seen as one or
	 * more malformed ones, each refused on its own.
	 */
	unsigned char buf[sizeof(struct rs_req) + 1024];

	for (;;)
	{
		iov.iov_base= buf;
		iov.iov_len= sizeof(buf);
		memset(&msg, '\0', sizeof(msg));
		msg.msg_iov= &iov;
		msg.msg_iovlen= 1;
		msg.msg_control= cbuf.buf;
		msg.msg_controllen= sizeof(cbuf.buf);
		n= recvmsg(sp, &msg, MSG_CMSG_CLOEXEC);
		if (n == 0)
			_exit(0);	/* The applet is gone */
		if (n == -1)
		{
			if (errno == EINTR)
				continue;
			_exit(1);
		}

		/* Collect any descriptors first, so that all of them get
		 * closed whatever the request turns out to be
		 */
		nfds= 0;
		r= 0;
		for (cmsg= CMSG_FIRSTHDR(&msg); cmsg;
			cmsg= CMSG_NXTHDR(&msg, cmsg))
		{
			int cnt;

			if (cmsg->cmsg_level != SOL_SOCKET ||
				cmsg->cmsg_type != SCM_RIGHTS)
			{
				r= EINVAL;
				continue;
			}
			cnt= (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);
			for (i= 0; i < cnt; i++)
			{
				memcpy(&fd, CMSG_DATA(cmsg) + i*sizeof(int),
					sizeof(int));
				if (nfds < (int)ARRAY_SIZE(fds))
					fds[nfds++]= fd;
				else
				{
					close(fd);
					r= EINVAL;
				}
			}
		}

		nout= 0;
		if (msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC))
			r= EMSGSIZE;
		else if (r != 0)
			;
		else if (n != sizeof(req))
			r= EINVAL;
		else
		{
			memcpy(&req, buf, sizeof(req));
			if (req.magic != RS_MAGIC)
				r= EINVAL;
			else if (req.op == RS_OP_SOCKET)
			{
				if (nfds != 0)
					r= EINVAL;
				else
				{
					r= broker_socket(&req, mask, &outfds[0]);
					nout= 1;
					dlts[0]= 0;
				}
			}
			else if (req.op == RS_OP_TCPCAP)
			{
				if (!(mask & RS_TCPCAP))
					r= EPERM;
				else if (nfds != 1 || req.af != req.flow.af ||
					req.proto != IPPROTO_TCP)
				{
					r= EINVAL;
				}
				else
				{
					r= tcpcap_open("/bpf", &req.flow,
						&req.ifs, fds[0], outfds,
						dlts, &nout);
				}
			}
			else
				r= EINVAL;
		}
		for (i= 0; i < nfds; i++)
			close(fds[i]);

		if (r != 0)
			nout= 0;
		broker_reply(sp, r, nout, outfds, dlts);
		for (i= 0; i < nout; i++)
			close(outfds[i]);
	}
}

static void NORETURN broker_child(int sp, unsigned mask)
{
	int i, nullfd;
	sigset_t set;
	struct rlimit rl;
	cap_rights_t rights;
	static char *empty_env[]= { NULL };

	for (i= 1; i < NSIG; i++)
		signal(i, SIG_DFL);
	signal(SIGPIPE, SIG_IGN);
	sigemptyset(&set);
	sigprocmask(SIG_SETMASK, &set, NULL);
	environ= empty_env;

	/* Root in every id, no supplementary groups */
	if (setgroups(0, NULL) == -1)
		_exit(1);
	if (setresgid(0, 0, 0) == -1 || setresuid(0, 0, 0) == -1)
		_exit(1);
	umask(077);

	/* Keep only stdio on /dev/null and the socketpair (3) */
	nullfd= open("/dev/null", O_RDWR);
	if (nullfd == -1)
		_exit(1);
	sp= fcntl(sp, F_DUPFD, 10);
	nullfd= fcntl(nullfd, F_DUPFD, 10);
	if (sp == -1 || nullfd == -1)
		_exit(1);
	if (dup2(nullfd, 0) == -1 || dup2(nullfd, 1) == -1 ||
		dup2(nullfd, 2) == -1 || dup2(sp, 3) == -1)
	{
		_exit(1);
	}
	sp= 3;
	closefrom(4);

	/* No core dumps, no tracing, few descriptors, no files.  Descriptors:
	 * stdio and the socketpair, what a request carries, the captures of
	 * a reply.
	 */
	rl.rlim_cur= rl.rlim_max= 0;
	setrlimit(RLIMIT_CORE, &rl);
	setrlimit(RLIMIT_FSIZE, &rl);
	rl.rlim_cur= rl.rlim_max= 4 + RS_INFDS + TCPCAP_MAXIF;
	setrlimit(RLIMIT_NOFILE, &rl);
	i= PROC_TRACE_CTL_DISABLE;
	procctl(P_PID, 0, PROC_TRACE_CTL, &i);

	/* Capability mode would refuse raw sockets and opening /bpf.  Limit
	 * what the socketpair can do and leave the file system for devfs,
	 * where the captures come from.  In a jail, chroot refuses while
	 * any directory is open, so hold none.
	 */
	cap_rights_init(&rights, CAP_RECV, CAP_SEND);
	if (cap_rights_limit(sp, &rights) == -1 && errno != ENOSYS)
		_exit(1);
	if (chroot("/dev") == -1 || chdir("/") == -1)
		_exit(1);

	/* Tell the applet that we are ready */
	broker_reply(sp, 0, 0, NULL, NULL);

	broker_serve(sp, mask);
}

/* Set effective and saved ids, no supplementary groups, and check that
 * root cannot be regained.  The real ids stay the caller's, as with the
 * setresuid(-1, uid, uid) of check_suid on Linux: the main loop, the real
 * user, can see and signal its applets, and an applet can become the real
 * user again.  check_suid returns early for real root, so root is in none
 * of the ids afterwards.
 */
static void drop_to(uid_t uid, gid_t gid)
{
	uid_t ruid, ru, eu, su;
	gid_t rgid, rg, eg, sg;
	int n;
	gid_t groups[2];

	ruid= getuid();
	rgid= getgid();
	if (setgroups(0, NULL) == -1 && setgroups(1, &gid) == -1)
		bb_perror_msg_and_die("setgroups");
	if (setresgid(-1, gid, gid) == -1)
		bb_perror_msg_and_die("setresgid");
	if (setresuid(-1, uid, uid) == -1)
		bb_perror_msg_and_die("setresuid");

	if (getresuid(&ru, &eu, &su) == -1 || getresgid(&rg, &eg, &sg) == -1)
		bb_perror_msg_and_die("getresuid");
	if (ru != ruid || eu != uid || su != uid ||
		rg != rgid || eg != gid || sg != gid)
	{
		bb_error_msg_and_die("privilege drop failed");
	}
	n= getgroups(ARRAY_SIZE(groups), groups);
	if (n < 0 || n > 1 || (n == 1 && groups[0] != gid))
		bb_error_msg_and_die("supplementary groups not cleared");
	if (uid != 0 && (setuid(0) != -1 || seteuid(0) != -1 ||
		setresuid(-1, 0, -1) != -1))
	{
		bb_error_msg_and_die("could regain root");
	}
	/* Group 0 as the caller's own real group is no gain */
	if (gid != 0 && rgid != 0 && (setgid(0) != -1 || setegid(0) != -1))
		bb_error_msg_and_die("could regain group 0");
}

void freebsd_privsep(unsigned mask, uid_t uid, gid_t gid)
{
	int sp[2], fd, n;
	pid_t pid;
	struct rs_rep rep;

	if (mask == 0)
	{
		drop_to(uid, gid);
		return;
	}

	if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sp) == -1)
		bb_perror_msg_and_die("socketpair");

	fflush_all();
	pid= fork();
	if (pid == -1)
		bb_perror_msg_and_die("fork");
	if (pid == 0)
	{
		close(sp[0]);
		broker_child(sp[1], mask);
	}
	close(sp[1]);

	/* Keep the descriptor out of the way of code that closes the low
	 * ones after daemonizing (bb_daemonize_or_rexec)
	 */
	fd= fcntl(sp[0], F_DUPFD_CLOEXEC, 64);
	if (fd == -1)
		bb_perror_msg_and_die("fcntl");
	close(sp[0]);
	sp[0]= fd;

	drop_to(uid, gid);

	/* Wait until the broker is set up */
	n= recv(sp[0], &rep, sizeof(rep), 0);
	if (n != sizeof(rep) || rep.magic != RS_MAGIC || rep.error != 0)
		bb_error_msg_and_die("raw socket broker failed to start");

	rs_fd= sp[0];
}

/* ---- The applet's side */

/* Send a request, with sendfd if it is not -1.  Returns the number of
 * descriptors of the reply, stored in fds (room for TCPCAP_MAXIF), or -1
 * with errno set.
 */
static int broker_call(const struct rs_req *req, int sendfd,
	struct rs_rep *rep, int *fds)
{
	int i, nfd;
	ssize_t n;
	struct iovec iov;
	struct msghdr msg;
	struct cmsghdr *cmsg;
	union
	{
		struct cmsghdr hdr;
		char buf[CMSG_SPACE(TCPCAP_MAXIF * sizeof(int))];
	} cbuf;

	iov.iov_base= (void *)req;
	iov.iov_len= sizeof(*req);
	memset(&msg, '\0', sizeof(msg));
	msg.msg_iov= &iov;
	msg.msg_iovlen= 1;
	if (sendfd != -1)
	{
		memset(&cbuf, '\0', sizeof(cbuf));
		msg.msg_control= cbuf.buf;
		msg.msg_controllen= CMSG_SPACE(sizeof(int));
		cmsg= CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_level= SOL_SOCKET;
		cmsg->cmsg_type= SCM_RIGHTS;
		cmsg->cmsg_len= CMSG_LEN(sizeof(int));
		memcpy(CMSG_DATA(cmsg), &sendfd, sizeof(int));
	}
	if (sendmsg(rs_fd, &msg, MSG_NOSIGNAL) != (ssize_t)sizeof(*req))
		return -1;

	iov.iov_base= rep;
	iov.iov_len= sizeof(*rep);
	memset(&msg, '\0', sizeof(msg));
	msg.msg_iov= &iov;
	msg.msg_iovlen= 1;
	msg.msg_control= cbuf.buf;
	msg.msg_controllen= sizeof(cbuf.buf);
	do
		n= recvmsg(rs_fd, &msg, MSG_CMSG_CLOEXEC);
	while (n == -1 && errno == EINTR);
	if (n == -1)
		return -1;

	nfd= 0;
	cmsg= CMSG_FIRSTHDR(&msg);
	if (cmsg && cmsg->cmsg_level == SOL_SOCKET &&
		cmsg->cmsg_type == SCM_RIGHTS)
	{
		nfd= (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);
		if (nfd > TCPCAP_MAXIF)
			nfd= 0;		/* Cannot happen, cbuf has no room */
		memcpy(fds, CMSG_DATA(cmsg), nfd * sizeof(int));
	}
	if (n != sizeof(*rep) || rep->magic != RS_MAGIC ||
		(msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) ||
		(rep->error == 0 && (rep->nfd == 0 || rep->nfd != (unsigned)nfd)))
	{
		errno= EPIPE;	/* Broker gone or confused */
	}
	else if (rep->error != 0)
		errno= rep->error;
	else
		return nfd;
	for (i= 0; i < nfd; i++)
		close(fds[i]);
	return -1;
}

int atlas_rawsocket(int af, int proto)
{
	int n;
	int fds[TCPCAP_MAXIF];
	struct rs_req req;
	struct rs_rep rep;

	if (rs_fd == -1)
		return socket(af, SOCK_RAW, proto);

	memset(&req, '\0', sizeof(req));
	req.magic= RS_MAGIC;
	req.op= RS_OP_SOCKET;
	req.af= af;
	req.proto= proto;
	n= broker_call(&req, -1, &rep, fds);
	if (n == 1)
		return fds[0];
	while (n > 0)
		close(fds[--n]);
	if (n == 0)
		errno= EPIPE;	/* More than one */
	return -1;
}

int xatlas_rawsocket(int af, int proto)
{
	int fd;

	fd= atlas_rawsocket(af, proto);
	if (fd < 0)
		bb_perror_msg_and_die("socket");
	return fd;
}

int freebsd_broker_tcpcap(const struct tcpcap_flow *flow,
	const struct tcpcap_ifs *ifs, int tcpfd, int *fds, unsigned *dlts,
	int *np)
{
	int i, n;
	struct rs_req req;
	struct rs_rep rep;

	if (rs_fd == -1)
		return -1;

	memset(&req, '\0', sizeof(req));
	req.magic= RS_MAGIC;
	req.op= RS_OP_TCPCAP;
	req.af= flow->af;
	req.proto= IPPROTO_TCP;
	req.flow= *flow;
	req.ifs= *ifs;
	n= broker_call(&req, tcpfd, &rep, fds);
	if (n == -1)
		return errno;
	for (i= 0; i < n; i++)
		dlts[i]= rep.dlt[i];
	*np= n;
	return 0;
}
