//
//
//

#ifdef HAVE_CONFIG
#include "config.h"
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <pthread.h>
#include <errno.h>
#include <assert.h>
#include <fcntl.h>
#include <sys/time.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <arpa/inet.h>
#include <poll.h>
#include <netdb.h>
#include <netinet/tcp.h>

#include "9p.h"
#include "npfs.h"
#include "xpthread.h"
#include "npfsimpl.h"

#define POLL_TIMEOUT	5000

#define VA_REUSEADDR	0x0001
#define VA_RCVBUF		0x0002
#define VA_SNDBUF		0x0004
#define VA_DONTROUTE	0x0008
#define VA_NODELAY		0x0010
#define VA_KEEPALIVE	0x0020
#define VA_SNDTIMEO		0x0040

static Npfile *make_node(Npfile *parent, char *name, u8 type, np_file_vtab_t *vtab);
static void destroy_node(Npfile *file);
static int next_inum (void);

static int tcp_ctl_read(Npfid *fid, u64 offset, u8 *data, u32 count);
static int tcp_ctl_write(Npfid *fid, u64 offset, u8 *data, u32 count);
static int tcp_data_read(Npfid *fid, u64 offset, u8 *data, u32 count);
static int tcp_data_write(Npfid *fid, u64 offset, u8 *data, u32 count);
static int tcp_clone_open(Npfid *fid, int mode);
static int tcp_listen_open(Npfid *fid, int mode);
static void tcp_sock_cleanup(Npfile *ctlfile);
static int dns_write(Npfid *fid, u64 offset, u8 *data, u32 count);
static int tcp_opts_read(Npfid *fid, u64 offset, u8 *data, u32 count);
static int tcp_opts_write(Npfid *fid, u64 offset, u8 *data, u32 count);
static int tcp_peer_read(Npfid *fid, u64 offset, u8 *data, u32 count);
static int tcp_local_read(Npfid *fid, u64 offset, u8 *data, u32 count);

np_file_vtab_t tcp_gen_vtab = { 0 };

np_file_vtab_t tcp_clone_vtab = {
   .open = tcp_clone_open,
};

np_file_vtab_t tcp_sock_vtab = {
	.cleanup = tcp_sock_cleanup,
};

np_file_vtab_t tcp_ctl_vtab = {
	.read = tcp_ctl_read,
	.write = tcp_ctl_write,
};

np_file_vtab_t tcp_data_vtab = {
	.read = tcp_data_read,
	.write = tcp_data_write
};

np_file_vtab_t tcp_listen_vtab = {
   .open = tcp_listen_open,
};

np_file_vtab_t dns_vtab = {
	.write = dns_write,
};

np_file_vtab_t tcp_opts_vtab = {
	.read = tcp_opts_read,
	.write = tcp_opts_write,
};

np_file_vtab_t tcp_peer_vtab = {
	.read = tcp_peer_read,
};

np_file_vtab_t tcp_local_vtab = {
	.read = tcp_local_read,
};

int np_file_open(Npfile *file, Npfid *fid, int mode)
{
	if (file->vtab->open != 0)
		return file->vtab->open(fid, mode);
	return 0;
}

int np_file_read(Npfile *file, Npfid *fid, u64 offset, u8 *data, u32 count)
{
	if (file->vtab->read != 0)
		return file->vtab->read(fid, offset, data, count);
	return 0;
}

int np_file_write(Npfile *file, Npfid *fid, u64 offset, u8 *data, u32 count)
{
	if (file->vtab->write != 0)
		return file->vtab->write(fid, offset, data, count);
	return 0;
}

void np_file_cleanup(Npfile *file)
{
	if (file->vtab->cleanup != 0)
		file->vtab->cleanup(file);
}

Npfile *np_net_make_root(void)
{
	// [net]/tcp/clone
	// [net]/dns
	
	Npfile *netroot = make_node(0, "net", P9_QTDIR, &tcp_gen_vtab);
	if (netroot == 0)
		goto error;
	Npfile *tcpdir = make_node(netroot, "tcp", P9_QTDIR, &tcp_gen_vtab);
	tcpdir->mode |= S_IWUSR;
	if (tcpdir == 0)
		goto error;
	Npfile *clone = make_node(tcpdir, "clone", P9_QTFILE, &tcp_clone_vtab);
	if (clone == 0)
		goto error;
	Npfile *dns = make_node(netroot, "dns", P9_QTFILE, &dns_vtab);
	if (dns == 0)
		goto error;

	return netroot;

error:
	destroy_node(netroot);
	return 0;
}

void np_net_shutdown(Npfile *netroot)
{
	np_file_cleanup(netroot);
	destroy_node(netroot);
}

static Npfile *make_node(Npfile *parent, char *name, u8 type, np_file_vtab_t *vtab)
{
	Npfile *file = malloc(sizeof(*file));
	if (file == 0) {
		np_uerror(ENOMEM);
		goto error;
	}
	memset(file, 0, sizeof(*file));
	file->vtab = vtab;
	file->name = strdup(name);
	if (file->name == 0) {
		np_uerror(ENOMEM);
		goto error;
	}
	file->qid.path = next_inum();
	file->qid.type = type | P9_QTTMP;
	file->qid.version = 0;
	if ((type & P9_QTDIR)) {
		file->mode = S_IFDIR;
		file->mode |= S_IRUSR | S_IRGRP | S_IROTH;
		file->mode |= S_IXUSR | S_IXGRP | S_IXOTH;
	} else {
		file->mode = S_IFREG;
		file->mode |= S_IRUSR | S_IRGRP | S_IROTH;
	}
	file->uid = 0;
	file->gid = 0;
	(void)gettimeofday (&file->atime, NULL);
	(void)gettimeofday (&file->mtime, NULL);
	(void)gettimeofday (&file->ctime, NULL);

	file->parent = parent;
	if (parent != 0) {
		file->next = parent->child;
		parent->child = file;
	}

	return file;

error:
	destroy_node(file);
	return 0;
}

static void destroy_node(Npfile *file)
{
	if (file == 0)
		return;
	Npfile *ff;
	for (ff = file->child; ff != NULL; ) {
		Npfile *tmp = ff->next;
		np_file_cleanup(ff);
		destroy_node(ff);
		ff = tmp;
	}
	if (file->name)
		free (file->name);
	free(file);
}

static int next_inum(void)
{
	static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
	static int i = 1;
	int ret;

	xpthread_mutex_lock (&lock);
	ret = i++;
	xpthread_mutex_unlock (&lock);
	return ret;
}

//
// Polymorphic bits
//

static int tcp_ctl_read(Npfid *fid, u64 offset, u8 *data, u32 count)
{
	Npfile *file = fid->aux;

	// reads the name of the parent directory
	Npfile *sockdir = file->parent;

	u32 len = strlen(sockdir->name);
	if (offset >= len)
		return 0;
	if (offset +count > len)
		count = len -offset;
	memcpy(data, sockdir->name +offset, count);
	return count;
}

#define CTL_PREF_CONNECT		"connect "
#define CTL_PREF_CONNECT_LEN	8
#define CTL_PREF_ANNOUNCE		"announce "
#define CTL_PREF_ANNOUNCE_LEN	9

#define CTL_STATE_CREATED		0
#define CTL_STATE_CONNECTED		1
#define CTL_STATE_LISTENING		2
#define CTL_STATE_ACCEPTED		3

static int tcp_ctl_write(Npfid *fid, u64 offset, u8 *data, u32 count)
{
	Npfile *file = fid->aux;

	// accept "connect ip!port" and "announce port"
	if (offset != 0)
		goto error2;

	if (file->state != CTL_STATE_CREATED)
		goto error1;

	Npfile *sockdir = file->parent;

	if (strncmp((char *)data, CTL_PREF_CONNECT, CTL_PREF_CONNECT_LEN) == 0)
	{
		struct in_addr addr;
		int port;

		char pad[count -CTL_PREF_CONNECT_LEN +1];
		memcpy(pad, data +CTL_PREF_CONNECT_LEN, count -CTL_PREF_CONNECT_LEN);
		pad[count -CTL_PREF_CONNECT_LEN] = 0;

		char *p = strchr(pad, '!');
		if (p == 0)
			goto error1;
		*p++ = 0;

		if (!inet_pton(AF_INET, pad, &addr))
			goto error1;
		port = atoi(p);
		if (port == 0)
			goto error1;

		struct sockaddr_in sa = {
			.sin_family = AF_INET,
			.sin_addr = addr,
			.sin_port = htons(port),
		};

		int n = connect(sockdir->sock, (struct sockaddr *)&sa, sizeof(sa));
		if (n < 0) {
			np_uerror(errno);
			return -1;
		}

		Npfile *datafile = make_node(sockdir, "data", P9_QTFILE, &tcp_data_vtab);
		if (datafile == 0)
			goto nomem1;
		Npfile *peerfile = make_node(sockdir, "peer", P9_QTFILE, &tcp_peer_vtab);
		if (peerfile == 0)
			goto nomem2;
		Npfile *localfile = make_node(sockdir, "local", P9_QTFILE, &tcp_local_vtab);
		if (localfile == 0)
		{
			destroy_node(peerfile);
nomem2:
			destroy_node(datafile);
nomem1:
			np_uerror(ENOMEM);
			return -1;
		}

		printf("~~~ sock %d connected to %s:%d\n", sockdir->sock, pad, port);
		file->state = CTL_STATE_CONNECTED;
	}
	else if (strncmp((char *)data, CTL_PREF_ANNOUNCE, CTL_PREF_ANNOUNCE_LEN) == 0)
	{
		char *p = (char *)data +CTL_PREF_ANNOUNCE_LEN;
		int port = atoi(p);
		//if (port == 0)
		//	goto error1;

		struct sockaddr_in sa = {
			.sin_family = AF_INET,
			.sin_addr.s_addr = htonl(INADDR_ANY),
			.sin_port = htons(port),
		};

		if (bind(sockdir->sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
			np_uerror(errno);
			return -1;
		}
		printf("~~~ sock %d bound to port %d\n", sockdir->sock, port);

		Npfile *listenfile = make_node(sockdir, "listen", P9_QTFILE, &tcp_listen_vtab);
		if (listenfile == 0)
			goto nomem3;
		Npfile *localfile = make_node(sockdir, "local", P9_QTFILE, &tcp_local_vtab);
		if (localfile == 0) {
			destroy_node(listenfile);
nomem3:
			np_uerror(ENOMEM);
			return -1;
		}

		if (listen(sockdir->sock, 8) < 0) {
			np_uerror(errno);
			return -1;
		}

		printf("~~~ sock %d listening\n", sockdir->sock);
		file->state = CTL_STATE_LISTENING;
	}
	else
		goto error1;

	return count;

error2:
	np_uerror(ENOTSUP);
	return -1;

error1:
	np_uerror(EINVAL);
	return 0;
}

static int tcp_data_read(Npfid *fid, u64 offset, u8 *data, u32 count)
{
	Npfile *file = fid->aux;
	Npfile *sockdir = file->parent;

	struct pollfd pfd = {
		.fd = sockdir->sock,
		.events = POLLIN,
	};

	int s = poll(&pfd, 1, POLL_TIMEOUT);
	if (s == 0) {
		np_uerror(EAGAIN);
		return -1;
	}

	int n = recv(sockdir->sock, data, count, 0);
	if (n < 0) {
		np_uerror(errno);
		return -1;
	}

	printf("~~~ %d byte(s) read from sock %d\n", n, sockdir->sock);
	return n;
}

static int tcp_data_write(Npfid *fid, u64 offset, u8 *data, u32 count)
{
	Npfile *file = fid->aux;
	Npfile *sockdir = file->parent;

	int n = send(sockdir->sock, data, count, 0);
	if (n < 0) {
		np_uerror(errno);
		return -1;
	}

	printf("~~~ %d byte(s) written to sock %d\n", n, sockdir->sock);
	return n;
}

static int tcp_clone_open(Npfid *fid, int mode)
{
	Npfile *clonefile = fid->aux;
	Npfile *tcpdir = clonefile->parent;

	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		np_uerror(errno);
		return -1;
	}

	char name[32];
	snprintf(name, sizeof(name), "%d", sock);
	Npfile *sockdir = make_node(tcpdir, name, P9_QTDIR, &tcp_sock_vtab);
	if (sockdir == 0)
		goto error1;
	sockdir->sock = sock;
	Npfile *ctlfile = make_node(sockdir, "ctl", P9_QTFILE, &tcp_ctl_vtab);
	if (ctlfile == 0)
		goto error2;
	ctlfile->state = CTL_STATE_CREATED;
	Npfile *optsfile = make_node(sockdir, "opts", P9_QTFILE, &tcp_opts_vtab);
	if (optsfile == 0)
		goto error3;

	printf("~~~ sock %d alloc\n", sock);
	fid->aux = ctlfile;
	return 0;

error3:
	destroy_node(ctlfile);
error2:
	destroy_node(sockdir);
error1:
	close(sock);
	np_uerror(ENOMEM);
	return -1;
}

static int tcp_listen_open(Npfid *fid, int mode)
{
	Npfile *listenfile = fid->aux;
	Npfile *sockdir = listenfile->parent;
	Npfile *tcpdir = sockdir->parent;

	struct pollfd pfd = {
		.fd = sockdir->sock,
		.events = POLLIN,
	};

	int n = poll(&pfd, 1, POLL_TIMEOUT);
	if (n == 0) {
		np_uerror(EAGAIN);
		return -1;
	}

	int newsock = accept(sockdir->sock, 0, 0);
	if (newsock < 0) {
		np_uerror(errno);
		return -1;
	}

	char name[32];
	snprintf(name, sizeof(name), "%d", newsock);
	Npfile *newdir = make_node(tcpdir, name, P9_QTDIR, &tcp_sock_vtab);
	if (newdir == 0)
		goto error1;
	newdir->sock = newsock;
	Npfile *ctlfile = make_node(newdir, "ctl", P9_QTFILE, &tcp_ctl_vtab);
	if (ctlfile == 0)
		goto error2;
	ctlfile->state = CTL_STATE_ACCEPTED;
	Npfile *datafile = make_node(newdir, "data", P9_QTFILE, &tcp_data_vtab);
	if (datafile == 0)
		goto error3;
	Npfile *optsfile = make_node(newdir, "opts", P9_QTFILE, &tcp_opts_vtab);
	if (optsfile == 0)
		goto error4;
	Npfile *peerfile = make_node(newdir, "peer", P9_QTFILE, &tcp_peer_vtab);
	if (peerfile == 0)
		goto error5;
	Npfile *localfile = make_node(newdir, "local", P9_QTFILE, &tcp_local_vtab);
	if (localfile == 0)
		goto error6;

	printf("~~~ sock %d accepted\n", newsock);
	fid->aux = datafile;
	return 0;

error6:
	destroy_node(peerfile);
error5:
	destroy_node(optsfile);
error4:
	destroy_node(datafile);
error3:
	destroy_node(ctlfile);
error2:
	destroy_node(newdir);
error1:
	close(newsock);
	np_uerror(ENOMEM);
	return -1;
}

static void tcp_sock_cleanup(Npfile *ctlfile)
{
	close(ctlfile->sock);
	printf("~~~ sock %d closed\n", ctlfile->sock);
}

static int dns_write(Npfid *fid, u64 offset, u8 *data, u32 count)
{
	// <host_or_address> <address_family>
	//
	// Examples:
	//
	// use gerhostbyname2_r:
	// 	google.com 0
	// 	google.com 10
	//
	// use gethostbyaddr_r:
	// 	!173.19.40.30 2
	//
	
	// parse request
	char parse_buf[count +1];
	memcpy(parse_buf, data, count);
	parse_buf[count] = 0;

	char *p = strchr(parse_buf, ' ');
	if (p == 0) {
		np_uerror(EINVAL);
		return 0;
	}
	*p++ = 0;
	const char *hostname = parse_buf;
	int use_addr = hostname[0] == '!';
	if (use_addr)
		hostname++;
	int family = atoi(p);

	// get hostent
	char hent_buf[1024];
	struct hostent hent;
	
	struct hostent *result;
	int hent_err;
	
	if (use_addr)
	{
		u8 addr_buf[16];
		int addr_len = (family == AF_INET) ?4 :16;
		if (inet_pton(family, hostname, addr_buf) < 0) {
			np_uerror(errno);
			return 0;
		}

		gethostbyaddr_r(addr_buf, addr_len, family,
				&hent, hent_buf, sizeof(hent_buf),
				&result, &hent_err);
	}
	else
	{
		gethostbyname2_r(hostname, family,
				&hent, hent_buf, sizeof(hent_buf),
				&result, &hent_err);
	}

	// build reply
	u8 *reply;
	int reply_len;

	if (result == 0)
	{
		reply_len = 2;
		reply = malloc(reply_len);
		if (reply == 0) {
error1:
			np_uerror(ENOMEM);
			return 0;
		}

		reply[0] = hent_err & 255;
		reply[1] = (hent_err >> 8) & 255;
	}
	else
	{
		// calculate the reply length
		reply_len = 2;	// 0 for success
		assert(result->h_name != 0);
		reply_len += 2 + strlen(result->h_name);
		char **pal = result->h_aliases;
		int tot_alias_len = 0;
		while (*pal != 0)
		{
			tot_alias_len += 2 + strlen(*pal);
			pal++;
		}
		reply_len += 2 +tot_alias_len;
		reply_len += 2;	// h_addrtype
		reply_len += 2; // h_length
		char **paddr = result->h_addr_list;
		int tot_addr_len = 0;
		while (*paddr != 0)
		{
			tot_addr_len += result->h_length;
			paddr++;
		}
		reply_len += 2 +tot_addr_len;

		// build the reply
		reply = malloc(reply_len);
		if (reply == 0)
			goto error1;
		u8 *rr = reply;

		*rr++ = 0;	// success
		*rr++ = 0;

		int len = strlen(result->h_name);
		*rr++ = len & 255;
		*rr++ = (len >> 8) & 255;
		memcpy(rr, result->h_name, len);
		rr += len;

		*rr++ = tot_alias_len & 255;
		*rr++ = (tot_alias_len >> 8) & 255;
		pal = result->h_aliases;
		while (*pal != 0)
		{
			len = strlen(*pal);
			*rr++ = len & 255;
			*rr++ = (len >> 8) & 255;
			memcpy(rr, *pal, len);
			rr += len;
			pal++;
		}

		*rr++ = result->h_addrtype & 255;
		*rr++ = (result->h_addrtype >> 8) & 255;

		*rr++ = result->h_length & 255;
		*rr++ = (result->h_length >> 8) & 255;

		*rr++ = tot_addr_len & 255;
		*rr++ = (tot_addr_len >> 8) & 255;
		paddr = result->h_addr_list;
		while (*paddr != 0)
		{
			memcpy(rr, *paddr, result->h_length);
			rr += result->h_length;
			paddr++;
		}
		assert(rr == reply +reply_len);
	}

	free(fid->data);	// safe if 0
	fid->data = reply;
	fid->data_len = reply_len;

	return count;
}

static int tcp_opts_read(Npfid *fid, u64 offset, u8 *data, u32 count)
{
	Npfile *file = fid->aux;
	Npfile *sockdir = file->parent;
	assert(sockdir != 0);
	int sock = sockdir->sock;

	// (valid mask) [4]
	// SO_REUSEADDR [b]
	// SO_RCVBUF [4]
	// SO_SNDBUF [4]
	// SO_DONTROUTE [b]
	// TCP_NODELAY (IPPROTO_IP) [b]
	// SO_KEEPALIVE [b]
	// SO_SNDTIMEO [8]
	
	int len = 4 +1 +4 +4 +1 +1 +1 +8;
	if (offset != 0 || count < len)
		return 0;

	u8 *rr = data;
	union {
		int i;
		struct timeval tv;
	} optval;
	socklen_t optlen;

	u32 valid = VA_REUSEADDR |
				VA_RCVBUF |
				VA_SNDBUF |
				VA_DONTROUTE |
				VA_NODELAY |
				VA_KEEPALIVE |
				VA_SNDTIMEO;
	*rr++ = valid & 255;
	*rr++ = (valid >> 8) & 255;
	*rr++ = (valid >> 16) & 255;
	*rr++ = (valid >> 24) & 255;

	optlen = 4;
	int ret_code = getsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, &optlen);
	assert(ret_code == 0 && optlen == 4);
	*rr++ = optval.i & 255;

	optlen = 4;
	ret_code = getsockopt(sock, SOL_SOCKET, SO_RCVBUF, &optval, &optlen);
	assert(ret_code == 0 && optlen == 4);
	*rr++ = optval.i & 255;
	*rr++ = (optval.i >> 8) & 255;
	*rr++ = (optval.i >> 16) & 255;
	*rr++ = (optval.i >> 24) & 255;

	optlen = 4;
	ret_code = getsockopt(sock, SOL_SOCKET, SO_SNDBUF, &optval, &optlen);
	assert(ret_code == 0 && optlen == 4);
	*rr++ = optval.i & 255;
	*rr++ = (optval.i >> 8) & 255;
	*rr++ = (optval.i >> 16) & 255;
	*rr++ = (optval.i >> 24) & 255;

	optlen = 4;
	ret_code = getsockopt(sock, SOL_SOCKET, SO_DONTROUTE, &optval, &optlen);
	assert(ret_code == 0 && optlen == 4);
	*rr++ = optval.i & 255;

	optlen = 4;
	ret_code = getsockopt(sock, IPPROTO_IP, TCP_NODELAY, &optval, &optlen);
	assert(ret_code == 0 && optlen == 4);
	*rr++ = optval.i & 255;

	optlen = 4;
	ret_code = getsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &optval, &optlen);
	assert(ret_code == 0 && optlen == 4);
	*rr++ = optval.i & 255;

	optlen = sizeof(struct timeval);
	ret_code = getsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &optval, &optlen);
	assert(ret_code == 0 && optlen == sizeof(struct timeval));
	u64 micros = (u64)optval.tv.tv_sec * 1000000 + optval.tv.tv_usec;
	*rr++ = micros & 255;
	*rr++ = (micros >> 8) & 255;
	*rr++ = (micros >> 16) & 255;
	*rr++ = (micros >> 24) & 255;
	*rr++ = (micros >> 32) & 255;
	*rr++ = (micros >> 40) & 255;
	*rr++ = (micros >> 48) & 255;
	*rr++ = (micros >> 56) & 255;

	assert(rr == data +len);
	printf("~~~ sock %d opts read\n", sock);
	return len;
}

static int tcp_opts_write(Npfid *fid, u64 offset, u8 *data, u32 count)
{
	Npfile *file = fid->aux;
	Npfile *sockdir = file->parent;
	int sock = sockdir->sock;

	if (offset != 0 || count != 4 +1 +4 +4 +1 +1 +1 +8) {
		np_uerror(EINVAL);
		return 0;
	}

	u8 *rr = data;
	u32 valid = ((u32)rr[0] << 24) | ((u32)rr[1] << 16) | ((u32)rr[2] << 8) | rr[3];
	rr += 4;

	if (valid & VA_REUSEADDR)
	{
		int optval = rr[0];
		int ret_code = setsockopt(sock,
				SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
		assert(ret_code == 0);
	}
	rr++;

	if (valid & VA_RCVBUF)
	{
		u32 optval = ((u32)rr[0] << 24) | ((u32)rr[1] << 16) | ((u32)rr[2] << 8) | rr[3];
		int ret_code = setsockopt(sock,
				SOL_SOCKET, SO_RCVBUF, &optval, sizeof(optval));
		assert(ret_code == 0);
	}
	rr += 4;

	if (valid & VA_SNDBUF)
   	{
		u32 optval = ((u32)rr[0] << 24) | ((u32)rr[1] << 16) | ((u32)rr[2] << 8) | rr[3];
		int ret_code = setsockopt(sock,
				SOL_SOCKET, SO_SNDBUF, &optval, sizeof(optval));
		assert(ret_code == 0);
	}
	rr += 4;

	if (valid & VA_DONTROUTE)
	{
		int optval = rr[0];
		int ret_code = setsockopt(sock,
				SOL_SOCKET, SO_DONTROUTE, &optval, sizeof(optval));
		assert(ret_code == 0);
	}
	rr++;

	if (valid & VA_NODELAY)
	{
		int optval = rr[0];
		int ret_code = setsockopt(sock,
				IPPROTO_IP, TCP_NODELAY, &optval, sizeof(optval));
		assert(ret_code == 0);
	}
	rr++;

	if (valid & VA_KEEPALIVE)
	{
		int optval = rr[0];
		int ret_code = setsockopt(sock,
				SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(optval));
		assert(ret_code == 0);
	}
	rr++;

	if (valid & VA_SNDTIMEO)
	{
		u64 micros = ((u64)rr[0] << 56) | ((u64)rr[1] << 48) | ((u64)rr[2] << 40) | ((u64)rr[3] << 32) |
					 ((u64)rr[4] << 24) | ((u64)rr[5] << 16) | ((u64)rr[6] << 8) | rr[7];
		struct timeval optval = {
			.tv_sec = micros / 1000000,
			.tv_usec = micros % 1000000,
		};
		int ret_code = setsockopt(sock,
				SOL_SOCKET, SO_SNDTIMEO, &optval, sizeof(optval));
		assert(ret_code == 0);
	}
	rr += 8;

	assert(rr == data +count);
	printf("~~~ sock %d opts set\n", sock);
	return count;
}

static int tcp_peer_read(Npfid *fid, u64 offset, u8 *data, u32 count)
{
	Npfile *file = fid->aux;
	Npfile *sockdir = file->parent;
	int sock = sockdir->sock;

	if (offset != 0)
		return 0;

	u8 buf[64];
	struct sockaddr *addr = (struct sockaddr *)buf;
	socklen_t addrlen = sizeof(buf);
	if (getpeername(sock, addr, &addrlen) < 0) {
		np_uerror(errno);
		return 0;
	}

	u8 *rr = data;
	int reply_len;
	if (addr->sa_family == AF_INET)
	{
		reply_len = 1 +4 +2;
		if (count < reply_len)
			return 0;

		struct sockaddr_in *sin = (struct sockaddr_in *)addr;
		*rr++ = AF_INET;
		memcpy(rr, &sin->sin_addr, 4);
		rr += 4;
		int port = ntohs(sin->sin_port);
		*rr++ = port & 255;
		*rr++ = (port >> 8) & 255;
		assert(rr == data +reply_len);
	}
	else
	{
		assert(addr->sa_family == AF_INET6);
		reply_len = 1 +16 +2;
		if (count < reply_len)
			return 0;

		struct sockaddr_in6 *sin = (struct sockaddr_in6 *)addr;
		*rr++ = AF_INET6;
		memcpy(rr, &sin->sin6_addr, 16);
		rr += 16;
		int port = ntohs(sin->sin6_port);
		*rr++ = port & 255;
		*rr++ = (port >> 8) & 255;
		assert(rr == data +reply_len);
	}

	return reply_len;
}

static int tcp_local_read(Npfid *fid, u64 offset, u8 *data, u32 count)
{
	Npfile *file = fid->aux;
	Npfile *sockdir = file->parent;
	int sock = sockdir->sock;

	if (offset != 0)
		return 0;

	u8 buf[64];
	struct sockaddr *addr = (struct sockaddr *)buf;
	socklen_t addrlen = sizeof(buf);
	if (getsockname(sock, addr, &addrlen) < 0) {
		np_uerror(errno);
		return 0;
	}

	u8 *rr = data;
	int reply_len;
	if (addr->sa_family == AF_INET)
	{
		reply_len = 1 +4 +2;
		if (count < reply_len)
			return 0;

		struct sockaddr_in *sin = (struct sockaddr_in *)addr;
		*rr++ = AF_INET;
		memcpy(rr, &sin->sin_addr, 4);
		rr += 4;
		int port = ntohs(sin->sin_port);
		*rr++ = port & 255;
		*rr++ = (port >> 8) & 255;
		assert(rr == data +reply_len);
	}
	else
	{
		assert(addr->sa_family == AF_INET6);
		reply_len = 1 +16 +2;
		if (count < reply_len)
			return 0;

		struct sockaddr_in6 *sin = (struct sockaddr_in6 *)addr;
		*rr++ = AF_INET6;
		memcpy(rr, &sin->sin6_addr, 16);
		rr += 16;
		int port = ntohs(sin->sin6_port);
		*rr++ = port & 255;
		*rr++ = (port >> 8) & 255;
		assert(rr == data +reply_len);
	}

	return reply_len;
}

//
// Server callbacks
//

Npfcall *np_net_attach(Npfid *fid, Npfid *afid, char *aname)
{
	NP_ASSERT(strcmp(aname, "net") == 0);
	Npsrv *srv = fid->conn->srv;
	Npfile *netroot = srv->netroot;
	Npfcall *rc = np_create_rattach(&netroot->qid);
	if (rc == 0)
		return 0;
	fid->type = netroot->qid.type;
	fid->aux = netroot;
	return rc;
}

int np_net_clone(Npfid *fid, Npfid *newfid)
{
	newfid->aux = fid->aux;
	return 1;
}

int np_net_walk(Npfid *fid, Npstr *wname, Npqid *wqid)
{
	Npfile *file = fid->aux;

	Npfile *ff;
	if (np_strcmp(wname, "..") == 0) {
		if (file->parent == 0)
			ff = file;
		else
			ff = file->parent;
	}
	else
	{
		for (ff = file->child; ff != 0; ff = ff->next) {
			if (np_strcmp(wname, ff->name) == 0)
				break;
		}
		if (ff == 0) {
			np_uerror(ENOENT);
			return 0;
		}
	}
	fid->aux = ff;
	wqid->path = ff->qid.path;
	wqid->type = ff->qid.type;
	wqid->version = ff->qid.version;
	return 1;
}

void np_net_fiddestroy(Npfid *fid)
{
}

Npfcall *np_net_clunk(Npfid *fid)
{
	Npfcall *rc = np_create_rclunk();
	if (rc == 0)
		np_uerror(ENOMEM);
	return rc;
}

Npfcall *np_net_lopen(Npfid *fid, u32 mode)
{
	Npfile *file = fid->aux;

	if (np_file_open(file, fid, mode) < 0)
		return 0;

	Npfcall *rc = np_create_rlopen(&file->qid, 0);
	if (rc == 0)
		np_uerror(ENOMEM);

	return rc;
}

Npfcall *np_net_read(Npfid *fid, u64 offset, u32 count, Npreq *req)
{
	Npfile *file = fid->aux;

	u8 data[count];
	int n;

 	if (fid->data != 0)
	{
		// the fid already has the reply
		n = fid->data_len - offset;
		if (n < 0)
			n = 0;
		else if (n > count)
			n = count;
		memcpy(data, fid->data +offset, n);
	}
	else
	{	
		n = np_file_read(file, fid, offset, data, count);
		if (n < 0)
			return 0;
	}
	Npfcall *rc = np_create_rread(n, data);
	if (rc == 0) {
		np_uerror(ENOMEM);
		return 0;
	}
	(void)gettimeofday(&file->atime, 0);
	return rc;
}

Npfcall *np_net_write(Npfid *fid, u64 offset, u32 count, u8 *data, Npreq *req)
{
	Npfile *file = fid->aux;

	int n = np_file_write(file, fid, offset, data, count);
	if (n < 0)
		return 0;
	Npfcall *rc = np_create_rwrite (n);
	if (rc == 0)
		np_uerror (ENOMEM);
	return rc;
}

Npfcall *np_net_readdir(Npfid *fid, u64 offset, u32 count, Npreq *req)
{
	Npfile *dir = fid->aux;

	Npfcall *rc = np_create_rreaddir(count);
	if (rc == 0) {
		np_uerror(ENOMEM);
		return 0;
	}
	int off = 0;
	int n = 0;
	Npfile *ff;
	for (ff = dir->child; ff != 0; ff = ff->next) {
		if (off >= offset) {
			int i = np_serialize_p9dirent(&ff->qid, off +1,
					(ff->qid.type & P9_QTDIR) ? DT_DIR : DT_REG,
					ff->name, rc->u.rreaddir.data +n, count -n);
			if (i == 0)
				break;
			n += i;
		}
		off++;
	}
	np_finalize_rreaddir(rc, n);
	(void)gettimeofday(&dir->atime, 0);
	return rc;
}

Npfcall *np_net_getattr(Npfid *fid, u64 valid)
{
	Npfile *file = fid->aux;
	Npfcall *rc = np_create_rgetattr(valid, &file->qid, file->mode,
			file->uid, file->gid, 1, 0, 0, 0, 0,
			file->atime.tv_sec, file->atime.tv_usec*1000,
			file->mtime.tv_sec, file->mtime.tv_usec*1000,
			file->ctime.tv_sec, file->ctime.tv_usec*1000,
			0, 0, 0, 0);
	if (rc == 0)
		np_uerror (ENOMEM);
	return rc;
}

Npfcall *np_net_setattr (Npfid *fid, u32 valid, u32 mode, u32 uid, u32 gid, u64 size,
              u64 atime_sec, u64 atime_nsec, u64 mtime_sec, u64 mtime_nsec)
{
	Npfcall *rc;

	/* do nothing for now - we exist only for setattr on /dev/null */

	if (!(rc = np_create_rsetattr()))
		np_uerror (ENOMEM);
	return rc;
}

Npfcall *np_net_remove(Npfid *fid)
{
	Npfile *file = fid->aux;
	Npconn *conn = fid->conn;

	if (file->parent != 0 && (file->parent->mode & S_IWUSR) != 0) {

		// remove reference to the file from all fids
		np_fidpool_clear_aux(conn->fidpool, file);
		Npfile *ff;
		for (ff = file->child; ff != NULL; ff = ff->next)
			np_fidpool_clear_aux(conn->fidpool, ff);

		// remove the node from the parent's children list
		Npfile **fp;
		for (fp = &file->parent->child; *fp != 0 && *fp != file; fp = &(*fp)->next);
		NP_ASSERT(*fp != 0);
		*fp = (*fp)->next;

		// cleanup, such as socket close
		np_file_cleanup(file);

		// release the subtree, calls cleanup for each leaf
		destroy_node(file);

		Npfcall *rc = np_create_rremove();
		if (rc == 0)
			np_uerror(ENOMEM);
		return rc;
	}
	else {
		np_uerror(EPERM);
		return 0;
	}
}

//EOF
