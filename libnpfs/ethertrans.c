//
//
//
//
//
//

#if HAVE_CONFIG
#include "config.h"
#endif

#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdint.h>
#include <errno.h>

#include <arpa/inet.h>

#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>

#include <poll.h>

#include "9p.h"
#include "npfs.h"
#include "npfsimpl.h"

#define EXP_9P_ETH	0x885b

typedef struct Ethertrans Ethertrans;

struct Ethertrans {
	struct sockaddr_ll saddr;
	int fd;
	Nptrans *trans;
};

static void ether_trans_destroy(void *a);
static int ether_trans_recv(Npfcall **fcp, u32 msize, void *a);
static int ether_trans_send(Npfcall *fc, void *a);

Nptrans *np_ethertrans_create(int ifindex)
{
	Ethertrans *et = malloc(sizeof(*et));

	et->fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL));
	if (et->fd < 0)
		goto error;

	struct sockaddr_ll saddr = {
		.sll_family = AF_PACKET,
		//.sll_protocol = htons(EXP_9P_ETH),
		.sll_protocol = htons(ETH_P_ALL),
		.sll_ifindex = ifindex,
	};

	if (bind(et->fd, (struct sockaddr *)&saddr, sizeof(saddr)) < 0)
		goto error;

	Nptrans *trans = np_trans_create(et,
			ether_trans_recv,
			ether_trans_send,
			ether_trans_destroy);
	if (trans == 0)
		goto error;

	et->trans = trans;
	return trans;

error:
	free(et);
	return NULL;
}

static void ether_trans_destroy(void *a)
{
	Ethertrans *et = a;
	free(et);
}

static int ether_trans_recv(Npfcall **fcp, u32 msize, void *a)
{
	Ethertrans *et = a;
	Npfcall *fc;

	if ((fc = np_alloc_fcall(msize)) == 0)
	{
		np_uerror(ENOMEM);
		return -1;
	}

	//
	// et->saddr is later reused for sending. This is safe as 9P connections are
	// initiated by clients and lladdr gets filled in properly.
	//
	
	socklen_t sa_len = sizeof(et->saddr);
	int n;
retry:
	n = recvfrom(et->fd, fc->pkt, msize, 0,
				(struct sockaddr *)&et->saddr, &sa_len);
	if (n < 0 && errno == EINTR)
		goto retry;
	if (n < 0)
	{
		np_uerror(errno);
		goto error;
	}

	if (et->saddr.sll_protocol != htons(EXP_9P_ETH))
		goto retry;

	int size = np_peek_size(fc->pkt, n);
	if (size > msize)
	{
		np_uerror(EPROTO);
		goto error;
	}
	if (size != n -4)	// -4: csum field
	{
		np_uerror(EIO);
		goto error;
	}
	fc->size = size;
	*fcp = fc;
	return 0;

error:
	free(fc);
	return -1;
}

static int ether_trans_send(Npfcall *fc, void *a)
{
	Ethertrans *et = a;

	struct pollfd pfd = {
		.fd = et->fd,
		.events = POLLOUT,
	};

	int n = poll(&pfd, 1, 3000);
	if (n == 0)
	{
		np_uerror(ETIMEDOUT);
		return -1;
	}

	if (n < 0)
		goto error;
	
	n = sendto(et->fd, fc->pkt, fc->size, 0,
			(struct sockaddr *)&et->saddr, sizeof(et->saddr));
	if (n < 0)
		goto error;

	return 0;

error:
	np_uerror(errno);
	return n;
}

//EOF
