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
#include <assert.h>
#include <string.h>

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
	int ifindex;
	uint8_t mac[ETH_ALEN];
	int mac_set;
	int fd;
	Nptrans *trans;
};

static void ether_trans_destroy(void *a);
static int ether_trans_recv(Npfcall **fcp, u32 msize, void *a);
static int ether_trans_send(Npfcall *fc, void *a);

Nptrans *np_ethertrans_create(int ifindex)
{
	Ethertrans *et = malloc(sizeof(*et));

	et->ifindex = ifindex;
	et->mac_set = 0;
	// et->mac is filled in after the first receive

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

	struct sockaddr_ll saddr;
	socklen_t sa_len = sizeof(saddr);
	int n;
retry:
	n = recvfrom(et->fd, fc->pkt, msize, 0,
				(struct sockaddr *)&saddr, &sa_len);
	if (n < 0 && errno == EINTR)
		goto retry;
	if (n < 0)
	{
		np_uerror(errno);
		goto error;
	}

	if (saddr.sll_protocol != htons(EXP_9P_ETH))
		goto retry;

	//
	// 9P requires that the first message comes from the client meaning that
	// the MAC address will be ready when it is time to send the reply.
	//

	if (!et->mac_set)
	{
		assert(saddr.sll_halen == ETH_ALEN);
		memcpy(et->mac, saddr.sll_addr, ETH_ALEN);
		et->mac_set = 1;
	}

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
	
	struct sockaddr_ll saddr = {
		.sll_family = AF_PACKET,
		.sll_protocol = htons(EXP_9P_ETH),
		.sll_ifindex = et->ifindex,
		.sll_halen = ETH_ALEN,
	};

	assert(et->mac_set);
	memcpy(saddr.sll_addr, et->mac, ETH_ALEN);

	n = sendto(et->fd, fc->pkt, fc->size, 0,
			(struct sockaddr *)&saddr, sizeof(saddr));
	if (n < 0)
		goto error;

	return n;

error:
	np_uerror(errno);
	return n;
}

//EOF
