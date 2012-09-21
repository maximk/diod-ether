//
//
//
//
//
//

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>

#include <sys/socket.h>

#include <netpacket/packet.h>
#include <net/ethernet.h>

#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <linux/if.h>

#include "9p.h"
#include "npfs.h"

#include "diod_log.h"
#include "diod_ether.h"

struct diod_ether_t {
	int nl_sock;
	int existing_connected;
	int try;
};

static void connect_existing_interfaces(Npsrv *srv, diod_ether_t *ether);

diod_ether_t *diod_ether_create(void)
{
	diod_ether_t *ether = malloc(sizeof(*ether));
	if (ether == 0)
		msg_exit("out of memory");

	ether->nl_sock = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
	if (ether->nl_sock < 0)
		err_exit("create netlink socket failed");

	return ether;
}

void
diod_ether_destroy(diod_ether_t *ether)
{
	free(ether);
}

int
diod_ether_listen(diod_ether_t *ether)
{
	struct sockaddr_nl saddr = {
		.nl_family = AF_NETLINK,
		.nl_pid = getpid(),
		.nl_groups = RTNLGRP_LINK | RTNLGRP_NOTIFY,
	};

	if (bind(ether->nl_sock, (struct sockaddr *)&saddr, sizeof(saddr)) < 0)
		err_exit("bind netlink socket failed");
	
	ether->existing_connected = 0;
	ether->try = 0;

	return 0;
}

void
diod_ether_shutdown(diod_ether_t *ether)
{
	close(ether->nl_sock);
}

void
diod_ether_accept_one(Npsrv *srv, diod_ether_t *ether)
{
	if (!ether->existing_connected)
		connect_existing_interfaces(srv, ether);

	uint8_t buf[4096];
	int len = recv(ether->nl_sock, buf, sizeof(buf), 0);
	if (len < 0)
		err_exit("read netlink socket failed");

	//
	// The analysis of real netlink traffic tells us that we need to wait for
	// RTM_NEW_LINK messages with IFF_UP and IFF_RUNNING bits set, attribute
	// IFLA_OPERSTATE set to 0 or 6, and attribute IFLA_PROTINFO set to 3.
	// Moreover, the second such messages should be acted upon. Magic, I say.
	//
	// In addition, network interfaces coming up are filtered by their names.
	// Only those that start with "xen" are taken into account.
	//

	struct nlmsghdr *hdr = (struct nlmsghdr *)buf;
	while (NLMSG_OK(hdr, len))
	{
		struct ifinfomsg *ifi = NLMSG_DATA(hdr);

		if (hdr->nlmsg_type == RTM_NEWLINK &&
				(ifi->ifi_flags & IFF_UP) != 0 &&
				(ifi->ifi_flags & IFF_RUNNING) != 0)
		{
			struct rtattr *rta = (void *)ifi + sizeof(*ifi);
			int rta_len = len -sizeof(*ifi);

			int ifname_ok = 0;
			int oper_state_ok = 0;
			int protinfo_ok = 0;
			char *ifname = 0;
			while (RTA_OK(rta, rta_len))
			{
				int dlen = RTA_PAYLOAD(rta);
				if (rta->rta_type == IFLA_IFNAME)
				{
					ifname = RTA_DATA(rta);
					ifname_ok = ifname[0] == 'v' &&
								ifname[1] == 'i' &&
								ifname[2] == 'f';
				}
				if (rta->rta_type == IFLA_OPERSTATE && dlen == 1)
				{
					uint8_t oper_state = *(uint8_t *)RTA_DATA(rta);
					oper_state_ok = (oper_state == IF_OPER_UP) ||
									(oper_state == IF_OPER_UNKNOWN);
				}
				else if (rta->rta_type == IFLA_PROTINFO && dlen == 1)
					protinfo_ok = *(uint8_t *)RTA_DATA(rta) == 3;	// magic constant

				rta = RTA_NEXT(rta, rta_len);
			}

			if (ifname_ok && oper_state_ok && protinfo_ok && ++ether->try >= 2)
			{
				msg("ether: link %s added", ifname);
				Nptrans *trans = np_ethertrans_create(ifi->ifi_index);
				if (trans != 0)
				{
					Npconn *conn = np_conn_create(srv, trans, "ether");
					np_srv_add_conn(srv, conn);
					ether->try = 0;
				}
				else
					errn(np_rerror(), "np_ethertrans_create failed");
			}
		}

		hdr = NLMSG_NEXT(hdr, len);
	}
}

static void connect_existing_interfaces(Npsrv *srv, diod_ether_t *ether)
{
	ether->existing_connected = 1;	// only try once

	int sock = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
	if (sock < 0)
		return;

	struct sockaddr_nl saddr = {
		.nl_family = AF_NETLINK,
		.nl_pid = ~getpid(),	// getpid() already taken
		.nl_groups = 0,
	};

	if (bind(sock, (struct sockaddr *)&saddr, sizeof(saddr)) < 0)
		goto error;

	typedef struct nl_req_s nl_req_t;
	struct nl_req_s {
		struct nlmsghdr hdr;
	    struct rtgenmsg gen;
	};

	struct sockaddr_nl kernel = {
		.nl_family = AF_NETLINK,
		.nl_pid = 0,
		.nl_groups = 0,
	};
	nl_req_t req;
	req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtgenmsg));
	req.hdr.nlmsg_type = RTM_GETLINK;
	req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	req.hdr.nlmsg_seq = 1;
	req.hdr.nlmsg_pid = getpid();
	req.gen.rtgen_family = AF_PACKET; /*  no preferred AF, we will get *all* interfaces */

	struct iovec io = {
		.iov_base = &req,
		.iov_len = req.hdr.nlmsg_len,
	};

	struct msghdr rtnl_msg = {
		.msg_iov = &io,
		.msg_iovlen = 1,
		.msg_name = &kernel,
		.msg_namelen = sizeof(kernel),
	};

	if (sendmsg(sock, &rtnl_msg, 0) < 0)
		goto error;

	uint8_t reply[8192];
	struct msghdr rtnl_reply;    /* generic msghdr structure */

	io.iov_base = reply;
    io.iov_len = sizeof(reply);
    rtnl_reply.msg_iov = &io;
    rtnl_reply.msg_iovlen = 1;
    rtnl_reply.msg_name = &kernel;
    rtnl_reply.msg_namelen = sizeof(kernel);

    int len = recvmsg(sock, &rtnl_reply, 0); /* read lots of data */
	if (len < 0)
		goto error;

	struct nlmsghdr *hdr = (struct nlmsghdr *)reply;
	while (NLMSG_OK(hdr, len))
	{
		struct ifinfomsg *ifi = NLMSG_DATA(hdr);

		if (hdr->nlmsg_type == RTM_NEWLINK &&
				(ifi->ifi_flags & IFF_UP) != 0 &&
				(ifi->ifi_flags & IFF_RUNNING) != 0)
		{
			// assume no padding between ifi and the first attribute
			struct rtattr *rta = (void *)ifi + sizeof(*ifi);
			int rta_len = len -sizeof(*ifi);

			int ifname_ok = 0;
			char *ifname = 0;
			while (RTA_OK(rta, rta_len))
			{
				if (rta->rta_type == IFLA_IFNAME)
				{
					ifname = RTA_DATA(rta);
					ifname_ok = ifname[0] == 'v' &&
								ifname[1] == 'i' &&
								ifname[2] == 'f';
				}
				rta = RTA_NEXT(rta, rta_len);
			}
			
			if (ifname_ok)
			{
				msg("ether: existing link %s added", ifname);
				Nptrans *trans = np_ethertrans_create(ifi->ifi_index);
				if (trans != 0)
				{
					Npconn *conn = np_conn_create(srv, trans, "ether");
					np_srv_add_conn(srv, conn);
					ether->try = 0;
				}
				else
					errn(np_rerror(), "np_ethertrans_create failed");
			}
		}

		hdr = NLMSG_NEXT(hdr, len);
	}

	close(sock);
	return;

error:
	close(sock);
	errn(np_rerror(), "connect existing interfaces failed");
}

//EOF
