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
	int try;
};

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
					ifname_ok = ifname[0] == 'x' &&
								ifname[1] == 'e' &&
								ifname[2] == 'n';
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

			if (oper_state_ok && protinfo_ok && ++ether->try >= 2)
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

//EOF
