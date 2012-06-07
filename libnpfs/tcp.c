//
//
//

#if HAVE_CONFIG_H
#include "config.h"
#endif
#include <assert.h>
#include <errno.h>
#include <sys/time.h>
#include <stdint.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>

#include "9p.h"
#include "npfs.h"
#include "xpthread.h"
#include "npfsimpl.h"

static char *_tcp_get_ctl(char *name, void *a);

int
np_tcp_initialize(Npsrv *srv)
{
	Npfile *netroot = np_ctl_adddir (srv->ctlroot, "net");
	if (netroot == 0)
		return -1;
	Npfile *tcproot = np_ctl_adddir (netroot, "tcp");
	if (tcproot == 0)
		return -1;
	if (!np_ctl_addfile (tcproot, "clone", NULL, NULL,
			   NP_CTL_FLAGS_TCP | NP_CTL_FLAGS_TCP_CLONE))
		return -1;

	srv->tcproot = tcproot;
	return 0;
}


Npfcall *
np_tcp_lopen(Npfid *fid, u32 mode)
{
	Fid *f = fid->aux;
	Npfcall *rc = NULL;

	assert(f->file->flags & NP_CTL_FLAGS_TCP);

	int what = f->file->flags & NP_CTL_FLAGS_TCP_MASK;
	if (what == NP_CTL_FLAGS_TCP_CLONE)
	{
		Npfile *tcproot = fid->conn->srv->tcproot;

		int sock = socket(AF_INET, SOCK_STREAM, 0);
		if (sock < 0) {
			np_uerror(errno);
			goto done;
		}
		char name[64];
		snprintf(name, sizeof(name), "%d", sock);
		Npfile *sockdir = np_ctl_adddir(tcproot, name);
		if (sockdir == 0) {
			np_uerror(ENOMEM);
			goto done;
		}
		Npfile *ctlfile = np_ctl_addfile(sockdir, "ctl",
				_tcp_get_ctl, (void *)sock, NP_CTL_FLAGS_TCP | NP_CTL_FLAGS_TCP_CTL);
		if (ctlfile == 0) {
			np_uerror(ENOMEM);
			goto done;
		}

		f->file = ctlfile;
		// fid now refs net/tcp/nnn/ctl
	}
	else if (what == NP_CTL_FLAGS_TCP_CTL)
	{
		//Do nothing
	}
	else
	{
		assert(what == NP_CTL_FLAGS_TCP_DATA);

		//TODO

		np_uerror(ENOTSUP);
		goto done;
	}

	if (!(rc = np_create_rlopen (&f->file->qid, 0))) {
		np_uerror (ENOMEM);
		goto done;
	}

done:
	return rc;
}

void
np_tcp_cleanup(Npfile *file)
{
	assert(file->flags & NP_CTL_FLAGS_TCP);

	if ((file->flags & NP_CTL_FLAGS_TCP_MASK) == NP_CTL_FLAGS_TCP_DATA)
	{
		int sock = (int)file->getf_arg;
		close(sock);
	}
}

static char *_tcp_get_ctl(char *name, void *a)
{
	int sock = (int)a;
	char *s = 0;
	int len = 0;

	if (aspf (&s, &len, "%d", sock) < 0)
		np_uerror (ENOMEM);
	return s;
}

//EOF
