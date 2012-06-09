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
#include <fcntl.h>
#include <sys/time.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>

#include <sys/types.h>
#include <sys/socket.h>

#include "9p.h"
#include "npfs.h"
#include "xpthread.h"
#include "npfsimpl.h"

static Npfile *make_node(Npfile *parent, char *name, u8 type, np_file_vtab_t *vtab);
static void destroy_node(Npfile *file);
static int next_inum (void);

static int tcp_clone_open(Npfid *fid, int mode);
static void tcp_sock_cleanup(Npfile *ctlfile);

np_file_vtab_t tcp_gen_vtab = { 0 };

np_file_vtab_t tcp_clone_vtab = {
   .open = tcp_clone_open
};

np_file_vtab_t tcp_sock_vtab = {
	.cleanup = tcp_sock_cleanup
};

np_file_vtab_t tcp_ctl_vtab = { 0 };

np_file_vtab_t tcp_data_vtab = { 0 };

np_file_vtab_t tcp_listen_vtab = { 0 };

int np_file_open(Npfile *file, Npfid *fid, int mode)
{
	if (file->vtab->open != 0)
		return file->vtab->open(fid, mode);
	return 0;
}

int np_file_read(Npfile *file, u8 *data, u32 count)
{
	if (file->vtab->read != 0)
		return file->vtab->read(file, data, count);
	return 0;
}

int np_file_write(Npfile *file, u8 *data, u32 count)
{
	if (file->vtab->write != 0)
		return file->vtab->write(file, data, count);
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

static int next_inum (void)
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

	fid->aux = ctlfile;
	return 0;

error2:
	destroy_node(sockdir);
error1:
	close(sock);
	np_uerror(ENOMEM);
	return -1;
}

static void tcp_sock_cleanup(Npfile *ctlfile)
{
	close(ctlfile->sock);
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
	int n = np_file_read(file, data, count);
	if (n < 0) {
		np_uerror(errno);
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

	int n = np_file_write(file, data, count);
	if (n < 0) {
		np_uerror(errno);
		return 0;
	}
	
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
