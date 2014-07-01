/*
  2010, 2011, 2012, 2103, 2014 Stef Bon <stefbon@gmail.com>

  This program is free software; you can redistribute it and/or
  modify it under the terms of the GNU General Public License
  as published by the Free Software Foundation; either version 2
  of the License, or (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.

*/

#include "global-defines.h"

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <err.h>
#include <sys/time.h>
#include <time.h>
#include <pthread.h>
#include <ctype.h>
#include <inttypes.h>

#include <sys/param.h>
#include <sys/types.h>
#include <sys/fsuid.h>
#include <sys/stat.h>
#include <time.h>

#include <nfsc/libnfs-zdr.h>
#include <nfsc/libnfs.h>
#include <nfsc/libnfs-raw-mount.h>
#include <nfsc/libnfs-raw-nfs.h>

#ifndef ENOATTR
#define ENOATTR ENODATA        /* No such attribute */
#endif

#ifdef LOGGING

#include <syslog.h>

static unsigned char loglevel=1;

#define logoutput_debug(...) if (loglevel >= 5) syslog(LOG_DEBUG, __VA_ARGS__)
#define logoutput_info(...) if (loglevel >= 4) syslog(LOG_INFO, __VA_ARGS__)
#define logoutput_notice(...) if (loglevel >= 3) syslog(LOG_NOTICE, __VA_ARGS__)
#define logoutput_warning(...) if (loglevel >= 2) syslog(LOG_WARNING, __VA_ARGS__)
#define logoutput_error(...) if (loglevel >= 1) syslog(LOG_ERR, __VA_ARGS__)

#define logoutput(...) if (loglevel >= 1) syslog(LOG_DEBUG, __VA_ARGS__)

#else

static inline void dummy_nolog()
{
    return;

}

#define logoutput_debug(...) dummy_nolog()
#define logoutput_info(...) dummy_nolog()
#define logoutput_notice(...) dummy_nolog()
#define logoutput_warning(...) dummy_nolog()
#define logoutput_error(...) dummy_nolog()

#endif

#include "fuse-workspace.h"
#include "workerthreads.h"
#include "beventloop-utils.h"

#include "entry-management.h"

#include "path-resolution.h"
#include "utils.h"
#include "options.h"

#include "fschangenotify.h"
#include "fschangenotify-event.h"
#include "fschangenotify-fssync.h"

#include "readdir-utils.h"

#include "workspaces.h"
#include "resources.h"
#include "objects.h"

#include "nfs-common.h"
#include "libnfs-exports-sync.h"

struct fs_options_struct fs_options;
struct workerthreads_queue_struct workerthreads_queue;

extern const char *rootpath;
extern const char *dotdotname;
extern const char *dotname;

static void workspace_nfs_destroy(struct workspace_object_struct *object)
{

    logoutput("nfs_destroy: destroy overlay browsing");
}

static void workspace_nfs_lookup_cached(fuse_req_t req, struct entry_struct *entry, struct call_info_struct *call_info)
{
    struct resource_struct *resource=call_info->object->resource;
    struct net_nfs_export_struct *nfs_export=(struct net_nfs_export_struct *) resource->data;
    struct nfs_context *nfs_ctx=(struct nfs_context *) nfs_export->data;
    char *path=call_info->pathinfo.path + call_info->relpath;
    struct stat st;
    int result=0;

    memset(&st, 0, sizeof(struct stat));

    if (strlen(path)==0) path=(char *) rootpath;

    logoutput("workspace_nfs_lookup_cached, path %s", path);

    pthread_mutex_lock(&nfs_export->mutex);

    result=nfs_stat(nfs_ctx, path, &st);

    pthread_mutex_unlock(&nfs_export->mutex);

    if (result<0) {

	result=abs(result);

	if (result==ENOENT) {
	    struct inode_struct *inode=entry->inode;
	    unsigned int error=0;

	    inode=entry->inode;
	    inode->alias=NULL;

	    remove_entry(entry, &error);
	    queue_remove(call_info->object, entry, &error);
	    entry=NULL;

	}

	fuse_reply_err(req, result);

    } else {
	struct fuse_entry_param e;
	struct inode_struct *inode=entry->inode;

	inode->mode=st.st_mode;
	inode->nlink=st.st_nlink;
	inode->uid=st.st_uid;
	inode->gid=st.st_gid;

	inode->rdev=st.st_rdev;

	inode->mtim.tv_sec=st.st_mtim.tv_sec;
	inode->mtim.tv_nsec=st.st_mtim.tv_nsec;

	inode->ctim.tv_sec=st.st_ctim.tv_sec;
	inode->ctim.tv_nsec=st.st_ctim.tv_nsec;

	inode->size=st.st_size;

	e.ino = inode->ino;
	e.generation = 1;
	e.attr_timeout = fs_options.attr_timeout;
	e.entry_timeout = fs_options.entry_timeout;

	get_current_time(&entry->synctime);

	e.attr.st_dev = 0;
	e.attr.st_ino = e.ino;
	e.attr.st_mode = st.st_mode;
	e.attr.st_nlink = st.st_nlink;
	e.attr.st_uid = st.st_uid;
	e.attr.st_gid = st.st_gid;
	e.attr.st_rdev = st.st_rdev;
	e.attr.st_size = st.st_size;
	e.attr.st_atim.tv_sec = st.st_atim.tv_sec;
	e.attr.st_atim.tv_nsec = st.st_atim.tv_nsec;
	e.attr.st_mtim.tv_sec = st.st_mtim.tv_sec;
	e.attr.st_mtim.tv_nsec = st.st_mtim.tv_nsec;
	e.attr.st_ctim.tv_sec = st.st_ctim.tv_sec;
	e.attr.st_ctim.tv_nsec = st.st_ctim.tv_nsec;

	e.attr.st_blksize=_DEFAULT_BLOCKSIZE;

	if (inode->size % e.attr.st_blksize == 0) {

	    e.attr.st_blocks = inode->size / e.attr.st_blksize;

	} else {

	    e.attr.st_blocks = 1 + inode->size / e.attr.st_blksize;

	}

	fuse_reply_entry(req, &e);

    }

    free_path_pathinfo(&call_info->pathinfo);

}

static void workspace_nfs_lookup_noncached(fuse_req_t req, struct inode_struct *pinode, struct name_struct *xname, struct call_info_struct *call_info)
{
    struct resource_struct *resource=call_info->object->resource;
    struct net_nfs_export_struct *nfs_export=(struct net_nfs_export_struct *) resource->data;
    struct nfs_context *nfs_ctx=(struct nfs_context *) nfs_export->data;
    char *path=call_info->pathinfo.path + call_info->relpath;
    struct stat st;
    int result=0;

    memset(&st, 0, sizeof(struct stat));

    if (strlen(path)==0) path=(char *) rootpath;

    logoutput("workspace_nfs_lookup_noncached, path %s", path);

    pthread_mutex_lock(&nfs_export->mutex);

    result=nfs_stat(nfs_ctx, path, &st);

    pthread_mutex_unlock(&nfs_export->mutex);

    if (result<0) {

	fuse_reply_err(req, abs(result));

    } else {
	struct entry_struct *entry=NULL, *parent=pinode->alias;
	struct inode_struct *inode;

	entry=create_entry(parent, xname);
	inode=create_inode();

	if (entry && inode) {
	    struct fuse_entry_param e;
	    unsigned int error=0;

	    add_inode_hashtable(inode, increase_inodes_workspace, (void *) call_info->workspace_mount);
	    insert_entry(entry, &error, 0);

	    adjust_pathmax(call_info->pathinfo.len);
	    get_current_time(&entry->synctime);

	    inode->mode=st.st_mode;
	    inode->nlink=st.st_nlink;
	    inode->uid=st.st_uid;
	    inode->gid=st.st_gid;

	    inode->rdev=st.st_rdev;

	    inode->mtim.tv_sec=st.st_mtim.tv_sec;
	    inode->mtim.tv_nsec=st.st_mtim.tv_nsec;

	    inode->ctim.tv_sec=st.st_ctim.tv_sec;
	    inode->ctim.tv_nsec=st.st_ctim.tv_nsec;

	    inode->size=st.st_size;

	    e.ino = inode->ino;
	    e.generation = 1;
	    e.attr_timeout = fs_options.attr_timeout;
	    e.entry_timeout = fs_options.entry_timeout;

	    e.attr.st_dev = 0;
	    e.attr.st_ino = e.ino;
	    e.attr.st_mode = st.st_mode;
	    e.attr.st_nlink = st.st_nlink;
	    e.attr.st_uid = st.st_uid;
	    e.attr.st_gid = st.st_gid;
	    e.attr.st_rdev = st.st_rdev;
	    e.attr.st_size = st.st_size;
	    e.attr.st_atim.tv_sec = st.st_atim.tv_sec;
	    e.attr.st_atim.tv_nsec = st.st_atim.tv_nsec;
	    e.attr.st_mtim.tv_sec = st.st_mtim.tv_sec;
	    e.attr.st_mtim.tv_nsec = st.st_mtim.tv_nsec;
	    e.attr.st_ctim.tv_sec = st.st_ctim.tv_sec;
	    e.attr.st_ctim.tv_nsec = st.st_ctim.tv_nsec;

	    e.attr.st_blksize=_DEFAULT_BLOCKSIZE;

	    if (inode->size % e.attr.st_blksize == 0) {

		e.attr.st_blocks=inode->size / e.attr.st_blksize;

	    } else {

		e.attr.st_blocks=1 + inode->size / e.attr.st_blksize;

	    }

	    fuse_reply_entry(req, &e);

	} else {

	    /* not enough memory to allocate entry and/or inode */

	    if (entry) {

		destroy_entry(entry);
		entry=NULL;

	    }

	    if (inode) {

		free(inode);
		inode=NULL;

	    }

	    fuse_reply_err(req, ENOMEM);

	}

    }

    free_path_pathinfo(&call_info->pathinfo);

}

static void workspace_nfs_setattr(fuse_req_t req, struct entry_struct *entry, struct call_info_struct *call_info, struct stat *st, int fuse_set)
{
    struct resource_struct *resource=call_info->object->resource;
    struct net_nfs_export_struct *nfs_export=(struct net_nfs_export_struct *) resource->data;
    struct nfs_context *nfs_ctx=(struct nfs_context *) nfs_export->data;
    char *path=call_info->pathinfo.path + call_info->relpath;
    int result=0;
    struct inode_struct *inode=entry->inode;

    if (strlen(path)==0) path=(char *) rootpath;

    logoutput("workspace_nfs_setattr, path %s", path);

    if (fuse_set & FUSE_SET_ATTR_MODE) {

	pthread_mutex_lock(&nfs_export->mutex);

	result=nfs_chmod(nfs_ctx, path, st->st_mode);

	pthread_mutex_unlock(&nfs_export->mutex);

	if (result<0) {

	    fuse_reply_err(req, -result);
	    free_path_pathinfo(&call_info->pathinfo);
	    return;

	} else {

	    inode->mode=st->st_mode;

	}

    }

    if (fuse_set & (FUSE_SET_ATTR_UID | FUSE_SET_ATTR_GID)) {
	uid_t uid=inode->uid;
	gid_t gid=inode->gid;

	if (fuse_set & FUSE_SET_ATTR_UID) uid=st->st_uid;
	if (fuse_set & FUSE_SET_ATTR_GID) gid=st->st_gid;

	result=nfs_chown(nfs_ctx, path, uid, gid);

	if (result<0) {

	    fuse_reply_err(req, -result);
	    free_path_pathinfo(&call_info->pathinfo);
	    return;

	} else {

	    if (fuse_set & FUSE_SET_ATTR_UID) {

		inode->uid=st->st_uid;

	    } else {

		st->st_uid=inode->uid;

	    }

	    if (fuse_set & FUSE_SET_ATTR_GID) {

		inode->gid=st->st_gid;

	    } else {

		st->st_gid=inode->gid;

	    }

	}

    }

    if (fuse_set & FUSE_SET_ATTR_SIZE) {


	pthread_mutex_lock(&nfs_export->mutex);

	result=nfs_truncate(nfs_ctx, path, st->st_size);

	pthread_mutex_unlock(&nfs_export->mutex);

	if (result<0) {

	    fuse_reply_err(req, -result);
	    free_path_pathinfo(&call_info->pathinfo);
	    return;

	} else {

	    inode->size=st->st_size;

	}

    }

    if (fuse_set & (FUSE_SET_ATTR_ATIME | FUSE_SET_ATTR_MTIME)) {
	struct timespec rightnow;
	struct timeval newtimes[2];

	newtimes[0].tv_sec=0;
	newtimes[0].tv_usec=0;

	newtimes[1].tv_sec=inode->mtim.tv_sec;
	newtimes[1].tv_usec=inode->mtim.tv_nsec / 1000;

	if (fuse_set & (FUSE_SET_ATTR_ATIME_NOW | FUSE_SET_ATTR_MTIME_NOW)) get_current_time(&rightnow);

	if (fuse_set & FUSE_SET_ATTR_ATIME) {

	    if (fuse_set & FUSE_SET_ATTR_ATIME_NOW) {

		st->st_atim.tv_sec = rightnow.tv_sec;
		st->st_atim.tv_nsec = rightnow.tv_nsec;

	    }

	    newtimes[0].tv_sec=st->st_atim.tv_sec;
	    newtimes[0].tv_usec = st->st_atim.tv_nsec / 1000;


	}

	if (fuse_set & FUSE_SET_ATTR_MTIME) {

	    if (fuse_set & FUSE_SET_ATTR_MTIME_NOW) {

		st->st_mtim.tv_sec = rightnow.tv_sec;
		st->st_mtim.tv_nsec = rightnow.tv_nsec;

	    }

	    newtimes[1].tv_sec = st->st_mtim.tv_sec;
	    newtimes[1].tv_usec = st->st_mtim.tv_nsec / 1000;

	}

	pthread_mutex_lock(&nfs_export->mutex);

	result=nfs_utimes(nfs_ctx, path, newtimes);

	pthread_mutex_unlock(&nfs_export->mutex);

	if (result<0) {

	    fuse_reply_err(req, -result);
	    free_path_pathinfo(&call_info->pathinfo);
	    return;

	} else {

	    if (fuse_set & FUSE_SET_ATTR_MTIME) {

		inode->mtim.tv_sec=newtimes[1].tv_sec;
		inode->mtim.tv_nsec=newtimes[1].tv_usec * 1000;

	    }

	}

    }

    out:

    st->st_dev=0;
    st->st_ino=inode->ino;
    st->st_mode=inode->mode;
    st->st_nlink=inode->nlink;
    st->st_uid=inode->uid;
    st->st_gid=inode->gid;
    st->st_rdev=inode->rdev;
    st->st_size=inode->size;

    st->st_blksize=_DEFAULT_BLOCKSIZE;

    if (inode->size % st->st_blksize == 0) {

	st->st_blocks = inode->size / st->st_blksize;

    } else {

	st->st_blocks = 1 + inode->size / st->st_blksize;

    }

    memcpy(&st->st_mtim, &inode->mtim, sizeof(struct timespec));
    memcpy(&st->st_ctim, &inode->ctim, sizeof(struct timespec));

    st->st_atim.tv_sec=0;
    st->st_atim.tv_nsec=0;

    fuse_reply_attr(req, st, fs_options.attr_timeout);

    free_path_pathinfo(&call_info->pathinfo);

}

static void workspace_nfs_getattr(fuse_req_t req, struct entry_struct *entry, struct call_info_struct *call_info)
{
    struct resource_struct *resource=call_info->object->resource;
    struct net_nfs_export_struct *nfs_export=(struct net_nfs_export_struct *) resource->data;
    struct nfs_context *nfs_ctx=(struct nfs_context *) nfs_export->data;
    char *path=call_info->pathinfo.path + call_info->relpath;
    struct stat st;
    int result=0;

    if (strlen(path)==0) path=(char *) rootpath;

    memset(&st, 0, sizeof(struct stat));

    logoutput("workspace_nfs_getattr, path %s", path);

    pthread_mutex_lock(&nfs_export->mutex);

    result=nfs_stat(nfs_ctx, path, &st);

    pthread_mutex_unlock(&nfs_export->mutex);

    if (result<0) {

	fuse_reply_err(req, abs(result));

    } else {
	struct inode_struct *inode=entry->inode;

	inode->mode=st.st_mode;
	inode->nlink=st.st_nlink;
	inode->uid=st.st_uid;
	inode->gid=st.st_gid;
	inode->rdev=st.st_rdev;
	inode->size=st.st_size;

	st.st_blksize=_DEFAULT_BLOCKSIZE;

	if (inode->size % st.st_blksize == 0) {

	    st.st_blocks=inode->size / st.st_blksize;

	} else {

	    st.st_blocks=1 + inode->size / st.st_blksize;

	}

	inode->mtim.tv_sec=st.st_mtim.tv_sec;
	inode->mtim.tv_nsec=st.st_mtim.tv_nsec;

	inode->ctim.tv_sec=st.st_ctim.tv_sec;
	inode->ctim.tv_nsec=st.st_ctim.tv_nsec;

	st.st_ino=inode->ino;
	st.st_dev=0;

	fuse_reply_attr(req, &st, fs_options.attr_timeout);

    }

    free_path_pathinfo(&call_info->pathinfo);

}

static void workspace_nfs_readlink(fuse_req_t req, struct entry_struct *entry, struct call_info_struct *call_info)
{
    struct resource_struct *resource=call_info->object->resource;
    struct net_nfs_export_struct *nfs_export=(struct net_nfs_export_struct *) resource->data;
    struct nfs_context *nfs_ctx=(struct nfs_context *) nfs_export->data;
    char *path=call_info->pathinfo.path + call_info->relpath;
    int result=0;
    int len=512;
    char buffer[len];

    if (strlen(path)==0) path=(char *) rootpath;

    logoutput("workspace_nfs_readlink, path %s", path);

    /*
	TODO: make this buffer variable, only how to correct that?
	what error gives nfs_readlink back when buffer is too small?
    */

    pthread_mutex_lock(&nfs_export->mutex);

    result=nfs_readlink(nfs_ctx, path, buffer, len);

    pthread_mutex_unlock(&nfs_export->mutex);

    if (result<0) {

	logoutput("workspace_nfs_readlink, error reading readlink of %s, error %i:%s", path, abs(result), nfs_get_error(nfs_ctx));

	fuse_reply_err(req, abs(result));

    } else {

	fuse_reply_readlink(req, buffer);

    }

    free_path_pathinfo(&call_info->pathinfo);

}

static void workspace_nfs_mkdir(fuse_req_t req, struct inode_struct *pinode, struct name_struct *xname, struct call_info_struct *call_info, mode_t mode)
{
    struct resource_struct *resource=call_info->object->resource;
    struct net_nfs_export_struct *nfs_export=(struct net_nfs_export_struct *) resource->data;
    struct nfs_context *nfs_ctx=(struct nfs_context *) nfs_export->data;
    char *path=call_info->pathinfo.path + call_info->relpath;
    struct entry_struct *entry=NULL, *parent=pinode->alias;
    struct inode_struct *inode;

    logoutput("workspace_nfs_mkdir, path %s", path);

    entry=create_entry(parent, xname);
    inode=create_inode();

    if (entry && inode) {
	int result=0;

	inode->alias=entry;
	entry->inode=inode;

	pthread_mutex_lock(&nfs_export->mutex);

	result=nfs_mkdir(nfs_ctx, path);

	pthread_mutex_unlock(&nfs_export->mutex);

	if (result==0) {
	    struct fuse_entry_param e;
	    unsigned int error=0;
	    struct stat st;

	    memset(&st, 0, sizeof(struct stat));

	    add_inode_hashtable(inode, increase_inodes_workspace, (void *) call_info->object->workspace_mount);
	    insert_entry(entry, &error, 0);

	    adjust_pathmax(call_info->pathinfo.len);

	    pthread_mutex_lock(&nfs_export->mutex);

	    nfs_chmod(nfs_ctx, path, mode);
	    nfs_stat(nfs_ctx, path, &st);

	    pthread_mutex_unlock(&nfs_export->mutex);

	    inode->nlookup=1;
	    inode->mode=st.st_mode;
	    inode->nlink=st.st_nlink;
	    inode->uid=st.st_uid;
	    inode->gid=st.st_gid;

	    inode->rdev=st.st_rdev;
	    inode->size=st.st_size;

	    inode->mtim.tv_sec=st.st_mtim.tv_sec;
	    inode->mtim.tv_nsec=st.st_mtim.tv_nsec;

	    inode->ctim.tv_sec=st.st_ctim.tv_sec;
	    inode->ctim.tv_nsec=st.st_ctim.tv_nsec;

	    e.ino = inode->ino;
	    e.generation = 1;
	    e.attr_timeout = fs_options.attr_timeout;
	    e.entry_timeout = fs_options.entry_timeout;

	    e.attr.st_ino = e.ino;
	    e.attr.st_mode = st.st_mode;
	    e.attr.st_nlink = st.st_nlink;
	    e.attr.st_uid = st.st_uid;
	    e.attr.st_gid = st.st_gid;
	    e.attr.st_rdev = st.st_rdev;
	    e.attr.st_size = st.st_size;
	    e.attr.st_atim.tv_sec = st.st_atim.tv_sec;
	    e.attr.st_atim.tv_nsec = st.st_atim.tv_nsec;
	    e.attr.st_mtim.tv_sec = st.st_mtim.tv_sec;
	    e.attr.st_mtim.tv_nsec = st.st_mtim.tv_nsec;
	    e.attr.st_ctim.tv_sec = st.st_ctim.tv_sec;
	    e.attr.st_ctim.tv_nsec = st.st_ctim.tv_nsec;

	    e.attr.st_blksize=_DEFAULT_BLOCKSIZE;

	    if (inode->size % e.attr.st_blksize == 0) {

		e.attr.st_blocks=inode->size / e.attr.st_blksize;

	    } else {

		e.attr.st_blocks=1 + inode->size / e.attr.st_blksize;

	    }

	    fuse_reply_entry(req, &e);

	} else {

	    /* error nfs create */

	    destroy_entry(entry);
	    free(inode);

	    fuse_reply_err(req, abs(result));

	}

    } else {

	/* not enough memory to allocate entry and/or inode */

	if (entry) {

	    destroy_entry(entry);
	    entry=NULL;

	}

	if (inode) {

	    free(inode);
	    inode=NULL;

	}

	fuse_reply_err(req, ENOMEM);

    }

    free_path_pathinfo(&call_info->pathinfo);

}

static void workspace_nfs_mknod(fuse_req_t req, struct inode_struct *pinode, struct name_struct *xname, struct call_info_struct *call_info, mode_t mode, dev_t rdev)
{
    struct resource_struct *resource=call_info->object->resource;
    struct net_nfs_export_struct *nfs_export=(struct net_nfs_export_struct *) resource->data;
    struct nfs_context *nfs_ctx=(struct nfs_context *) nfs_export->data;
    char *path=call_info->pathinfo.path + call_info->relpath;
    struct entry_struct *entry=NULL, *parent=pinode->alias;
    struct inode_struct *inode;

    logoutput("workspace_nfs_mknod, path %s", path);

    entry=create_entry(parent, xname);
    inode=create_inode();

    if (entry && inode) {
	int result=0;

	inode->alias=entry;
	entry->inode=inode;

        pthread_mutex_lock(&nfs_export->mutex);

	result=nfs_mknod(nfs_ctx, path, mode, rdev);

	pthread_mutex_unlock(&nfs_export->mutex);

	if (result==0) {
	    struct fuse_entry_param e;
	    unsigned int error=0;
	    struct stat st;

	    memset(&st, 0, sizeof(struct stat));

	    add_inode_hashtable(inode, increase_inodes_workspace, (void *) call_info->object->workspace_mount);
	    insert_entry(entry, &error, 0);

	    adjust_pathmax(call_info->pathinfo.len);

	    pthread_mutex_lock(&nfs_export->mutex);

	    nfs_chmod(nfs_ctx, path, mode);
	    nfs_stat(nfs_ctx, path, &st);

	    pthread_mutex_unlock(&nfs_export->mutex);

	    inode->nlookup=1;
	    inode->mode=st.st_mode;
	    inode->nlink=st.st_nlink;
	    inode->uid=st.st_uid;
	    inode->gid=st.st_gid;

	    inode->rdev=st.st_rdev;
	    inode->size=st.st_size;

	    inode->mtim.tv_sec=st.st_mtim.tv_sec;
	    inode->mtim.tv_nsec=st.st_mtim.tv_nsec;

	    inode->ctim.tv_sec=st.st_ctim.tv_sec;
	    inode->ctim.tv_nsec=st.st_ctim.tv_nsec;

	    e.ino = inode->ino;
	    e.generation = 1;
	    e.attr_timeout = fs_options.attr_timeout;
	    e.entry_timeout = fs_options.entry_timeout;

	    e.attr.st_ino = e.ino;
	    e.attr.st_mode = st.st_mode;
	    e.attr.st_nlink = st.st_nlink;
	    e.attr.st_uid = st.st_uid;
	    e.attr.st_gid = st.st_gid;
	    e.attr.st_rdev = st.st_rdev;
	    e.attr.st_atim.tv_sec = st.st_atim.tv_sec;
	    e.attr.st_atim.tv_nsec = st.st_atim.tv_nsec;
	    e.attr.st_mtim.tv_sec = st.st_mtim.tv_sec;
	    e.attr.st_mtim.tv_nsec = st.st_mtim.tv_nsec;
	    e.attr.st_ctim.tv_sec = st.st_ctim.tv_sec;
	    e.attr.st_ctim.tv_nsec = st.st_ctim.tv_nsec;

	    e.attr.st_blksize=_DEFAULT_BLOCKSIZE;

	    if (inode->size % e.attr.st_blksize == 0) {

		e.attr.st_blocks=inode->size / e.attr.st_blksize;

	    } else {

		e.attr.st_blocks=1 + inode->size / e.attr.st_blksize;

	    }

	    fuse_reply_entry(req, &e);

	} else {

	    /* error nfs create */

	    destroy_entry(entry);
	    free(inode);

	    fuse_reply_err(req, abs(result));

	}

    } else {

	/* not enough memory to allocate entry and/or inode */

	if (entry) {

	    destroy_entry(entry);
	    entry=NULL;

	}

	if (inode) {

	    free(inode);
	    inode=NULL;

	}

	fuse_reply_err(req, ENOMEM);

    }

    free_path_pathinfo(&call_info->pathinfo);

}

static void workspace_nfs_open(fuse_req_t req, struct workspace_fh_struct *fh)
{
    struct resource_struct *resource=fh->object->resource;
    struct net_nfs_export_struct *nfs_export=(struct net_nfs_export_struct *) resource->data;
    struct nfs_context *nfs_ctx=(struct nfs_context *) nfs_export->data;
    char *path=fh->pathinfo.path + fh->relpath;
    struct nfsfh *nfsfh=NULL;
    int result=0;

    if (strlen(path)==0) path=(char *) rootpath;

    logoutput("workspace_nfs_open, path %s", path);

    pthread_mutex_lock(&nfs_export->mutex);

    result=nfs_open(nfs_ctx, path, fh->flags, &nfsfh);

    pthread_mutex_unlock(&nfs_export->mutex);

    if (result==0) {

	fh->handle.data=(void *) nfsfh;
	fuse_reply_open(req, fh->fi);

    } else {

	fuse_reply_err(req, abs(result));

    }

    free_path_pathinfo(&fh->pathinfo);

}

static void workspace_nfs_read(fuse_req_t req, size_t size, off_t offset, struct workspace_fh_struct *fh)
{
    struct resource_struct *resource=fh->object->resource;
    struct net_nfs_export_struct *nfs_export=(struct net_nfs_export_struct *) resource->data;
    struct nfs_context *nfs_ctx=(struct nfs_context *) nfs_export->data;
    struct nfsfh *nfsfh=(struct nfsfh *) fh->handle.data;
    int result=0;
    char *buff;

    buff=malloc(size);

    if (! buff) {

	fuse_reply_err(req, ENOMEM);
	return;

    }

    logoutput("workspace_nfs_read");

    pthread_mutex_lock(&nfs_export->mutex);

    result=nfs_pread(nfs_ctx, nfsfh, offset, size, buff);

    pthread_mutex_unlock(&nfs_export->mutex);

    if (result>=0) {

	fuse_reply_buf(req, buff, result);

    } else {

	fuse_reply_err(req, abs(result));

    }

}
static void workspace_nfs_write(fuse_req_t req, const char *buff, size_t size, off_t offset, struct workspace_fh_struct *fh)
{
    struct resource_struct *resource=fh->object->resource;
    struct net_nfs_export_struct *nfs_export=(struct net_nfs_export_struct *) resource->data;
    struct nfs_context *nfs_ctx=(struct nfs_context *) nfs_export->data;
    struct nfsfh *nfsfh=(struct nfsfh *) fh->handle.data;
    int result=0;

    logoutput("workspace_nfs_write");

    pthread_mutex_lock(&nfs_export->mutex);

    result=nfs_pwrite(nfs_ctx, nfsfh, offset, size, (void *) (intptr_t) buff);

    pthread_mutex_unlock(&nfs_export->mutex);

    if (result>=0) {

	fuse_reply_write(req, result);

    } else {

	fuse_reply_err(req, abs(result));

    }

}

static void workspace_nfs_fsync(fuse_req_t req, int datasync, struct workspace_fh_struct *fh)
{
    struct resource_struct *resource=fh->object->resource;
    struct net_nfs_export_struct *nfs_export=(struct net_nfs_export_struct *) resource->data;
    struct nfs_context *nfs_ctx=(struct nfs_context *) nfs_export->data;
    struct nfsfh *nfsfh=(struct nfsfh *) fh->handle.data;
    int result=0;

    logoutput("workspace_nfs_fsync");

    pthread_mutex_lock(&nfs_export->mutex);

    result=nfs_close(nfs_ctx, nfsfh);

    pthread_mutex_unlock(&nfs_export->mutex);

    fuse_reply_err(req, abs(result));

}

static void workspace_nfs_fgetattr(fuse_req_t req, struct workspace_fh_struct *fh)
{
    struct resource_struct *resource=fh->object->resource;
    struct net_nfs_export_struct *nfs_export=(struct net_nfs_export_struct *) resource->data;
    struct nfs_context *nfs_ctx=(struct nfs_context *) nfs_export->data;
    struct nfsfh *nfsfh=(struct nfsfh *) fh->handle.data;
    int result=0;
    struct stat st;

    logoutput("workspace_nfs_fgetattr");

    memset(&st, 0, sizeof(struct stat));

    pthread_mutex_lock(&nfs_export->mutex);

    result=nfs_fstat(nfs_ctx, nfsfh, &st);

    pthread_mutex_unlock(&nfs_export->mutex);

    if (result==0) {

	fuse_reply_attr(req, &st, fs_options.attr_timeout);

    } else {

	fuse_reply_err(req, -result);

    }

}

static void workspace_nfs_fsetattr(fuse_req_t req, struct workspace_fh_struct *fh, struct stat *st, int toset)
{
    struct resource_struct *resource=fh->object->resource;
    struct net_nfs_export_struct *nfs_export=(struct net_nfs_export_struct *) resource->data;
    struct nfs_context *nfs_ctx=(struct nfs_context *) nfs_export->data;
    struct nfsfh *nfsfh=(struct nfsfh *) fh->handle.data;
    int result=0;
    struct inode_struct *inode=fh->entry->inode;

    logoutput("workspace_nfs_fsetattr");

    if (toset & FUSE_SET_ATTR_MODE) {

        pthread_mutex_lock(&nfs_export->mutex);

	result=nfs_fchmod(nfs_ctx, nfsfh, st->st_mode);

	pthread_mutex_unlock(&nfs_export->mutex);

	if (result<0) {

	    fuse_reply_err(req, -result);
	    return;

	} else {

	    inode->mode=st->st_mode;

	}

    }

    if (toset & (FUSE_SET_ATTR_UID | FUSE_SET_ATTR_GID)) {
	uid_t uid=inode->uid;
	gid_t gid=inode->gid;

	if (toset & FUSE_SET_ATTR_UID) uid=st->st_uid;
	if (toset & FUSE_SET_ATTR_GID) gid=st->st_gid;

	pthread_mutex_lock(&nfs_export->mutex);

	result=nfs_fchown(nfs_ctx, nfsfh, uid, gid);

	pthread_mutex_unlock(&nfs_export->mutex);

	if (result<0) {

	    fuse_reply_err(req, -result);
	    return;

	} else {

	    if (toset & FUSE_SET_ATTR_UID) {

		inode->uid=st->st_uid;

	    } else {

		st->st_uid=inode->uid;

	    }

	    if (toset & FUSE_SET_ATTR_GID) {

		inode->gid=st->st_gid;

	    } else {

		st->st_gid=inode->gid;

	    }

	}

    }

    if (toset & FUSE_SET_ATTR_SIZE) {

        pthread_mutex_lock(&nfs_export->mutex);

	result=nfs_ftruncate(nfs_ctx, nfsfh, st->st_size);

        pthread_mutex_unlock(&nfs_export->mutex);

	if (result<0) {

	    fuse_reply_err(req, -result);
	    return;

	} else {

	    inode->size=st->st_size;

	}

    }

    if (toset & (FUSE_SET_ATTR_ATIME | FUSE_SET_ATTR_MTIME)) {

	logoutput("workspace_mfs_fsetattr: setting times through filehandle not supported yet");

    }

    out:

    st->st_dev=0;
    st->st_ino=inode->ino;
    st->st_mode=inode->mode;
    st->st_nlink=inode->nlink;
    st->st_uid=inode->uid;
    st->st_gid=inode->gid;
    st->st_rdev=inode->rdev;
    st->st_size=inode->size;

    st->st_blksize=_DEFAULT_BLOCKSIZE;

    if (inode->size % st->st_blksize == 0) {

	st->st_blocks = inode->size / st->st_blksize;

    } else {

	st->st_blocks = 1 + inode->size / st->st_blksize;

    }

    memcpy(&st->st_mtim, &inode->mtim, sizeof(struct timespec));
    memcpy(&st->st_ctim, &inode->ctim, sizeof(struct timespec));

    st->st_atim.tv_sec=0;
    st->st_atim.tv_nsec=0;

    fuse_reply_attr(req, st, fs_options.attr_timeout);

}

static void workspace_nfs_create(fuse_req_t req, struct inode_struct *pinode, struct name_struct *xname, struct workspace_fh_struct *fh, mode_t mode)
{
    struct resource_struct *resource=fh->object->resource;
    struct net_nfs_export_struct *nfs_export=(struct net_nfs_export_struct *) resource->data;
    struct nfs_context *nfs_ctx=(struct nfs_context *) nfs_export->data;
    char *path=fh->pathinfo.path + fh->relpath;
    struct entry_struct *entry=NULL, *parent=pinode->alias;
    struct inode_struct *inode;
    struct nfsfh *nfsfh=NULL;

    logoutput("workspace_nfs_create, path %s", path);

    entry=create_entry(parent, xname);
    inode=create_inode();

    if (entry && inode) {
	int result=0;

	inode->alias=entry;
	entry->inode=inode;

	pthread_mutex_lock(&nfs_export->mutex);

	result=nfs_creat(nfs_ctx, path, mode, &nfsfh);

	pthread_mutex_unlock(&nfs_export->mutex);

	if (result==0) {
	    struct fuse_entry_param e;
	    unsigned int error=0;
	    struct stat st;

	    memset(&st, 0, sizeof(struct stat));

	    add_inode_hashtable(inode, increase_inodes_workspace, (void *) fh->object->workspace_mount);
	    insert_entry(entry, &error, 0);

	    adjust_pathmax(fh->pathinfo.len);

	    nfs_fstat(nfs_ctx, nfsfh, &st);

	    inode->nlookup=1;
	    inode->mode=st.st_mode;
	    inode->nlink=st.st_nlink;
	    inode->uid=st.st_uid;
	    inode->gid=st.st_gid;

	    inode->rdev=st.st_rdev;
	    inode->size=st.st_size;

	    inode->mtim.tv_sec=st.st_mtim.tv_sec;
	    inode->mtim.tv_nsec=st.st_mtim.tv_nsec;

	    inode->ctim.tv_sec=st.st_ctim.tv_sec;
	    inode->ctim.tv_nsec=st.st_ctim.tv_nsec;

	    e.ino = inode->ino;
	    e.generation = 1;
	    e.attr_timeout = fs_options.attr_timeout;
	    e.entry_timeout = fs_options.entry_timeout;

	    e.attr.st_ino = e.ino;
	    e.attr.st_mode = st.st_mode;
	    e.attr.st_nlink = st.st_nlink;
	    e.attr.st_uid = st.st_uid;
	    e.attr.st_gid = st.st_gid;
	    e.attr.st_rdev = st.st_rdev;
	    e.attr.st_atim.tv_sec = st.st_atim.tv_sec;
	    e.attr.st_atim.tv_nsec = st.st_atim.tv_nsec;
	    e.attr.st_mtim.tv_sec = st.st_mtim.tv_sec;
	    e.attr.st_mtim.tv_nsec = st.st_mtim.tv_nsec;
	    e.attr.st_ctim.tv_sec = st.st_ctim.tv_sec;
	    e.attr.st_ctim.tv_nsec = st.st_ctim.tv_nsec;

	    e.attr.st_blksize=_DEFAULT_BLOCKSIZE;

	    if (inode->size % e.attr.st_blksize == 0) {

		e.attr.st_blocks=inode->size / e.attr.st_blksize;

	    } else {

		e.attr.st_blocks=1 + inode->size / e.attr.st_blksize;

	    }

	    fh->handle.data=(void *) nfsfh;

	    fuse_reply_create(req, &e, fh->fi);

	} else {

	    /* error nfs create */

	    destroy_entry(entry);
	    free(inode);

	    fuse_reply_err(req, abs(result));

	}

    } else {

	/* not enough memory to allocate entry and/or inode */

	if (entry) {

	    destroy_entry(entry);
	    entry=NULL;

	}

	if (inode) {

	    free(inode);
	    inode=NULL;

	}

	fuse_reply_err(req, ENOMEM);

    }

    free_path_pathinfo(&fh->pathinfo);

}

static void workspace_nfs_release(fuse_req_t req, struct workspace_fh_struct *fh)
{
    struct resource_struct *resource=fh->object->resource;
    struct net_nfs_export_struct *nfs_export=(struct net_nfs_export_struct *) resource->data;
    struct nfs_context *nfs_ctx=(struct nfs_context *) nfs_export->data;
    struct nfsfh *nfsfh=(struct nfsfh *) fh->handle.data;
    struct fuse_file_info *fi=fh->fi;

    logoutput("workspace_nfs_release");

    if (nfsfh) {
	int result=0;

        pthread_mutex_lock(&nfs_export->mutex);

	result=nfs_close(nfs_ctx, nfsfh);

        pthread_mutex_unlock(&nfs_export->mutex);

    }

    free(fh);

    fi->fh=0;

    fuse_reply_err(req, 0);

}

static void remove_old_entries(struct workspace_object_struct *object, struct directory_struct *directory, struct timespec *synctime)
{
    struct entry_struct *entry;

    logoutput("remove_old_entries: synctime %li:%li", synctime->tv_sec, synctime->tv_nsec);

    /* TODO: add locking */

    entry=(struct entry_struct *) directory->first;

    while (entry) {

	if (entry->inode && entry->inode->mode==0) {

	    entry=entry->name_next;
	    continue;

	}

	if (entry->synctime.tv_sec<synctime->tv_sec || 
	    (entry->synctime.tv_sec==synctime->tv_sec && entry->synctime.tv_nsec<synctime->tv_nsec)) {
	    struct entry_struct *next=entry->name_next;
	    unsigned int error=0;

	    logoutput("remove_old_entries: remove %s synctime %li:%li", entry->name.name, entry->synctime.tv_sec, entry->synctime.tv_nsec);

	    remove_entry(entry, &error);

	    if (error==0) queue_remove(object, entry, &error);

	    entry=next;

	} else {

	    entry=entry->name_next;

	}

    }

}

static mode_t translate_libnfs_type(uint32_t type)
{
    mode_t mode=0;

    if (type==NF3REG) {

	mode=S_IFREG;

    } else if (type==NF3DIR) {

	mode=S_IFDIR;

    } else if (type==NF3BLK) {

	mode=S_IFBLK;

    } else if (type==NF3CHR) {

	mode=S_IFCHR;

    } else if (type==NF3LNK) {

	mode=S_IFLNK;

    } else if (type==NF3SOCK) {

	mode=S_IFSOCK;

    } else if (type==NF3FIFO) {

	mode=S_IFIFO;

    }

    return mode;

}


static void workspace_nfs_opendir(fuse_req_t req, struct workspace_dh_struct *dh)
{
    struct resource_struct *resource=dh->object->resource;
    struct net_nfs_export_struct *nfs_export=(struct net_nfs_export_struct *) resource->data;
    struct nfs_context *nfs_ctx=(struct nfs_context *) nfs_export->data;
    char *path=dh->pathinfo.path + dh->relpath;
    unsigned int error=0;
    struct directory_struct *directory=dh->directory;
    struct nfsdir *dir=NULL;
    int result=0;

    if (strlen(path)==0) path=(char *) rootpath;

    logoutput("workspace_nfs_opendir: path %s", path);

    pthread_mutex_lock(&nfs_export->mutex);

    result=nfs_opendir(nfs_ctx, path, &dir);

    pthread_mutex_unlock(&nfs_export->mutex);

    if (result==0) {

	dh->handle.data = (void *) dir;

        fuse_reply_open(req, dh->fi);
	free_path_pathinfo(&dh->pathinfo);

	return;

    } else {

	error=abs(result);

    }

    logoutput("workspace_opendir, error %i", error);

    fuse_reply_err(req, error);
    free_path_pathinfo(&dh->pathinfo);

}

static void workspace_nfs_readdir_simple(fuse_req_t req, size_t size, off_t offset, struct workspace_dh_struct *dh)
{
    struct resource_struct *resource=dh->object->resource;
    struct net_nfs_export_struct *nfs_export=(struct net_nfs_export_struct *) resource->data;
    struct nfs_context *nfs_ctx=(struct nfs_context *) nfs_export->data;
    unsigned int error=0;
    char *buff=NULL;
    size_t pos=0;
    size_t dirent_size;
    char *name=NULL;
    struct directory_struct *directory=dh->directory;
    struct nfsdir *dir=(struct nfsdir *) dh->handle.data;
    struct entry_struct *entry, *result;
    struct inode_struct *inode;
    struct name_struct xname={NULL, 0, 0};
    struct stat st;

    memset(&st, 0, sizeof(struct stat));

    buff=malloc(size);

    if (! buff) {

	error=ENOMEM;
	goto error;

    }

    if (lock_directory(directory, _DIRECTORY_LOCK_EXCL)==-1) {

	free(buff);
	buff=NULL;
	error=EAGAIN;
	goto error;

    }

    while (pos<size) {

	if (offset==0) {

	    inode=dh->parent->inode;

    	    /* the . entry */

    	    st.st_ino = inode->ino;
	    st.st_mode = S_IFDIR;
	    name = (char *) dotname;

    	} else if (offset==1) {

    	    /* the .. entry */

	    if (! dh->parent->parent ) {

		inode=dh->parent->inode;
	    	st.st_ino = inode->ino;

	    } else {
		struct entry_struct *parent=dh->parent->parent;

		inode=parent->inode;
	    	st.st_ino=inode->ino;

	    }

	    st.st_mode = S_IFDIR;
	    name = (char *) dotdotname;

    	} else {

	    if (! dh->entry) {
		struct nfsdirent *de;

		readdir:

		pthread_mutex_lock(&nfs_export->mutex);

		de=nfs_readdir(nfs_ctx, dir);

	        pthread_mutex_unlock(&nfs_export->mutex);

		if (de) {

		    if (strcmp(de->name, ".")==0 || strcmp(de->name, "..")==0) continue;

		    xname.name=de->name;
		    xname.len=strlen(xname.name);
		    calculate_nameindex(&xname);

		} else {

		    dh->mode |= _WORKSPACE_READDIR_MODE_FINISH;
		    break;

		}

		error=0;

		entry=create_entry(dh->parent, &xname);
		inode=create_inode();

		if (entry && inode) {

		    result=insert_entry_batch(directory, entry, &error, 0);

		    if (result==entry) {
			struct workspace_object_struct *export_object=NULL;

			inode->mode = translate_libnfs_type(de->type);
			inode->mode |= de->mode;

			add_inode_hashtable(inode, increase_inodes_workspace, (void *) dh->object->workspace_mount);

			inode->alias=entry;
			entry->inode=inode;

			adjust_pathmax(dh->pathinfo.len + 1 + xname.len);

		    } else {

			if (error==EEXIST) {

			    destroy_entry(entry);
			    entry=result;

			    free(inode);
			    inode=entry->inode;

			} else {

			    free(buff);
			    destroy_entry(entry);
			    free(inode);

			    goto error;

			}

		    }

		    st.st_mode=entry->inode->mode;
		    st.st_ino=entry->inode->ino;
		    name=entry->name.name;

		} else {

		    if (entry) {

			destroy_entry(entry);
			entry=NULL;

		    }

		    if (inode) {

			free(inode);
			inode=NULL;

		    }

		    error=ENOMEM;
		    free(buff);

		    goto error;

		}

		dh->entry=entry;

	    } else {

		st.st_ino=dh->entry->inode->ino;
		st.st_mode=dh->entry->inode->mode;
		name=dh->entry->name.name;

	    }

	}

    	dirent_size=fuse_add_direntry(req, buff+pos, size-pos, name, &st, offset+1);

	if (pos + dirent_size > size) {

	    dh->offset = offset + 1;
	    break;

	}

	/* increase counter and clear the various fields */

	dh->entry=NULL; /* forget current entry to force readdir */
	offset++;
	pos += dirent_size;

    }

    unlock_directory(directory, _DIRECTORY_LOCK_EXCL);

    fuse_reply_buf(req, buff, pos);

    free(buff);
    buff=NULL;

    return;

    error:

    fuse_reply_err(req, error);

}

static void workspace_nfs_readdirplus_simple(fuse_req_t req, size_t size, off_t offset, struct workspace_dh_struct *dh)
{
    struct resource_struct *resource=dh->object->resource;
    struct net_nfs_export_struct *nfs_export=(struct net_nfs_export_struct *) resource->data;
    struct nfs_context *nfs_ctx=(struct nfs_context *) nfs_export->data;
    unsigned int error=0;
    char *buff=NULL;
    size_t pos=0;
    size_t dirent_size;
    struct fuse_entry_param e;
    char *name=NULL;
    struct directory_struct *directory=dh->directory;
    struct nfsdir *dir=(struct nfsdir *) dh->handle.data;
    struct entry_struct *entry, *result;
    struct inode_struct *inode;
    struct name_struct xname={NULL, 0, 0};

    memset(&e, 0, sizeof(struct fuse_entry_param));

    e.generation = 1;
    e.attr_timeout = fs_options.attr_timeout;
    e.entry_timeout = fs_options.entry_timeout;

    e.attr.st_blksize=_DEFAULT_BLOCKSIZE;

    buff=malloc(size);

    if (! buff) {

	error=ENOMEM;
	goto error;

    }

    if (lock_directory(directory, _DIRECTORY_LOCK_EXCL)==-1) {

	free(buff);
	buff=NULL;
	error=EAGAIN;
	goto error;

    }

    while (pos<size) {

    	if (offset==0) {

	    inode=dh->parent->inode;

    	    /* the . entry */

	    e.ino = inode->ino;

	    e.attr.st_ino = e.ino;
	    e.attr.st_mode = inode->mode;
	    e.attr.st_nlink = inode->nlink;
	    e.attr.st_uid = inode->uid;
	    e.attr.st_gid = inode->gid;
	    e.attr.st_rdev = inode->rdev;
	    e.attr.st_size = inode->size;
	    e.attr.st_atim.tv_sec = 0;
	    e.attr.st_atim.tv_nsec = 0;
	    e.attr.st_mtim.tv_sec = inode->mtim.tv_sec;
	    e.attr.st_mtim.tv_nsec = inode->mtim.tv_nsec;
	    e.attr.st_ctim.tv_sec = inode->ctim.tv_sec;
	    e.attr.st_ctim.tv_nsec = inode->ctim.tv_nsec;

	    name = (char *) dotname;

	    inode->nlookup++;

    	} else if (offset==1) {

    	    /* the .. entry */

	    if ( ! dh->parent->parent ) {

		inode=dh->parent->inode;

	    } else {

		inode=dh->parent->parent->inode;

	    }

	    e.ino = inode->ino;

	    e.attr.st_ino = e.ino;
	    e.attr.st_mode = inode->mode;
	    e.attr.st_nlink = inode->nlink;
	    e.attr.st_uid = inode->uid;
	    e.attr.st_gid = inode->gid;
	    e.attr.st_rdev = inode->rdev;
	    e.attr.st_size = inode->size;
	    e.attr.st_atim.tv_sec = 0;
	    e.attr.st_atim.tv_nsec = 0;
	    e.attr.st_mtim.tv_sec = inode->mtim.tv_sec;
	    e.attr.st_mtim.tv_nsec = inode->mtim.tv_nsec;
	    e.attr.st_ctim.tv_sec = inode->ctim.tv_sec;
	    e.attr.st_ctim.tv_nsec = inode->ctim.tv_nsec;

	    name = (char *) dotdotname;

	    inode->nlookup++;

    	} else {

	    if (! dh->entry) {
		struct nfsdirent *de;

		readdir:

	        pthread_mutex_lock(&nfs_export->mutex);

		de=nfs_readdir(nfs_ctx, dir);

	        pthread_mutex_unlock(&nfs_export->mutex);

		if (de) {

		    if (strcmp(de->name, ".")==0 || strcmp(de->name, "..")==0) continue;

		    xname.name=de->name;
		    xname.len=strlen(xname.name);
		    calculate_nameindex(&xname);

		} else {

		    dh->mode |= _WORKSPACE_READDIR_MODE_FINISH;
		    break;

		}

		error=0;

		entry=create_entry(dh->parent, &xname);
		inode=create_inode();

		if (entry && inode) {

		    result=insert_entry_batch(directory, entry, &error, 0);

		    if (result==entry) {
			struct workspace_object_struct *export_object=NULL;

			inode->mode = translate_libnfs_type(de->type);
			inode->mode |= de->mode;

			add_inode_hashtable(inode, increase_inodes_workspace, (void *) dh->object->workspace_mount);

			inode->alias=entry;
			entry->inode=inode;

			memcpy(&entry->synctime, &dh->synctime, sizeof(struct timespec));

			inode->nlookup++;
			inode->nlink=2;
			inode->uid=0; /* ?? */
			inode->gid=0; /* ?? */
			inode->size=de->size;

			/* struct timeval convert to timespec */

			inode->mtim.tv_sec=de->mtime.tv_sec;
			inode->mtim.tv_nsec=1000 * de->mtime.tv_usec;

			inode->ctim.tv_sec=de->ctime.tv_sec;
			inode->ctim.tv_nsec=1000 * de->ctime.tv_usec;

			adjust_pathmax(dh->pathinfo.len + 1 + xname.len);

		    } else {

			if (error==EEXIST) {

			    destroy_entry(entry);
			    entry=result;

			    memcpy(&entry->synctime, &dh->synctime, sizeof(struct timespec));

			    free(inode);
			    inode=entry->inode;

			} else {

			    free(buff);
			    destroy_entry(entry);
			    free(inode);

			    goto error;

			}

		    }

		} else {

		    if (entry) {

			destroy_entry(entry);
			entry=NULL;

		    }

		    if (inode) {

			free(inode);
			inode=NULL;

		    }

		    error=ENOMEM;
		    free(buff);

		    goto error;

		}

		name=entry->name.name;
		dh->entry=entry;


	    } else {

		entry=dh->entry;

		inode=entry->inode;
		name=entry->name.name;

	    }

	    e.ino = inode->ino;

	    e.attr.st_ino = e.ino;
	    e.attr.st_mode = inode->mode;
	    e.attr.st_nlink = inode->nlink;
	    e.attr.st_uid = inode->uid;
	    e.attr.st_gid = inode->gid;
	    e.attr.st_rdev = inode->rdev;
	    e.attr.st_size = inode->size;

	    e.attr.st_atim.tv_sec = 0;
	    e.attr.st_atim.tv_nsec = 0;
	    e.attr.st_mtim.tv_sec = inode->mtim.tv_sec;
	    e.attr.st_mtim.tv_nsec = inode->mtim.tv_nsec;
	    e.attr.st_ctim.tv_sec = inode->ctim.tv_sec;
	    e.attr.st_ctim.tv_nsec = inode->ctim.tv_nsec;

	    if (inode->size % e.attr.st_blksize == 0) {

		e.attr.st_blocks=inode->size / e.attr.st_blksize;

	    } else {

		e.attr.st_blocks=1 + inode->size / e.attr.st_blksize;

	    }

	}

    	dirent_size=fuse_add_direntry_plus(req, buff+pos, size-pos, name, &e, offset+1);

	if (pos + dirent_size > size) {

	    dh->offset=offset;
	    break;

	}

	/* increase counter and clear the various fields */

	dh->entry=NULL; /* forget current entry to force readdir */
	offset++;
	pos += dirent_size;

    }

    unlock_directory(directory, _DIRECTORY_LOCK_EXCL);

    fuse_reply_buf(req, buff, pos);

    free(buff);
    buff=NULL;

    return;

    error:

    fuse_reply_err(req, error);

}


static void workspace_nfs_readdir(fuse_req_t req, size_t size, off_t offset, struct workspace_dh_struct *dh)
{

    workspace_nfs_readdir_simple(req, size, offset, dh);

}

static void workspace_nfs_readdirplus(fuse_req_t req, size_t size, off_t offset, struct workspace_dh_struct *dh)
{

    workspace_nfs_readdirplus_simple(req, size, offset, dh);

}

static void workspace_nfs_releasedir(fuse_req_t req, struct workspace_dh_struct *dh)
{
    struct resource_struct *resource=dh->object->resource;
    struct net_nfs_export_struct *nfs_export=(struct net_nfs_export_struct *) resource->data;
    struct nfs_context *nfs_ctx=(struct nfs_context *) nfs_export->data;
    struct nfsdir *dir=(struct nfsdir *) dh->handle.data;
    struct directory_struct *directory=NULL;

    logoutput("workspace_nfs_releasedir");

    directory=dh->directory;

    if (dir) {

        pthread_mutex_lock(&nfs_export->mutex);

	nfs_closedir(nfs_ctx, dir);

        pthread_mutex_unlock(&nfs_export->mutex);

    }

    fuse_reply_err(req, 0);

    if (directory) {

	/* when synced with backend and there were entries at start test these are not synced */

	if (dh->mode & _WORKSPACE_READDIR_MODE_NONEMPTY) remove_old_entries(dh->object, directory, &dh->synctime);
	memcpy(&directory->synctime, &dh->synctime, sizeof(struct timespec));

    }

    // clean_pathcache();

}

void set_module_calls_libnfs_export(struct module_calls_struct *mcalls)
{

	strcpy(mcalls->name, "libnfs-export-sync");

	mcalls->groupid		= 0;

	mcalls->destroy		= workspace_nfs_destroy;

	mcalls->lookup_cached	= workspace_nfs_lookup_cached;
	mcalls->lookup_noncached= workspace_nfs_lookup_noncached;
	mcalls->getattr		= workspace_nfs_getattr;
	mcalls->setattr		= workspace_nfs_setattr;
	mcalls->readlink	= workspace_nfs_readlink;
	mcalls->mkdir		= workspace_nfs_mkdir;
	mcalls->mknod		= workspace_nfs_mknod;

	mcalls->open		= workspace_nfs_open;
	mcalls->read		= workspace_nfs_read;
	mcalls->write		= workspace_nfs_write;
	mcalls->fsync		= workspace_nfs_fsync;
	mcalls->release		= workspace_nfs_release;
	mcalls->fgetattr	= workspace_nfs_fgetattr;
	mcalls->fsetattr	= workspace_nfs_fsetattr;
	mcalls->create		= workspace_nfs_create;

	mcalls->opendir		= workspace_nfs_opendir;
	mcalls->readdir		= workspace_nfs_readdir;
	mcalls->readdirplus	= workspace_nfs_readdirplus;
	mcalls->releasedir	= workspace_nfs_releasedir;


}
