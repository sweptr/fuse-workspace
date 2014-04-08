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
#include <sys/syscall.h>
#include <math.h>

#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif

#ifndef ENOATTR
#define ENOATTR ENODATA        /* No such attribute */
#endif

#ifdef LOGGING

#include <syslog.h>

static unsigned char loglevel=1;

static inline void open_logoutput()
{
    openlog("simpleoverlays", 0, LOG_SYSLOG);
}

static inline void close_logoutput()
{
    closelog();

}

#define logoutput_debug(...) if (loglevel >= 5) syslog(LOG_DEBUG, __VA_ARGS__)
#define logoutput_info(...) if (loglevel >= 4) syslog(LOG_INFO, __VA_ARGS__)
#define logoutput_notice(...) if (loglevel >= 3) syslog(LOG_NOTICE, __VA_ARGS__)
#define logoutput_warning(...) if (loglevel >= 2) syslog(LOG_WARNING, __VA_ARGS__)
#define logoutput_error(...) if (loglevel >= 1) syslog(LOG_ERR, __VA_ARGS__)

#define logoutput(...) if (loglevel >= 1) syslog(LOG_DEBUG, __VA_ARGS__)

#else

static inline void open_logoutput()
{
    return;

}

static inline void close_logoutput()
{
    return;

}

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


#include "workerthreads.h"

#include "entry-management.h"

#include "skiplist.h"
#include "skiplist-utils.h"
#include "skiplist-delete.h"
#include "skiplist-find.h"
#include "skiplist-insert.h"

#include "path-resolution.h"
#include "simpleoverlayfs.h"
#include "beventloop-utils.h"
#include "handlefuseevent.h"
#include "utils.h"
#include "options.h"
#include "fschangenotify.h"


struct overlayfs_options_struct overlayfs_options;

extern const char *rootpath;
extern const char *dotdotname;
extern const char *dotname;
extern struct fuse_chan *chan;

static void overlayfs_lookup(fuse_req_t req, fuse_ino_t ino, const char *name)
{
    struct fuse_entry_param e;
    struct entry_struct *parent=NULL, *entry=NULL;
    struct inode_struct *inode;
    struct call_info_struct call_info=CALL_INFO_INIT;
    unsigned char inodecreated=0;
    const struct fuse_ctx *ctx=fuse_req_ctx(req);
    unsigned int error=0;
    struct stat st;

    logoutput("LOOKUP, name: %s, uid %i, gid %i, pid %i", name, (int) ctx->uid, (int) ctx->gid, (int) ctx->pid);

    inode=find_inode(ino);

    if ( ! inode ) {

	error=ENOENT;
	goto out;

    }

    parent=inode->alias;

    if ( ! parent ) {

	error=ENOENT;
	goto out;

    }

    call_info.entry=parent;

    call_info.pid=ctx->pid;
    call_info.uid=ctx->uid;
    call_info.gid=ctx->gid;
    call_info.umask=ctx->umask;

    call_info.pathinfo.path=NULL;
    call_info.pathinfo.len=0;
    call_info.pathinfo.flags=0;

    if (get_path_extra(&call_info, name, &error)==-1) goto out;

    /* check entry on underlying fs 
	just the root for now (no prefix)*/

    memset(&st, 0, sizeof(struct stat));

    if (lstat(call_info.pathinfo.path, &st)==-1) {

	/* entry does not exist in the underlying fs */

	entry=find_entry(parent, name);

	if ( entry ) {
	    unsigned int row=0;

	    inode=entry->inode;
	    inode->alias=NULL;

	    delete_entry_sl(entry, &row, &error);
	    remove_entry(entry);

	}

	error=ENOENT;

    } else {

	entry=find_entry(parent, name);

	if ( ! entry ) {
	    unsigned int row=0;

	    entry=insert_entry_sl(parent, name, &row, &error, create_entry_cb, NULL);

	    adjust_pathmax(call_info.pathinfo.len);

	}

    }

    out:

    if ( error==ENOENT) {

	logoutput("overlayfs_lookup: entry %s does not exist (ENOENT)", name);

	fuse_reply_err(req, error);

    } else if ( error>0 ) {

	logoutput("overlayfs_lookup: error (%i)", error);

	fuse_reply_err(req, error);

    } else {

	inode=entry->inode;
	inode->nlookup++;

	e.ino = inode->ino;
	e.generation = 1;
	e.attr_timeout = overlayfs_options.attr_timeout;
	e.entry_timeout = overlayfs_options.entry_timeout;

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

	e.attr.st_blksize=4096;
	e.attr.st_blocks=0;

	inode->mode=st.st_mode;
	inode->nlink=st.st_nlink;
	inode->uid=st.st_uid;
	inode->gid=st.st_gid;

	inode->rdev=st.st_rdev;

	if (S_ISDIR(st.st_mode)) {

	    e.attr.st_size = 0;

	} else {

	    inode->type.size=st.st_size;
	    e.attr.st_size = st.st_size;

	}

	inode->mtim.tv_sec=st.st_mtim.tv_sec;
	inode->mtim.tv_nsec=st.st_mtim.tv_nsec;

	inode->ctim.tv_sec=st.st_ctim.tv_sec;
	inode->ctim.tv_nsec=st.st_ctim.tv_nsec;

	fuse_reply_entry(req, &e);

	logoutput("overlayfs_lookup: entry %s found", name);

    }

    free_path_pathinfo(&call_info.pathinfo);

}


static void overlayfs_forget(fuse_req_t req, fuse_ino_t ino, unsigned long nlookup)
{
    struct inode_struct *inode;

    logoutput("FORGET");

    inode = remove_inode(ino);

    if (inode) {

	if (inode->alias) {
	    struct entry_struct *entry=inode->alias;

	    logoutput("forget, entry %s does still exist", entry->name);

	} else {
	    if ( inode->nlookup < nlookup ) {

		logoutput("internal error: forget ino=%llu %llu from %llu", (unsigned long long) ino, (unsigned long long) nlookup, (unsigned long long) inode->nlookup);
		inode->nlookup=0;

	    } else {

    		inode->nlookup -= nlookup;

		logoutput("forget, current nlookup value %llu", (unsigned long long) inode->nlookup);

	    }

	    free(inode);

	    decrease_nrinodes();

	}

    }

    out:

    fuse_reply_none(req);

}

static void overlayfs_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
    struct stat st;
    struct entry_struct *entry;
    struct inode_struct *inode;
    struct call_info_struct call_info=CALL_INFO_INIT;
    const struct fuse_ctx *ctx=fuse_req_ctx(req);
    unsigned int error=0;

    logoutput("GETATTR");

    inode=find_inode(ino);

    if ( ! inode ) {

	error=ENOENT;
	goto out;

    }

    entry=inode->alias;

    if ( ! entry ) {

	error=ENOENT;
	goto out;

    }

    call_info.entry=entry;
    call_info.pid=ctx->pid;
    call_info.uid=ctx->uid;
    call_info.gid=ctx->gid;
    call_info.umask=ctx->umask;

    call_info.pathinfo.path=NULL;
    call_info.pathinfo.len=0;
    call_info.pathinfo.flags=0;

    if (isrootentry(entry)==1) {

	call_info.pathinfo.path=(char *) rootpath;

    } else {

	if (get_path(&call_info, &error)==-1) goto out;

    }

    /* check entry on underlying fs 
	just the root for now (no prefix)*/

    if (lstat(call_info.pathinfo.path, &st)==-1) error=errno;

    out:

    logoutput("overlayfs_getattr, return: %i", error);

    if (error>0) {

	fuse_reply_err(req, error);

    } else {

	inode->mode=st.st_mode;
	inode->nlink=st.st_nlink;
	inode->uid=st.st_uid;
	inode->gid=st.st_gid;

	inode->rdev=st.st_rdev;

	if (S_ISDIR(st.st_mode)) {

	    st.st_size=0;

	} else {

	    inode->type.size=st.st_size;

	}

	inode->mtim.tv_sec=st.st_mtim.tv_sec;
	inode->mtim.tv_nsec=st.st_mtim.tv_nsec;

	inode->ctim.tv_sec=st.st_ctim.tv_sec;
	inode->ctim.tv_nsec=st.st_ctim.tv_nsec;

	fuse_reply_attr(req, &st, overlayfs_options.attr_timeout);

    }

    free_path_pathinfo(&call_info.pathinfo);

}

static void overlayfs_mkdir(fuse_req_t req, fuse_ino_t ino, const char *name, mode_t mode)
{
    struct entry_struct *entry=NULL;
    struct inode_struct *inode;
    unsigned int error=0;
    const struct fuse_ctx *ctx=fuse_req_ctx(req);

    logoutput("MKDIR, name: %s", name);

    inode=find_inode(ino);

    if (inode) {
	struct entry_struct *parent=inode->alias;

	entry=find_entry(parent, name);

	if ( ! entry ) {
	    struct call_info_struct call_info=CALL_INFO_INIT;
	    uid_t uid_keep;
	    gid_t gid_keep;
	    mode_t umask_keep;

	    call_info.entry=entry;
	    call_info.pid=ctx->pid;
	    call_info.uid=ctx->uid;
	    call_info.gid=ctx->gid;
	    call_info.umask=ctx->umask;

	    call_info.pathinfo.path=NULL;
	    call_info.pathinfo.len=0;
	    call_info.pathinfo.flags=0;

	    if (get_path_extra(&call_info, name, &error)==0) {

		/* change to uid/gid/umask of user */

		uid_keep=setfsuid(call_info.uid);
		gid_keep=setfsgid(call_info.gid);
		umask_keep=umask(call_info.umask);

		if (mkdir(call_info.pathinfo.path, mode)==0) {
		    unsigned int row=0;

		    entry=insert_entry_sl(parent, name, &row, &error, create_entry_cb, NULL);

		    adjust_pathmax(call_info.pathinfo.len);

		} else {

		    error=errno;

		}

		uid_keep=setfsuid(uid_keep);
		gid_keep=setfsgid(gid_keep);
		umask_keep=umask(umask_keep);

	    }

	    free_path_pathinfo(&call_info.pathinfo);

	} else {

	    error=EEXIST;

	}

    } else {

	error=ENOENT;

    }

    out:

    if ( error==0 ) {
        struct fuse_entry_param e;
    
	memset(&e, 0, sizeof(&e));

	inode=entry->inode;

	e.ino = inode->ino;
	e.attr.st_ino = e.ino;
	e.attr.st_mode = mode;
	e.generation = 1;
	e.attr_timeout = overlayfs_options.attr_timeout;
	e.entry_timeout = overlayfs_options.entry_timeout;

	e.attr.st_blksize=4096;
	e.attr.st_blocks=0;

	inode->mode=S_IFDIR;

	inode->nlink=0;
	inode->uid=ctx->uid;
	inode->gid=ctx->gid;

	inode->rdev=0;
	inode->type.directory=NULL;

	inode->mtim.tv_sec=0;
	inode->mtim.tv_nsec=0;

	inode->ctim.tv_sec=0;
	inode->ctim.tv_nsec=0;

        fuse_reply_entry(req, &e);

    } else {

	logoutput("overlayfs_mkdir: error %i", error);

	fuse_reply_err(req, error);

    }

}

static void overlayfs_mknod(fuse_req_t req, fuse_ino_t ino, const char *name, mode_t mode, dev_t rdev)
{
    struct entry_struct *entry=NULL;
    struct inode_struct *inode;
    unsigned int error=0;
    const struct fuse_ctx *ctx=fuse_req_ctx(req);

    logoutput("MKNOD, name: %s", name);

    inode=find_inode(ino);

    if (inode) {
	struct entry_struct *parent=inode->alias;

	entry=find_entry(parent, name);

	if ( ! entry ) {
	    struct call_info_struct call_info=CALL_INFO_INIT;
	    uid_t uid_keep;
	    gid_t gid_keep;
	    mode_t umask_keep;

	    call_info.entry=entry;
	    call_info.pid=ctx->pid;
	    call_info.uid=ctx->uid;
	    call_info.gid=ctx->gid;
	    call_info.umask=ctx->umask;

	    call_info.pathinfo.path=NULL;
	    call_info.pathinfo.len=0;
	    call_info.pathinfo.flags=0;

	    if (get_path_extra(&call_info, name, &error)==0) {

		/* change to uid/gid/umask of user */

		uid_keep=setfsuid(call_info.uid);
		gid_keep=setfsgid(call_info.gid);
		umask_keep=umask(call_info.umask);

		if (mknod(call_info.pathinfo.path, mode, rdev)==0) {
		    unsigned int row=0;

		    entry=insert_entry_sl(parent, name, &row, &error, create_entry_cb, NULL);

		    adjust_pathmax(call_info.pathinfo.len);

		} else {

		    error=errno;

		}

		uid_keep=setfsuid(uid_keep);
		gid_keep=setfsgid(gid_keep);
		umask_keep=umask(umask_keep);

	    }

	    free_path_pathinfo(&call_info.pathinfo);

	} else {

	    error=EEXIST;

	}

    }

    out:

    if ( error==0 ) {
        struct fuse_entry_param e;

	memset(&e, 0, sizeof(&e));

	inode=entry->inode;

	e.ino = inode->ino;
	e.attr.st_ino = e.ino;
	e.attr.st_mode = mode;
	e.attr.st_rdev = rdev;
	e.generation = 1;
	e.attr_timeout = overlayfs_options.attr_timeout;
	e.entry_timeout = overlayfs_options.entry_timeout;

	e.attr.st_blksize=4096;
	e.attr.st_blocks=0;

	inode->mode=mode;

	inode->nlink=0;
	inode->uid=ctx->uid;
	inode->gid=ctx->gid;

	inode->rdev=rdev;
	inode->type.size=0;

	inode->mtim.tv_sec=0;
	inode->mtim.tv_nsec=0;

	inode->ctim.tv_sec=0;
	inode->ctim.tv_nsec=0;

        fuse_reply_entry(req, &e);

    } else {

	logoutput("overlayfs_mknod: error %i", error);

	fuse_reply_err(req, error);

    }

}

static void overlayfs_readlink(fuse_req_t req, fuse_ino_t ino)
{
    struct inode_struct *inode;
    unsigned int error=0;
    const struct fuse_ctx *ctx=fuse_req_ctx(req);
    struct call_info_struct call_info=CALL_INFO_INIT;

    logoutput("READLINK");

    call_info.entry=NULL;
    call_info.pid=ctx->pid;
    call_info.uid=ctx->uid;
    call_info.gid=ctx->gid;
    call_info.umask=ctx->umask;

    call_info.pathinfo.path=NULL;
    call_info.pathinfo.len=0;
    call_info.pathinfo.flags=0;

    inode=find_inode(ino);

    if ( inode ) {
	struct entry_struct *entry;

	entry=inode->alias;

	if ( entry ) {
	    size_t size=512;
	    char *buff=NULL;

	    call_info.entry=entry;

	    if (isrootentry(entry)==1) {

		call_info.pathinfo.path=(char *)rootpath;

	    } else {

		if (get_path(&call_info, &error)==-1) goto out;

	    }

	    while(size<=PATH_MAX) {
		uid_t uid_keep;
		gid_t gid_keep;
		ssize_t lenread=0;

		if (buff) {

		    buff = realloc(buff, size);

		} else {

		    buff = malloc(size);

		}

		if ( buff ) {

		    uid_keep=setfsuid(call_info.uid);
		    gid_keep=setfsgid(call_info.gid);

    		    if ((lenread=readlink(call_info.pathinfo.path, buff, size))==-1) {

			error=errno;

			setfsuid(uid_keep);
			setfsgid(gid_keep);

			free(buff);
			goto out;

		    }

		    setfsuid(uid_keep);
		    setfsgid(gid_keep);

		    if (lenread < size) {

			/* success */

			buff[lenread] = '\0';
			fuse_reply_readlink(req, buff);

			logoutput("overlayfs_readlink: read link %s for %s", buff, entry->name);

			free(buff);
			free_path_pathinfo(&call_info.pathinfo);

			return;

		    }

		    size+=512;

		} else {

		    error=ENOMEM;
		    break;

		}

	    }

	} else {

	    error=ENOENT;

	}

    }

    out:

    logoutput("overlayfs_readlink: error %i", error);

    fuse_reply_err(req, error);

    free_path_pathinfo(&call_info.pathinfo);

}

void remove_old_entries(struct entry_struct *parent, struct timespec *synctime)
{
    struct entry_struct *entry;

    logoutput("remove_old_entries: synctime %li:%li", synctime->tv_sec, synctime->tv_nsec);

    entry=get_next_entry(parent, NULL);

    while (entry) {

	if (entry->synctime.tv_sec<synctime->tv_sec || 
	    (entry->synctime.tv_sec==synctime->tv_sec && entry->synctime.tv_nsec<synctime->tv_nsec)) {
	    struct entry_struct *next_entry=get_next_entry(parent, entry);
	    unsigned int row=0;
	    unsigned int error=0;
	    struct inode_struct *inode=entry->inode;

	    logoutput("remove_old_entries: remove %s", entry->name);

	    if (S_ISDIR(inode->mode)) remove_directory_recursive(entry);

	    notify_kernel_delete(parent->inode->ino, inode->ino, entry->name);

	    delete_entry_sl(entry, &row, &error);
	    remove_entry(entry);

	    entry=next_entry;

	} else {

	    entry=get_next_entry(parent, entry);

	}

    }

}

#define _GETDENTS_BUFFSIZE				1024

struct linux_dirent {
    unsigned long				d_ino;
    unsigned long				d_off;
    unsigned short				d_reclen;
    char					d_name[];
};

static void overlayfs_opendir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
    struct overlayfs_dirp_struct *overlayfs_dirp=NULL;
    unsigned int error=0;
    struct entry_struct *entry;
    struct inode_struct *inode;
    struct call_info_struct call_info=CALL_INFO_INIT;
    const struct fuse_ctx *ctx=fuse_req_ctx(req);

    logoutput("OPENDIR");

    call_info.pid=ctx->pid;
    call_info.uid=ctx->uid;
    call_info.gid=ctx->gid;
    call_info.umask=ctx->umask;

    call_info.pathinfo.path=NULL;
    call_info.pathinfo.len=0;
    call_info.pathinfo.flags=0;

    inode=find_inode(ino);

    if (inode) {

	entry=inode->alias;

	if ( entry ) {
	    struct stat st;
	    struct directory_struct *directory=NULL;
	    int fd=0;

	    call_info.entry=entry;

	    if (isrootentry(entry)==1) {

		call_info.pathinfo.path=(char *)rootpath;

	    } else {

		if (get_path(&call_info, &error)==-1) goto error;

	    }

	    fd=open(call_info.pathinfo.path, O_RDONLY | O_DIRECTORY);

	    if (fd==-1) {

		error=errno;
		goto error;

	    }

	    if (fstat(fd, &st)==-1) {

		error=errno;
		goto error;

	    } else if (! S_ISDIR(st.st_mode)) {

		error=ENOTDIR;
		goto error;

	    }

	    overlayfs_dirp = malloc(sizeof(struct overlayfs_dirp_struct));

	    if ( ! overlayfs_dirp ) {

		error=ENOMEM;
		goto error;

	    }

	    overlayfs_dirp->parent=entry;
	    overlayfs_dirp->entry=NULL;
	    overlayfs_dirp->offset=0;
	    overlayfs_dirp->mode=0;
	    overlayfs_dirp->fd=fd;
	    overlayfs_dirp->buffer=NULL;
	    overlayfs_dirp->size=0;
	    overlayfs_dirp->pos=0;
	    overlayfs_dirp->read=0;
	    overlayfs_dirp->lenpath=call_info.pathinfo.len;

	    directory=get_directory_sl(entry, 1, &error);

	    if (! directory || error>0) {

		error=(error==0) ? ENOMEM : error;
		goto error;

	    }

	    /*
		check the modification time of the directory
		if changed after latest synctime then a full readdir is required 
	    */

	    logoutput("overlayfs_opendir: compare modifytime %li:%li with synctime %li:%li", st.st_mtim.tv_sec, st.st_mtim.tv_nsec, directory->synctime.tv_sec, directory->synctime.tv_nsec);

	    if (st.st_mtim.tv_sec>directory->synctime.tv_sec || 
		(st.st_mtim.tv_sec==directory->synctime.tv_sec && st.st_mtim.tv_nsec>directory->synctime.tv_nsec)) {

		overlayfs_dirp->buffer=malloc(_GETDENTS_BUFFSIZE);

		if ( ! overlayfs_dirp->buffer) {

		    error=ENOMEM;
		    goto error;

		}

		overlayfs_dirp->size=_GETDENTS_BUFFSIZE;

		get_current_time(&overlayfs_dirp->synctime);

	    } else {

		overlayfs_dirp->mode |= _OVERLAYFS_MODE_VIRTUAL;

	    }

	    inode->mtim.tv_sec=st.st_mtim.tv_sec;
	    inode->mtim.tv_nsec=st.st_mtim.tv_nsec;

	    inode->ctim.tv_sec=st.st_ctim.tv_sec;
	    inode->ctim.tv_nsec=st.st_ctim.tv_nsec;

	    fi->fh = (uint64_t) overlayfs_dirp;

	    fuse_reply_open(req, fi);

	    add_pathcache(&call_info.pathinfo, entry);

	    free_path_pathinfo(&call_info.pathinfo);

	    return;

	} else {

	    error=ENOENT;

	}

    } else {

	error=ENOENT;

    }

    error:

    fuse_reply_err(req, error);

    if (overlayfs_dirp) {

	if (overlayfs_dirp->fd>0) {

	    close(overlayfs_dirp->fd);
	    overlayfs_dirp->fd=0;

	}

    }

    logoutput("overlayfs_opendir, error %i", error);

    free_path_pathinfo(&call_info.pathinfo);

}

static void overlayfs_readdir_virtual(fuse_req_t req, size_t size, off_t offset, struct overlayfs_dirp_struct *overlayfs_dirp)
{
    unsigned int error=0;

    logoutput("READDIR virtual, size: %zi", size);

    if (overlayfs_dirp->mode & _OVERLAYFS_MODE_FINISH) {

	fuse_reply_buf(req, NULL, 0);
	return;

    } else {
	char *buff=NULL;
	size_t pos=0;
	size_t dirent_size;
	struct stat st;
	char *name=NULL;

	memset(&st, 0, sizeof(struct stat));

	buff=malloc(size);

	if (! buff) {

	    error=ENOMEM;
	    goto error;

	}

	while (pos<size) {

    	    if (overlayfs_dirp->offset==0) {
		struct inode_struct *inode=overlayfs_dirp->parent->inode;

        	/* the . entry */

        	st.st_ino = inode->ino;
		st.st_mode = S_IFDIR;
		name = (char *) dotname;

    	    } else if (overlayfs_dirp->offset==1) {

        	/* the .. entry */

		if (isrootentry(overlayfs_dirp->parent)==1 ) {
		    struct inode_struct *inode=overlayfs_dirp->parent->inode;

	    	    st.st_ino = inode->ino;

		} else {
		    struct entry_struct *parent=overlayfs_dirp->parent->parent;
		    struct inode_struct *inode=parent->inode;

	    	    st.st_ino=inode->ino;

		}

		st.st_mode = S_IFDIR;
		name = (char *) dotdotname;

		overlayfs_dirp->entry=get_next_entry(overlayfs_dirp->parent, NULL);

    	    } else {

		if (overlayfs_dirp->entry) {

		    name=overlayfs_dirp->entry->name;
		    st.st_mode=overlayfs_dirp->entry->inode->mode;
		    st.st_ino=overlayfs_dirp->entry->inode->ino;

		} else {

		    overlayfs_dirp->mode |= _OVERLAYFS_MODE_FINISH;
		    break;

		}

	    }

    	    dirent_size=fuse_add_direntry(req, buff+pos, size-pos, name, &st, overlayfs_dirp->offset+1);

	    if (pos + dirent_size > size) {

		break;

	    }

	    /* increase counter and clear the various fields */

	    overlayfs_dirp->entry=get_next_entry(overlayfs_dirp->parent, overlayfs_dirp->entry);
	    overlayfs_dirp->offset++;
	    pos += dirent_size;

	}

	fuse_reply_buf(req, buff, pos);

	free(buff);
	buff=NULL;

	return;

    }

    error:

    fuse_reply_err(req, error);

}

static void overlayfs_readdir_real(fuse_req_t req, size_t size, off_t offset, struct overlayfs_dirp_struct *overlayfs_dirp)
{
    unsigned int error=0;

    logoutput("READDIR real, size: %zi", size);

    if (overlayfs_dirp->mode & _OVERLAYFS_MODE_FINISH) {

	fuse_reply_buf(req, NULL, 0);
	return;

    } else {
	char *buff=NULL;
	size_t pos=0;
	size_t dirent_size;
	struct stat st;
	char *name=NULL;

	memset(&st, 0, sizeof(struct stat));

	buff=malloc(size);

	if (! buff) {

	    error=ENOMEM;
	    goto error;

	}

	while (pos<size) {

    	    if (overlayfs_dirp->offset==0) {
		struct inode_struct *inode=overlayfs_dirp->parent->inode;

        	/* the . entry */

        	st.st_ino = inode->ino;
		st.st_mode = S_IFDIR;
		name = (char *) dotname;

    	    } else if (overlayfs_dirp->offset==1) {

        	/* the .. entry */

		if (isrootentry(overlayfs_dirp->parent)==1 ) {
		    struct inode_struct *inode=overlayfs_dirp->parent->inode;

	    	    st.st_ino = inode->ino;

		} else {
		    struct entry_struct *parent=overlayfs_dirp->parent->parent;
		    struct inode_struct *inode=parent->inode;

	    	    st.st_ino=inode->ino;

		}

		st.st_mode = S_IFDIR;
		name = (char *) dotdotname;

    	    } else {

		if (! overlayfs_dirp->entry) {
		    struct entry_struct *entry;
		    unsigned int row=0;
		    struct linux_dirent *de=NULL;
		    unsigned char d_type=0;

		    readdir:

		    if (overlayfs_dirp->pos>=overlayfs_dirp->size) {
			int nread=0;

			nread=syscall(SYS_getdents, overlayfs_dirp->fd, overlayfs_dirp->buffer, overlayfs_dirp->size);

			if (nread<=0) {

			    if (nread==-1) {

				error=errno;
				free(buff);
				goto error;

			    }

			    overlayfs_dirp->mode |= _OVERLAYFS_MODE_FINISH;
			    break;

			}

			overlayfs_dirp->pos=0;

		    }

		    de=(struct linux_dirent *) (overlayfs_dirp->buffer + overlayfs_dirp->pos);

		    if (strcmp(de->d_name, ".")==0 || strcmp(de->d_name, "..")==0) {

			overlayfs_dirp->pos+=de->d_reclen;
			goto readdir;

		    }

		    d_type=*(overlayfs_dirp->buffer + overlayfs_dirp->pos + de->d_reclen - 1);

		    entry=find_entry_by_name_sl(overlayfs_dirp->parent, de->d_name, &row, &error);

		    if (! entry) {

			entry=insert_entry_sl(overlayfs_dirp->parent, de->d_name, &row, &error, create_entry_cb, NULL);

			if (! entry) break;

			memcpy(&entry->synctime, &overlayfs_dirp->synctime, sizeof(struct timespec));

			entry->inode->mode=DTTOIF(d_type);

			st.st_mode=entry->inode->mode;
			st.st_ino=entry->inode->ino;
			name=entry->name;

		    } else {

			st.st_ino=entry->inode->ino;
			st.st_mode=entry->inode->mode;
			name=entry->name;

			memcpy(&entry->synctime, &overlayfs_dirp->synctime, sizeof(struct timespec));

		    }

		    overlayfs_dirp->entry=entry;

		} else {

		    st.st_ino=overlayfs_dirp->entry->inode->ino;
		    st.st_mode=overlayfs_dirp->entry->inode->mode;
		    name=overlayfs_dirp->entry->name;

		}

	    }

    	    dirent_size=fuse_add_direntry(req, buff+pos, size-pos, name, &st, overlayfs_dirp->offset+1);

	    if (pos + dirent_size > size) {

		break;

	    }

	    /* increase counter and clear the various fields */

	    overlayfs_dirp->entry=NULL; /* forget current entry to force readdir */
	    overlayfs_dirp->offset++;
	    pos += dirent_size;

        }

	fuse_reply_buf(req, buff, pos);

	free(buff);
	buff=NULL;

	return;

    }

    error:

    fuse_reply_err(req, error);

}

static void overlayfs_readdirplus_virtual(fuse_req_t req, size_t size, off_t offset, struct overlayfs_dirp_struct *overlayfs_dirp)
{
    unsigned int error=0;

    logoutput("READDIRPLUS virtual, size: %zi", size);

    if (overlayfs_dirp->mode & _OVERLAYFS_MODE_FINISH) {

	fuse_reply_buf(req, NULL, 0);
	return;

    } else {
	char *buff=NULL;
	size_t pos=0;
	size_t dirent_size;
	struct fuse_entry_param e;
	char *name=NULL;

	memset(&e, 0, sizeof(struct fuse_entry_param));

	e.generation = 1;
	e.attr_timeout = overlayfs_options.attr_timeout;
	e.entry_timeout = overlayfs_options.entry_timeout;

	e.attr.st_blksize=4096;
	e.attr.st_blocks=0;

	buff=malloc(size);

	if (! buff) {

	    error=ENOMEM;
	    goto error;

	}

	while (pos<size) {

    	    if (overlayfs_dirp->offset==0) {
		struct inode_struct *inode=overlayfs_dirp->parent->inode;

        	/* the . entry */

		e.ino = inode->ino;

		e.attr.st_ino = e.ino;
		e.attr.st_mode = inode->mode;
		e.attr.st_nlink = inode->nlink;
		e.attr.st_uid = inode->uid;
		e.attr.st_gid = inode->gid;
		e.attr.st_rdev = inode->rdev;
		e.attr.st_size = 0;
		e.attr.st_atim.tv_sec = 0;
		e.attr.st_atim.tv_nsec = 0;
		e.attr.st_mtim.tv_sec = inode->mtim.tv_sec;
		e.attr.st_mtim.tv_nsec = inode->mtim.tv_nsec;
		e.attr.st_ctim.tv_sec = inode->ctim.tv_sec;
		e.attr.st_ctim.tv_nsec = inode->ctim.tv_nsec;

		name = (char *) dotname;

		inode->nlookup++;

    	    } else if (overlayfs_dirp->offset==1) {
    		struct inode_struct *inode=NULL;

        	/* the .. entry */

		if (isrootentry(overlayfs_dirp->parent)==1 ) {

		    inode=overlayfs_dirp->parent->inode;

		} else {

		    inode=overlayfs_dirp->parent->parent->inode;

		}

		e.ino = inode->ino;

		e.attr.st_ino = e.ino;
		e.attr.st_mode = inode->mode;
		e.attr.st_nlink = inode->nlink;
		e.attr.st_uid = inode->uid;
		e.attr.st_gid = inode->gid;
		e.attr.st_rdev = inode->rdev;
		e.attr.st_size = 0;
		e.attr.st_atim.tv_sec = 0;
		e.attr.st_atim.tv_nsec = 0;
		e.attr.st_mtim.tv_sec = inode->mtim.tv_sec;
		e.attr.st_mtim.tv_nsec = inode->mtim.tv_nsec;
		e.attr.st_ctim.tv_sec = inode->ctim.tv_sec;
		e.attr.st_ctim.tv_nsec = inode->ctim.tv_nsec;

		name = (char *) dotdotname;

		inode->nlookup++;

		overlayfs_dirp->entry=get_next_entry(overlayfs_dirp->parent, NULL);

    	    } else {

		if (overlayfs_dirp->entry) {
		    struct inode_struct *inode=overlayfs_dirp->entry->inode;

		    e.ino = inode->ino;

		    e.attr.st_ino = e.ino;
		    e.attr.st_mode = inode->mode;
		    e.attr.st_nlink = inode->nlink;
		    e.attr.st_uid = inode->uid;
		    e.attr.st_gid = inode->gid;
		    e.attr.st_rdev = inode->rdev;

		    if (S_ISDIR(inode->mode)) {

			e.attr.st_size = 0;

		    } else {

			e.attr.st_size = inode->type.size;

		    }

		    e.attr.st_atim.tv_sec = 0;
		    e.attr.st_atim.tv_nsec = 0;
		    e.attr.st_mtim.tv_sec = inode->mtim.tv_sec;
		    e.attr.st_mtim.tv_nsec = inode->mtim.tv_nsec;
		    e.attr.st_ctim.tv_sec = inode->ctim.tv_sec;
		    e.attr.st_ctim.tv_nsec = inode->ctim.tv_nsec;

		    name=overlayfs_dirp->entry->name;

		    inode->nlookup++;

		    overlayfs_dirp->entry=get_next_entry(overlayfs_dirp->parent, overlayfs_dirp->entry);

		} else {

		    overlayfs_dirp->mode |= _OVERLAYFS_MODE_FINISH;
		    break;

		}

	    }

    	    dirent_size=fuse_add_direntry_plus(req, buff+pos, size-pos, name, &e, overlayfs_dirp->offset+1);

	    if (pos + dirent_size > size) {

		break;

	    }

	    /* increase counter and clear the various fields */

	    overlayfs_dirp->offset++;
	    pos += dirent_size;

	}

	fuse_reply_buf(req, buff, pos);

	free(buff);
	buff=NULL;

	return;

    }

    error:

    fuse_reply_err(req, error);

}

static void overlayfs_readdirplus_real(fuse_req_t req, size_t size, off_t offset, struct overlayfs_dirp_struct *overlayfs_dirp)
{
    unsigned int error=0;

    logoutput("READDIRPLUS real, size: %zi", size);

    if (overlayfs_dirp->mode & _OVERLAYFS_MODE_FINISH) {

	fuse_reply_buf(req, NULL, 0);
	return;

    } else {
	char *buff=NULL;
	size_t pos=0;
	size_t dirent_size;
	struct fuse_entry_param e;
	char *name=NULL;

	memset(&e, 0, sizeof(struct fuse_entry_param));

	e.generation = 1;
	e.attr_timeout = overlayfs_options.attr_timeout;
	e.entry_timeout = overlayfs_options.entry_timeout;

	e.attr.st_blksize=4096;
	e.attr.st_blocks=0;

	buff=malloc(size);

	if (! buff) {

	    error=ENOMEM;
	    goto error;

	}

	while (pos<size) {

    	    if (overlayfs_dirp->offset==0) {
		struct inode_struct *inode=overlayfs_dirp->parent->inode;

        	/* the . entry */

		e.ino = inode->ino;

		e.attr.st_ino = e.ino;
		e.attr.st_mode = inode->mode;
		e.attr.st_nlink = inode->nlink;
		e.attr.st_uid = inode->uid;
		e.attr.st_gid = inode->gid;
		e.attr.st_rdev = inode->rdev;
		e.attr.st_size = 0;
		e.attr.st_atim.tv_sec = 0;
		e.attr.st_atim.tv_nsec = 0;
		e.attr.st_mtim.tv_sec = inode->mtim.tv_sec;
		e.attr.st_mtim.tv_nsec = inode->mtim.tv_nsec;
		e.attr.st_ctim.tv_sec = inode->ctim.tv_sec;
		e.attr.st_ctim.tv_nsec = inode->ctim.tv_nsec;

		name = (char *) dotname;

		inode->nlookup++;

    	    } else if (overlayfs_dirp->offset==1) {
    		struct inode_struct *inode=NULL;

        	/* the .. entry */

		if (isrootentry(overlayfs_dirp->parent)==1 ) {

		    inode=overlayfs_dirp->parent->inode;

		} else {

		    inode=overlayfs_dirp->parent->parent->inode;

		}

		e.ino = inode->ino;

		e.attr.st_ino = e.ino;
		e.attr.st_mode = inode->mode;
		e.attr.st_nlink = inode->nlink;
		e.attr.st_uid = inode->uid;
		e.attr.st_gid = inode->gid;
		e.attr.st_rdev = inode->rdev;
		e.attr.st_size = 0;
		e.attr.st_atim.tv_sec = 0;
		e.attr.st_atim.tv_nsec = 0;
		e.attr.st_mtim.tv_sec = inode->mtim.tv_sec;
		e.attr.st_mtim.tv_nsec = inode->mtim.tv_nsec;
		e.attr.st_ctim.tv_sec = inode->ctim.tv_sec;
		e.attr.st_ctim.tv_nsec = inode->ctim.tv_nsec;

		name = (char *) dotdotname;

		inode->nlookup++;

    	    } else {
    		struct inode_struct *inode=NULL;

		if (! overlayfs_dirp->entry) {
		    struct entry_struct *entry;
		    unsigned int row=0;
		    struct linux_dirent *de=NULL;
		    unsigned char d_type=0;

		    readdir:

		    if (overlayfs_dirp->pos >= overlayfs_dirp->read) {
			int read=0;

			read=syscall(SYS_getdents, overlayfs_dirp->fd, overlayfs_dirp->buffer, overlayfs_dirp->size);

			if (read<=0) {

			    if (read==-1) {

				error=errno;
				free(buff);
				goto error;

			    }

			    overlayfs_dirp->mode |= _OVERLAYFS_MODE_FINISH;
			    break;

			}

			overlayfs_dirp->pos=0;
			overlayfs_dirp->read=read;

		    }

		    de=(struct linux_dirent *) (overlayfs_dirp->buffer + overlayfs_dirp->pos);
		    overlayfs_dirp->pos+=de->d_reclen;

		    logoutput("overlayfs_readdirplus: found %s", de->d_name);

		    if (strcmp(de->d_name, ".")==0 || strcmp(de->d_name, "..")==0) {

			goto readdir;

		    }

		    if (fstatat(overlayfs_dirp->fd, de->d_name, &e.attr, AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT)==-1) {

			goto readdir;

		    }

		    d_type=*(overlayfs_dirp->buffer + overlayfs_dirp->pos + de->d_reclen - 1);

		    entry=find_entry_by_name_sl(overlayfs_dirp->parent, de->d_name, &row, &error);

		    if (! entry) {

			entry=insert_entry_sl(overlayfs_dirp->parent, de->d_name, &row, &error, create_entry_cb, NULL);

			if (! entry) break;

			inode=entry->inode;

			memcpy(&entry->synctime, &overlayfs_dirp->synctime, sizeof(struct timespec));

			inode->mode=DTTOIF(d_type);

			inode->nlookup++;
			adjust_pathmax(overlayfs_dirp->lenpath + strlen(name));

		    } else {

			inode=entry->inode;
			memcpy(&entry->synctime, &overlayfs_dirp->synctime, sizeof(struct timespec));

			inode->nlookup++;

		    }

		    name=entry->name;
		    overlayfs_dirp->entry=entry;

		    inode->mode = e.attr.st_mode;
		    inode->nlink = e.attr.st_nlink;
		    inode->uid = e.attr.st_uid;
		    inode->gid = e.attr.st_gid;
		    inode->rdev = e.attr.st_rdev;

		    inode->mtim.tv_sec = e.attr.st_mtim.tv_sec;
		    inode->mtim.tv_nsec = e.attr.st_mtim.tv_nsec;
		    inode->ctim.tv_sec = e.attr.st_ctim.tv_sec;
		    inode->ctim.tv_nsec = e.attr.st_ctim.tv_nsec;

		    if (S_ISDIR(e.attr.st_mode)) {

			e.attr.st_size=0;

		    } else {

			inode->type.size=e.attr.st_size;

		    }

		} else {

		    inode=overlayfs_dirp->entry->inode;
		    name=overlayfs_dirp->entry->name;

		    e.attr.st_mode = inode->mode;
		    e.attr.st_nlink = inode->nlink;
		    e.attr.st_uid = inode->uid;
		    e.attr.st_gid = inode->gid;
		    e.attr.st_rdev = inode->rdev;

		    if (S_ISDIR(inode->mode)) {

			e.attr.st_size = 0;

		    } else {

			e.attr.st_size = inode->type.size;

		    }

		    e.attr.st_atim.tv_sec = 0;
		    e.attr.st_atim.tv_nsec = 0;
		    e.attr.st_mtim.tv_sec = inode->mtim.tv_sec;
		    e.attr.st_mtim.tv_nsec = inode->mtim.tv_nsec;
		    e.attr.st_ctim.tv_sec = inode->ctim.tv_sec;
		    e.attr.st_ctim.tv_nsec = inode->ctim.tv_nsec;

		    inode->nlookup++;

		}

		e.ino = inode->ino;
		e.attr.st_ino = e.ino;

	    }

	    logoutput("overlayfs_readdirplus: add direntry %s, offset %i", name, overlayfs_dirp->offset);

    	    dirent_size=fuse_add_direntry_plus(req, buff+pos, size-pos, name, &e, overlayfs_dirp->offset+1);

	    if (pos + dirent_size > size) {

		break;

	    }

	    /* increase counter and clear the various fields */

	    overlayfs_dirp->entry=NULL; /* forget current entry to force readdir */
	    overlayfs_dirp->offset++;
	    pos += dirent_size;

        }

	fuse_reply_buf(req, buff, pos);

	free(buff);
	buff=NULL;

	return;

    }

    error:

    fuse_reply_err(req, error);

}

static void overlayfs_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t offset, struct fuse_file_info *fi)
{
    struct overlayfs_dirp_struct *overlayfs_dirp=(struct overlayfs_dirp_struct *) (uintptr_t) fi->fh;

    if (overlayfs_dirp->mode & _OVERLAYFS_MODE_VIRTUAL) {

	overlayfs_readdir_virtual(req, size, offset, overlayfs_dirp);

    } else {

	overlayfs_readdir_real(req, size, offset, overlayfs_dirp);

    }

}

static void overlayfs_readdirplus(fuse_req_t req, fuse_ino_t ino, size_t size, off_t offset, struct fuse_file_info *fi)
{
    struct overlayfs_dirp_struct *overlayfs_dirp=(struct overlayfs_dirp_struct *) (uintptr_t) fi->fh;

    if (overlayfs_dirp->mode & _OVERLAYFS_MODE_VIRTUAL) {

	overlayfs_readdirplus_virtual(req, size, offset, overlayfs_dirp);

    } else {

	overlayfs_readdirplus_real(req, size, offset, overlayfs_dirp);

    }

}

static void overlayfs_releasedir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
    struct overlayfs_dirp_struct *overlayfs_dirp=(struct overlayfs_dirp_struct *) (uintptr_t) fi->fh;

    (void) ino;

    logoutput("RELEASEDIR");

    if (overlayfs_dirp) {

	if (overlayfs_dirp->fd>0) {

	    close(overlayfs_dirp->fd);
	    overlayfs_dirp->fd=0;

	}

	if (overlayfs_dirp->buffer) {

	    free(overlayfs_dirp->buffer);
	    overlayfs_dirp->buffer=NULL;

	}

	if (!(overlayfs_dirp->mode & _OVERLAYFS_MODE_VIRTUAL)) {
	    struct directory_struct *directory=NULL;
	    unsigned int error=0;

	    /* remove the entries not found when syncing with backend */

	    remove_old_entries(overlayfs_dirp->parent, &overlayfs_dirp->synctime);

	    directory=get_directory_sl(overlayfs_dirp->parent, 0, &error);

	    if (directory) {

		logoutput("overlayfs_releasedir: copy time %li:%li", overlayfs_dirp->synctime.tv_sec, overlayfs_dirp->synctime.tv_nsec);

		directory->synctime.tv_sec=overlayfs_dirp->synctime.tv_sec;
		directory->synctime.tv_nsec=overlayfs_dirp->synctime.tv_nsec;

	    }

	}

	free(overlayfs_dirp);
	overlayfs_dirp=NULL;

    }

    fuse_reply_err(req, 0);
    fi->fh=0;

    clean_pathcache();

}

static void overlayfs_statfs(fuse_req_t req, fuse_ino_t ino)
{
    struct statvfs st;
    unsigned int error=0;
    struct entry_struct *entry; 
    struct inode_struct *inode;

    logoutput("STATFS");

    inode=find_inode(ino);

    if ( ! inode ) {

	error=ENOENT;
	goto error;

    }

    entry=inode->alias;

    if ( ! entry ){

	error=ENOENT;
	goto error;

    }

    memset(&st, 0, sizeof(statvfs));

    /* should the statvfs be taken of the path or the root ?? */

    if (statvfs("/", &st)==0) {

	// take some values from the default

	/* note the fs does not provide opening/reading/writing of files, so info about blocksize etc
	   is useless, so do not override the default from the root */ 

	st.f_bsize=4096; /* good?? */
	st.f_frsize=st.f_bsize; /* no fragmentation on this fs */
	st.f_blocks=0;

	st.f_bfree=0;
	st.f_bavail=0;

	st.f_files=get_nrinodes();
	st.f_ffree=UINT64_MAX - st.f_files ; /* inodes are of unsigned long int, 4 bytes:32 */
	st.f_favail=st.f_ffree;

	// do not know what to put here... just some default values... no fsid.... just zero

	st.f_fsid=0;
	st.f_flag=0;
	st.f_namemax=255;

	fuse_reply_statfs(req, &st);

	return;

    } else {

	error=errno;

    }

    error:

    fuse_reply_err(req, error);

    logoutput("statfs error: %i", error);

}

static void overlayfs_fsnotify(fuse_req_t req, fuse_ino_t ino, uint32_t mask)
{
    unsigned int error=0;
    struct entry_struct *entry;
    struct inode_struct *inode;
    struct call_info_struct call_info=CALL_INFO_INIT;
    const struct fuse_ctx *ctx=fuse_req_ctx(req);
    struct notifywatch_struct *watch=NULL;

    logoutput("FSNOTIFY");

    call_info.pid=ctx->pid;
    call_info.uid=ctx->uid;
    call_info.gid=ctx->gid;
    call_info.umask=ctx->umask;

    call_info.pathinfo.path=NULL;
    call_info.pathinfo.len=0;
    call_info.pathinfo.flags=0;

    inode=find_inode(ino);

    if ( ! inode ) {

	error=ENOENT;
	goto out;

    }

    entry=inode->alias;

    if ( ! entry ){

	error=ENOENT;
	goto out;

    }

    call_info.entry=entry;

    if (isrootentry(entry)==1) {

	call_info.pathinfo.path = (char *)rootpath;
	call_info.pathinfo.flags = PATHINFOFLAGS_INUSE;
	call_info.pathinfo.len = strlen(rootpath);

    } else {

	if (get_path(&call_info, &error)==-1) goto out;

    }

    logoutput("overlayfs_fsnotify: on %s mask %i", call_info.pathinfo.path, mask);

    watch=lookup_watch_inode(inode);

    if (watch) {

	watch->mask=mask;
	change_notifywatch(watch);

    } else if (mask>0) {

	watch=add_notifywatch(inode, mask, &call_info.pathinfo);

    }

    out:

    free_path_pathinfo(&call_info.pathinfo);

}

static void overlayfs_init (void *userdata, struct fuse_conn_info *conn)
{

    logoutput("INIT");

}

static void overlayfs_destroy (void *userdata)
{

    logoutput("DESTROY");


}

static void overlayfs_getxattr(fuse_req_t req, fuse_ino_t ino, const char *name, size_t size)
{
    struct inode_struct *inode;

    logoutput("GETXATTR, name %s", name);

    if (strcmp(name, "system.posix_acl_access")==0 || strcmp(name, "system.posix_acl_default")==0) goto out;

    inode=find_inode(ino);

    if ( inode ) {
	struct entry_struct *entry=NULL;

	entry=inode->alias;

	if ( entry ) {

	    if (isrootentry(entry)==1) {

		if (strcmp(name, "pathmax")==0) {

		    if (size==0) {
			size_t count=0;

			/* pathmax */

			count+=log10(get_pathmax()) + 2;

			fuse_reply_xattr(req, count);

		    } else {
			size_t count=0;

			/* pathmax */

			count+=log10(get_pathmax()) + 2;

			if (count<size) {
			    char *buff=NULL;
			    char result[count];

			    buff=malloc(size);

			    if (buff) {

				sprintf(result, "%i", (int) get_pathmax());

				memset(buff, 0, size);
				memcpy(buff, result, count);

				logoutput("overlayfs_getxattr: reply buff %s", buff);

				fuse_reply_buf(req, buff, size);

				free(buff);

			    } else {

				fuse_reply_err(req, ENOMEM);

			    }

			} else {

			    fuse_reply_err(req, ERANGE);

			}

		    }

		    return;

		}

	    }

	}

    }

    out:

    fuse_reply_err(req, ENOATTR);

}

static void overlayfs_listxattr(fuse_req_t req, fuse_ino_t ino, size_t size)
{
    struct inode_struct *inode;

    logoutput("LISTXATTR");

    inode=find_inode(ino);

    if ( inode ) {
	struct entry_struct *entry=NULL;

	entry=inode->alias;

	if ( entry ) {

	    if (isrootentry(entry)==1) {

		if (size==0) {
		    size_t count=0;

		    /* pathmax */

		    count+=strlen("pathmax") + 2;

		    fuse_reply_xattr(req, count);

		} else {
		    size_t count=0;

		    /* pathmax */

		    count+=strlen("pathmax") + 2;

		    if (count<=size) {
			char *buff=NULL;
			char result[count];

			buff=malloc(size);

			if (buff) {
			    int len=0;

			    len=sprintf(result, "%i", (int) get_pathmax());

			    memset(buff, '\0', size);
			    memcpy(buff, result, count);

			    logoutput("overlayfs_listxattr: reply buff %s", buff);

			    fuse_reply_buf(req, buff, size);

			    free(buff);

			} else {

			    fuse_reply_err(req, ENOMEM);

			}

		    } else {

			fuse_reply_err(req, ERANGE);

		    }

		}

		return;

	    }

	}

    }

    if (size==0) {

	fuse_reply_xattr(req, 0);

    } else {

	fuse_reply_buf(req, NULL, 0);

    }

}

struct fuse_lowlevel_ops overlayfs_oper = {
    .init	= overlayfs_init,
    .destroy	= overlayfs_destroy,
    .lookup	= overlayfs_lookup,
    .forget	= overlayfs_forget,
    .getattr	= overlayfs_getattr,
    .mkdir	= overlayfs_mkdir,
    .mknod	= overlayfs_mknod,
    .readlink	= overlayfs_readlink,
    .opendir	= overlayfs_opendir,
    .readdir	= overlayfs_readdir,
    .readdirplus= overlayfs_readdirplus,
    .releasedir	= overlayfs_releasedir,
    .statfs	= overlayfs_statfs,
    .fsnotify   = overlayfs_fsnotify,
    .listxattr  = overlayfs_listxattr,
    .getxattr	= overlayfs_getxattr,
};

int main(int argc, char *argv[])
{
    int res, epoll_fd=0;
    struct fuse_args global_fuse_args = FUSE_ARGS_INIT(0, NULL);
    struct workerthreads_queue_struct workerthreads_queue;
    unsigned int error=0;

    umask(0);

    open_logoutput(); 

    /* parse commandline options and initialize the fuse options */

    if (parse_arguments(argc, argv, &global_fuse_args, &error)==-1) {

	fprintf(stderr, "Error, cannot parse arguments (error: %i).\n", error);
	goto skipeverything;

    }

    initialize_workerthreads(&workerthreads_queue);

    set_max_numberthreads(&workerthreads_queue, 6);
    set_workerthreads_timeout(&workerthreads_queue, 10);

    /*
        init the hash lookup tables
    */

    if (init_pathcache_group(&error)==-1) {

	fprintf(stderr, "Error, cannot intialize pathcache (error: %i).\n", error);
	exit(1);

    }

    if (init_inode_hashtable(&error)==-1) {

	fprintf(stderr, "Error, cannot intialize hash tables (error: %i).\n", error);
	exit(1);

    }

    /*
        create the root inode and entry
    */

    if (create_root(&error)==-1) {

	fprintf(stderr, "Error, failed to create the root entry(error: %i).\n", error);
	exit(1);

    }


    res = fuse_daemonize(0);

    if ( res!=0 ) {

        logoutput("Error daemonize.");
        goto out;

    }

    /*
	initialize the eventloop (using epoll)
    */

    if (init_beventloop(NULL, &error)==-1) {

        logoutput("Error creating eventloop, error: %i.", error);
        goto out;

    }

    /*
	add signal handler to eventloop
    */

    if (set_beventloop_signal(NULL, 1, &error)==-1) {

	logoutput("Error adding signal handler to eventlopp: %i.", error);
        goto out;

    }

    /*
	initialize fs change notify
    */

    if (init_fschangenotify(&error)==-1) {

	logoutput("Error initializing fschange notify, error: %i", error);
	goto out;

    }

    /*
	add the fuse channel(=fd) to the eventloop
    */

    res=initialize_fuse(overlayfs_options.mountpoint, "overlayfs", &overlayfs_oper, sizeof(overlayfs_oper), &global_fuse_args, &workerthreads_queue);
    if (res<0) goto out;

    res=start_beventloop(NULL);

    out:

    destroy_workerthreads_queue(&workerthreads_queue);

    finish_fuse();

    end_fschangenotify();

    /* remove any remaining xdata from mainloop */

    destroy_beventloop(NULL);

    fuse_opt_free_args(&global_fuse_args);

    skipeverything:

    close_logoutput();

    return error>0 ? 1 : 0;

    notforked:

    if (error>0) {

	fprintf(stderr, "Error (error: %i).\n", error);

    }

    return error>0 ? 1 : 0;

}
