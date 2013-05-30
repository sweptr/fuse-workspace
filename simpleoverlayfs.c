/*
  2010, 2011 Stef Bon <stefbon@gmail.com>

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
#include <syslog.h>
#include <time.h>
#include <pthread.h>
#include <ctype.h>
#include <inttypes.h>

#include <sys/param.h>
#include <sys/types.h>
#include <sys/inotify.h>
#include <sys/epoll.h>
#include <sys/fsuid.h>

#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif

#ifndef ENOATTR
#define ENOATTR ENODATA        /* No such attribute */
#endif

#define LOG_LOGAREA LOG_LOGAREA_FILESYSTEM

#include <fuse/fuse_lowlevel.h>

#include "workerthreads.h"

#include "entry-management.h"
#include "path-resolution.h"
#include "logging.h"

#include "notifyfs-fsevent.h"

#include "simpleoverlayfs.h"
#include "epoll-utils.h"
#include "handlefuseevent.h"
#include "utils.h"
#include "options.h"
#include "socket.h"

#include "watches.h"

#include "changestate.h"

#include "handleclientmessage.h"

#include "message-base.h"
#include "message-receive.h"
#include "message-send.h"





struct overlayfs_options_struct overlayfs_options;
struct notifyfs_connection_struct notifyfsserver;
char *recv_buffer=NULL;

unsigned char loglevel=0;
int logarea=0;

extern const char *rootpath;
extern const char *dotdotname;
extern const char *dotname;
extern struct fuse_chan *chan;

void notify_kernel_delete(struct entry_struct *entry)
{
    int res=0;

    if (!chan) return;

    if (entry->parent) {

#if FUSE_VERSION >= 29

	if (entry->inode) {

	    res=fuse_lowlevel_notify_delete(chan, entry->parent->inode->ino, entry->inode->ino, entry->name, strlen(entry->name));

	}

#else

	res=-ENOSYS;

#endif

	if (res==-ENOSYS) {

	    fuse_lowlevel_notify_inval_entry(chan, entry->parent->inode->ino, entry->name, strlen(entry->name));

	    if (entry->inode) fuse_lowlevel_notify_inval_inode(chan, entry->inode->ino, 0, 0);

	}

    }

}


static void overlayfs_lookup(fuse_req_t req, fuse_ino_t parentino, const char *name)
{
    struct fuse_entry_param e;
    struct entry_struct *parent;
    struct inode_struct *inode;
    int nreturn=0;
    struct call_info_struct call_info=CALL_INFO_INIT;
    unsigned char inodecreated=0;
    const struct fuse_ctx *ctx=fuse_req_ctx(req);

    logoutput("LOOKUP, name: %s", name);

    inode=find_inode_generic(parentino);

    if ( ! inode ) {

	nreturn=-ENOENT;
	goto out;

    }

    parent=inode->alias;

    if ( ! parent ) {

	nreturn=-ENOENT;
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

    nreturn=get_path(&call_info, name);
    if (nreturn<0) goto out;

    /* check entry on underlying fs 
	just the root for now (no prefix)*/

    nreturn=lstat(call_info.pathinfo.path, &(e.attr));

    if (nreturn==-1) {
	struct entry_struct *entry;

	/* entry does not exist in the underlying fs */

	entry=find_entry_table(parent, name, 1);

	if ( entry ) {

	    inode=entry->inode;

	    remove_entry_from_name_hash(entry);
	    remove_entry(entry);

	    inode->alias=NULL;

	}

	nreturn=-ENOENT;

    } else {
	struct entry_struct *entry;

	entry=find_entry_table(parent, name, 1);

	if ( ! entry ) {

	    entry=create_entry(parent, name, NULL);

	    if (entry) {

		assign_inode(entry);

		if (! entry->inode) {

		    remove_entry(entry);
		    nreturn=-ENOMEM;
		    goto out;

		}

		inodecreated=1;

	    } else {

		nreturn=-ENOMEM;
		goto out;

	    }

	    add_to_name_hash_table(entry);
	    add_to_inode_hash_table(entry->inode);

	}

	inode=entry->inode;

    }

    out:

    if ( nreturn==-ENOENT) {

	logoutput("lookup: entry does not exist (ENOENT)");

	e.ino = 0;
	e.entry_timeout = overlayfs_options.negative_timeout;

    } else if ( nreturn<0 ) {

	logoutput("do_lookup: error (%i)", nreturn);

    } else {

	// no error

	inode->nlookup++;
	e.ino = inode->ino;
	e.attr.st_ino = e.ino;
	e.generation = 0;
	e.attr_timeout = overlayfs_options.attr_timeout;
	e.entry_timeout = overlayfs_options.entry_timeout;

	copy_stat(&inode->st, &e.attr);

	if (S_ISDIR(inode->st.st_mode)) {

	    if (inodecreated==1) {

		/* when a directory is found for the first time, it's not synced yet 
		    by setting this to zero: make sure it's synced */

		inode->st.st_mtim.tv_sec=0;
		inode->st.st_mtim.tv_nsec=0;

	    }


	} else {

	    inode->st.st_mtim.tv_sec=e.attr.st_mtim.tv_sec;
	    inode->st.st_mtim.tv_nsec=e.attr.st_mtim.tv_nsec;

	}

	inode->st.st_ctim.tv_sec=e.attr.st_ctim.tv_sec;
	inode->st.st_ctim.tv_nsec=e.attr.st_ctim.tv_nsec;

	get_current_time(&inode->st.st_atim);

	logoutput("lookup: entry %s found", name);

    }

    if ( nreturn<0 ) {

	fuse_reply_err(req, -nreturn);

    } else {

        fuse_reply_entry(req, &e);

    }

    free_path_pathinfo(&call_info.pathinfo);

}


static void overlayfs_forget(fuse_req_t req, fuse_ino_t ino, unsigned long nlookup)
{
    struct inode_struct *inode;

    inode = find_inode_generic(ino);
    if ( ! inode ) goto out;

    logoutput("FORGET");

    if ( inode->nlookup < nlookup ) {

	logoutput("internal error: forget ino=%llu %llu from %llu", (unsigned long long) ino, (unsigned long long) nlookup, (unsigned long long) inode->nlookup);
	inode->nlookup=0;

    } else {

        inode->nlookup -= nlookup;

    }

    logoutput("forget, current nlookup value %llu", (unsigned long long) inode->nlookup);

    out:

    fuse_reply_none(req);

}

static void overlayfs_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
    struct stat st;
    struct entry_struct *entry;
    struct inode_struct *inode;
    int nreturn=0;
    struct call_info_struct call_info=CALL_INFO_INIT;
    const struct fuse_ctx *ctx=fuse_req_ctx(req);

    logoutput("GETATTR");

    inode=find_inode_generic(ino);

    if ( ! inode ) {

	nreturn=-ENOENT;
	goto out;

    }

    entry=inode->alias;

    if ( ! entry ) {

	nreturn=-ENOENT;
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

	nreturn=get_path(&call_info, NULL);
	if (nreturn<0) goto out;

    }

    /* check entry on underlying fs 
	just the root for now (no prefix)*/

    nreturn=lstat(call_info.pathinfo.path, &st);

    if (nreturn==-1) nreturn=-errno;

    out:

    logoutput("getattr, return: %i", nreturn);

    if (nreturn < 0) {

	//if (nreturn==-ENOENT) 

	fuse_reply_err(req, -nreturn);

    } else {

	copy_stat(&inode->st, &st);

	if (! S_ISDIR(inode->st.st_mode)) {

	    inode->st.st_mtim.tv_sec=st.st_mtim.tv_sec;
	    inode->st.st_mtim.tv_nsec=st.st_mtim.tv_nsec;

	}

	inode->st.st_ctim.tv_sec=st.st_ctim.tv_sec;
	inode->st.st_ctim.tv_nsec=st.st_ctim.tv_nsec;

	get_current_time(&inode->st.st_atim);

	fuse_reply_attr(req, &st, overlayfs_options.attr_timeout);

    }

    free_path_pathinfo(&call_info.pathinfo);

}

static void overlayfs_mkdir(fuse_req_t req, fuse_ino_t parentino, const char *name, mode_t mode)
{
    struct fuse_entry_param e;
    struct entry_struct *entry;
    int nreturn=0;
    unsigned char entrycreated=0;
    struct call_info_struct call_info=CALL_INFO_INIT;
    uid_t uid_keep;
    gid_t gid_keep;
    mode_t umask_keep;
    const struct fuse_ctx *ctx=fuse_req_ctx(req);

    logoutput("MKDIR, name: %s", name);

    entry=find_entry_generic(parentino, name);

    if ( ! entry ) {
        struct inode_struct *pinode;

	pinode=find_inode_generic(parentino);

	if ( pinode ) {
            struct entry_struct *parent=pinode->alias;

	    if (parent) {

		entry=create_entry(parent, name, NULL);

		if ( !entry ) {

		    nreturn=-ENOMEM;
		    goto error;

		}

		entrycreated=1;

	    } else {

		nreturn=-ENOENT;
		goto error;

	    }

	} else { 

	    nreturn=-ENOENT;
	    goto error;

	}

    } else {

	/* here an error, the entry does exist already */

	nreturn=-EEXIST;
	goto error;

    }

    call_info.entry=entry;
    call_info.pid=ctx->pid;
    call_info.uid=ctx->uid;
    call_info.gid=ctx->gid;
    call_info.umask=ctx->umask;

    call_info.pathinfo.path=NULL;
    call_info.pathinfo.len=0;
    call_info.pathinfo.flags=0;

    nreturn=get_path(&call_info, NULL);
    if ( nreturn<0) goto out;

    /* change to uid/gid/umask of user */

    uid_keep=setfsuid(call_info.uid);
    gid_keep=setfsgid(call_info.gid);
    umask_keep=umask(call_info.umask);

    nreturn=mkdir(call_info.pathinfo.path, mode);

    /* change back */

    uid_keep=setfsuid(uid_keep);
    gid_keep=setfsgid(gid_keep);
    umask_keep=umask(umask_keep);

    out:

    if ( nreturn==0 ) {
	struct inode_struct *inode;

        assign_inode(entry);

	inode=entry->inode;

        if ( ! inode ) {

            nreturn=-ENOMEM;
            goto error;

        }

	e.ino = inode->ino;
	e.attr.st_ino = e.ino;
	e.generation = 0;
	e.attr_timeout = overlayfs_options.attr_timeout;
	e.entry_timeout = overlayfs_options.entry_timeout;

	inode->st.st_mode=S_IFDIR;

        add_to_name_hash_table(entry);
	add_to_inode_hash_table(entry->inode);

        fuse_reply_entry(req, &e);

	free_path_pathinfo(&call_info.pathinfo);

        return;

    }

    error:

    logoutput("mkdir: error %i", nreturn);

    if ( entrycreated==1 ) remove_entry(entry);

    e.ino = 0;
    e.entry_timeout = overlayfs_options.negative_timeout;

    fuse_reply_err(req, abs(nreturn));

    free_path_pathinfo(&call_info.pathinfo);

}


static void overlayfs_mknod(fuse_req_t req, fuse_ino_t parentino, const char *name, mode_t mode, dev_t rdev)
{
    struct fuse_entry_param e;
    struct entry_struct *entry;
    int nreturn=0;
    unsigned char entrycreated=0;
    struct call_info_struct call_info=CALL_INFO_INIT;
    uid_t uid_keep;
    gid_t gid_keep;
    mode_t umask_keep;
    const struct fuse_ctx *ctx=fuse_req_ctx(req);

    logoutput("MKNOD, name: %s", name);

    entry=find_entry_generic(parentino, name);

    if ( ! entry ) {
        struct inode_struct *pinode;

	pinode=find_inode_generic(parentino);

	if ( pinode ) {
            struct entry_struct *parent=pinode->alias;

	    if (parent) {

		entry=create_entry(parent, name, NULL);

		if ( !entry ) {

		    nreturn=-ENOMEM;
		    goto error;

		}

		entrycreated=1;

	    } else {

		nreturn=-ENOENT;
		goto error;

	    }

	} else { 

	    nreturn=-ENOENT;
	    goto error;

	}

    } else {

	/* here an error, the entry does exist already */

	nreturn=-EEXIST;
	goto error;

    }


    call_info.entry=entry;
    call_info.pid=ctx->pid;
    call_info.uid=ctx->uid;
    call_info.gid=ctx->gid;
    call_info.umask=ctx->umask;

    call_info.pathinfo.path=NULL;
    call_info.pathinfo.len=0;
    call_info.pathinfo.flags=0;

    nreturn=get_path(&call_info, NULL);
    if ( nreturn<0) goto out;

    /* change to uid/gid/umask of user */

    uid_keep=setfsuid(call_info.uid);
    gid_keep=setfsgid(call_info.gid);
    umask_keep=umask(call_info.umask);

    nreturn=mknod(call_info.pathinfo.path, mode, rdev);

    /* change back */

    uid_keep=setfsuid(uid_keep);
    gid_keep=setfsgid(gid_keep);
    umask_keep=umask(umask_keep);

    out:

    if ( nreturn==0 ) {
	struct inode_struct *inode;

        assign_inode(entry);

	inode=entry->inode;

        if ( ! inode ) {

            nreturn=-ENOMEM;
            goto error;

        }

	e.ino = inode->ino;
	e.attr.st_ino = e.ino;
	e.generation = 0;
	e.attr_timeout = overlayfs_options.attr_timeout;
	e.entry_timeout = overlayfs_options.entry_timeout;

	inode->st.st_mode=mode;
	inode->st.st_rdev=rdev;

        add_to_name_hash_table(entry);
	add_to_inode_hash_table(entry->inode);

        logoutput("mkdir: successfull");

        fuse_reply_entry(req, &e);

	free_path_pathinfo(&call_info.pathinfo);

        return;

    }

    error:

    logoutput("mkdir: error %i", nreturn);

    if ( entrycreated==1 ) remove_entry(entry);

    e.ino = 0;
    e.entry_timeout = overlayfs_options.negative_timeout;

    fuse_reply_err(req, abs(nreturn));

    free_path_pathinfo(&call_info.pathinfo);
}

static void overlayfs_readlink(fuse_req_t req, fuse_ino_t ino)
{
    struct entry_struct *entry;
    struct inode_struct *inode;
    int nreturn=0;
    struct call_info_struct call_info=CALL_INFO_INIT;
    size_t size=512;
    char *buff=NULL;
    const struct fuse_ctx *ctx=fuse_req_ctx(req);

    logoutput("READLINK");

    inode=find_inode_generic(ino);

    if ( ! inode ) {

	nreturn=-ENOENT;
	goto out;

    }

    entry=inode->alias;

    if ( ! entry ) {

	nreturn=-ENOENT;
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

	call_info.pathinfo.path=(char *)rootpath;

    } else {

	nreturn=get_path(&call_info, NULL);
	if (nreturn<0) goto out;

    }

    while(1) {
	uid_t uid_keep;
	gid_t gid_keep;
	mode_t umask_keep;
	int res;

	if (buff) {

	    buff = realloc(buff, size);

	} else {

	    buff = malloc(size);

	}

	if (! buff ) {

	    nreturn=-ENOMEM;
	    goto out;

	}

	uid_keep=setfsuid(call_info.uid);
	gid_keep=setfsgid(call_info.gid);

    	res = readlink(call_info.pathinfo.path, buff, size);
	if ( res==-1) nreturn=-errno;

	setfsuid(uid_keep);
	setfsgid(gid_keep);

	if (nreturn<0) {

	    break;

	} else if (res < size) {

	    buff[res] = '\0';
	    break;

	}

	size *= 2;

    }

    out:

    logoutput("readlink, return: %i", nreturn);

    if (nreturn < 0) {

	fuse_reply_err(req, -nreturn);

    } else {

	fuse_reply_readlink(req, buff);

    }

    free_path_pathinfo(&call_info.pathinfo);

    if (buff) {

	free(buff);
	buff=NULL;

    }

}

void remove_children_entry(struct entry_struct *parent)
{
    struct entry_struct *entry, *next_entry;

    entry=get_next_entry(parent, NULL);

    while(entry) {

	next_entry=entry=get_next_entry(parent, entry);

	if (S_ISDIR(entry->inode->st.st_mode)) remove_children_entry(entry);

	/* if a watch has been set here: remove that one.. and send notifyfs a message */

	notify_kernel_delete(entry);

	remove_entry_from_name_hash(entry);
	remove_entry(entry);

	entry=next_entry;

    }

}

void remove_old_entries(struct entry_struct *parent, struct timespec *sync_time)
{
    struct entry_struct *entry, *next_entry;
    struct inode_struct *parent_inode, *inode;

    logoutput("remove_old_entries");

    parent_inode=parent->inode;

    entry=get_next_entry(parent, NULL);

    while (entry) {

	next_entry=get_next_entry(parent, entry);

	inode=entry->inode;

	if (inode->st.st_atim.tv_sec<sync_time->tv_sec || 
	    (inode->st.st_atim.tv_sec==sync_time->tv_sec && inode->st.st_atim.tv_nsec<sync_time->tv_nsec)) {

	    /* if directory remove recursivly ... it's required to know it's a directory ... */

	    if (S_ISDIR(inode->st.st_mode)) remove_children_entry(entry);

	    /* if a watch has been set here: remove that one.. and send notifyfs a message */

	    notify_kernel_delete(entry);

	    remove_entry_from_name_hash(entry);
	    remove_entry(entry);

	    /* TODO:
	    signal to notifyfs when a watch has been removed.. */

	}

	entry=next_entry;

    }

}

static void overlayfs_opendir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
    struct generic_dirp_struct *generic_dirp=NULL;
    int nreturn=0;
    struct entry_struct *entry;
    struct inode_struct *inode;
    struct call_info_struct call_info=CALL_INFO_INIT;
    DIR *dp=NULL;
    struct stat st;
    const struct fuse_ctx *ctx=fuse_req_ctx(req);

    logoutput("OPENDIR");

    inode=find_inode_generic(ino);

    if ( ! inode ) {

	nreturn=-ENOENT;
	goto out;

    }

    entry=inode->alias;

    if ( ! entry ) {

	nreturn=-ENOENT;
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

	call_info.pathinfo.path=(char *)rootpath;

    } else {

	nreturn=get_path(&call_info, NULL);
	if (nreturn<0) goto out;

    }

    if (stat(call_info.pathinfo.path, &st)==-1) {

	/* handle error here */

	nreturn=-errno;
	goto out;

    }

    generic_dirp = malloc(sizeof(struct generic_dirp_struct));

    if ( ! generic_dirp ) {

	nreturn=-ENOMEM;
	goto out;

    }

    generic_dirp->parent=entry;
    generic_dirp->upperfs_offset=0;
    generic_dirp->name=NULL;
    generic_dirp->virtual=1;

    /* compare the modification time of the directory with the cached value 
       if they directory has changed, this mod. time is newer than the cached on
       take into account the directory must have been cached before
    */

    if (st.st_mtim.tv_sec>inode->st.st_mtim.tv_sec || (st.st_mtim.tv_sec==inode->st.st_mtim.tv_sec && st.st_mtim.tv_nsec>inode->st.st_mtim.tv_nsec)) {

	/* fs directory has changed compared to cache */

	generic_dirp->virtual=0;

    }

    copy_stat(&inode->st, &st);

    inode->st.st_mtim.tv_sec=st.st_mtim.tv_sec;
    inode->st.st_mtim.tv_nsec=st.st_mtim.tv_nsec;

    inode->st.st_ctim.tv_sec=st.st_ctim.tv_sec;
    inode->st.st_ctim.tv_nsec=st.st_ctim.tv_nsec;

    if (generic_dirp->virtual==0) {

	/* open directory */

	generic_dirp->data=(void *)opendir(call_info.pathinfo.path);

	if ( ! generic_dirp->data) {

	    nreturn=-errno;
	    goto out;

	}

    }

    get_current_time(&inode->st.st_atim);

    /* assign this generic dirp object to fi->fh */

    fi->fh = (unsigned long) generic_dirp;

    out:

    if ( nreturn<0 ) {

	if (generic_dirp) {

	    if (generic_dirp->data) {

		closedir((DIR *)generic_dirp->data);
		generic_dirp->data=NULL;

	    }

	    free(generic_dirp);
	    generic_dirp=NULL;

	}

	fuse_reply_err(req, -nreturn);

    } else {

	fuse_reply_open(req, fi);

    }

    logoutput("opendir, nreturn %i", nreturn);

    free_path_pathinfo(&call_info.pathinfo);

}

static void overlayfs_readdir_virtual(fuse_req_t req, size_t size, off_t offset, struct generic_dirp_struct *generic_dirp)
{
    char *buff=NULL;
    size_t buffpos=0;
    int nreturn=0;
    size_t entsize;
    struct entry_struct *entry=NULL;

    logoutput("READDIR virtual, size: %zi", size);

    if (generic_dirp->data) {

	entry=(struct entry_struct *) generic_dirp->data;

    }

    if (generic_dirp->upperfs_offset>1 && ! entry) goto out;

    buff=malloc(size);

    if (! buff) {

	nreturn=-ENOMEM;
	goto out;

    }

    while (buffpos<size) {

        if (generic_dirp->upperfs_offset==0) {
	    struct inode_struct *inode=generic_dirp->parent->inode;

            /* the . entry */

            generic_dirp->st.st_ino = inode->ino;
	    generic_dirp->st.st_mode=S_IFDIR;
	    generic_dirp->name=(char *) dotname;

        } else if (generic_dirp->upperfs_offset==1) {

            /* the .. entry */

	    if (isrootentry(generic_dirp->parent)==1 ) {
		struct inode_struct *inode=generic_dirp->parent->inode;

	        generic_dirp->st.st_ino = inode->ino;

	    } else {
		struct entry_struct *parent=generic_dirp->parent->parent;
		struct inode_struct *inode=parent->inode;

	        generic_dirp->st.st_ino=inode->ino;

	    }

	    generic_dirp->st.st_mode=S_IFDIR;
	    generic_dirp->name=(char *) dotdotname;

        } else {

	    if (buffpos>0) {

		if (generic_dirp->upperfs_offset==2) {

		    entry=get_next_entry(generic_dirp->parent, NULL);

		} else {

		    entry=get_next_entry(generic_dirp->parent, entry);

		}

	    }

	    if ( ! entry) {

		generic_dirp->name=NULL;
		generic_dirp->st.st_ino=0;
		generic_dirp->st.st_mode=0;
		generic_dirp->data=NULL;

		break;

	    }

	    generic_dirp->name=entry->name;
	    generic_dirp->st.st_ino=entry->inode->ino;
	    generic_dirp->st.st_mode=entry->inode->st.st_mode;

        }

        entsize=fuse_add_direntry(req, buff+buffpos, size-buffpos, generic_dirp->name, &generic_dirp->st, generic_dirp->upperfs_offset);

	if (buffpos+entsize > size) {

	    /* this entry does not fit into buffer, remember it for next batch */

	    generic_dirp->data=(void *) entry;
	    break;

	}

	/* increase counter and clear the various fields */

        generic_dirp->upperfs_offset++;
	generic_dirp->name=NULL;
	generic_dirp->data=NULL;
	generic_dirp->st.st_ino=0;
	generic_dirp->st.st_mode=0;
	buffpos += entsize;

    }

    out:

    if (nreturn < 0 ) {

	fuse_reply_err(req, -nreturn);

    } else {

	fuse_reply_buf(req, buff, buffpos);

    }

    if ( buff ) {

	free(buff);
	buff=NULL;

    }

}

static void overlayfs_readdir_real(fuse_req_t req, size_t size, off_t offset, struct generic_dirp_struct *generic_dirp)
{
    char *buff;
    size_t buffpos=0;
    int nreturn=0;
    DIR *dp=(DIR *) generic_dirp->data;
    struct dirent *de;
    size_t entsize;
    struct timespec *sync_time=NULL;

    logoutput("READDIR real, size: %zi", size);

    buff=malloc(size);

    if (! buff) {

	nreturn=-ENOMEM;
	goto out;

    }

    sync_time=&generic_dirp->parent->inode->st.st_atim;

    while (buffpos<size) {

	if (! generic_dirp->name) {

	    de=readdir(dp);

	    if ( ! de) break;

	    generic_dirp->name=de->d_name;
	    generic_dirp->st.st_mode=de->d_type<<12;

	}

        if ( strcmp(de->d_name, ".")==0 ) {
	    struct inode_struct *inode=generic_dirp->parent->inode;

            /* the . entry */

            generic_dirp->st.st_ino = inode->ino;

        } else if ( strcmp(de->d_name, "..")==0 ) {

            /* the .. entry */

	    if (isrootentry(generic_dirp->parent)==1 ) {
		struct inode_struct *inode=generic_dirp->parent->inode;

	        generic_dirp->st.st_ino = inode->ino;

	    } else {
		struct entry_struct *parent=generic_dirp->parent->parent;
		struct inode_struct *inode=parent->inode;

	        generic_dirp->st.st_ino=inode->ino;

	    }

        } else {
	    struct entry_struct *entry;

	    entry=find_entry_table(generic_dirp->parent, de->d_name, 1);

	    if ( ! entry) {

		entry=create_entry(generic_dirp->parent, de->d_name, NULL);

		if (entry) {

		    assign_inode(entry);

		    if ( ! entry->inode) {

			remove_entry(entry);
			entry=NULL;

			nreturn=-ENOMEM;
			break;

		    }

		} else {

		    nreturn=-ENOMEM;
		    break;

		}

		add_to_name_hash_table(entry);
		add_to_inode_hash_table(entry->inode);

	    }

	    entry->inode->st.st_atim.tv_sec=sync_time->tv_sec;
	    entry->inode->st.st_atim.tv_nsec=sync_time->tv_nsec;

	    generic_dirp->st.st_ino=entry->inode->ino;

        }

        entsize=fuse_add_direntry(req, buff+buffpos, size-buffpos, generic_dirp->name, &generic_dirp->st, generic_dirp->upperfs_offset);

	if (buffpos+entsize > size) break;

	/* increase counter and clear the various fields */

        generic_dirp->upperfs_offset++;
	generic_dirp->name=NULL;
	generic_dirp->st.st_ino=0;
	generic_dirp->st.st_mode=0;

	buffpos += entsize;

    }

    out:

    if (nreturn < 0 ) {

	fuse_reply_err(req, -nreturn);

    } else {

	fuse_reply_buf(req, buff, buffpos);

    }

    if ( buff ) {

	free(buff);
	buff=NULL;

    }

}

static void overlayfs_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t offset, struct fuse_file_info *fi)
{
    struct generic_dirp_struct *generic_dirp=(struct generic_dirp_struct *) (uintptr_t) fi->fh;

    if (generic_dirp->virtual==1) {

	overlayfs_readdir_virtual(req, size, offset, generic_dirp);

    } else {

	overlayfs_readdir_real(req, size, offset, generic_dirp);

    }

}

static void overlayfs_releasedir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
    struct generic_dirp_struct *generic_dirp=(struct generic_dirp_struct *) (uintptr_t) fi->fh;

    (void) ino;

    logoutput("RELEASEDIR");

    if (generic_dirp) {

	if (generic_dirp->virtual==0) {
	    struct inode_struct *inode=generic_dirp->parent->inode;

	    if (generic_dirp->data) {

	        closedir((DIR *)generic_dirp->data);
		generic_dirp->data=NULL;

	    }

	    remove_old_entries(generic_dirp->parent, &generic_dirp->parent->inode->st.st_atim);

	}

	free(generic_dirp);
	generic_dirp=NULL;


    }

    fuse_reply_err(req, 0);

    fi->fh=0;

}

static void overlayfs_statfs(fuse_req_t req, fuse_ino_t ino)
{
    struct statvfs st;
    int nreturn=0, res;
    struct entry_struct *entry; 
    struct inode_struct *inode;
    struct call_info_struct call_info=CALL_INFO_INIT;

    logoutput("STATFS");

    inode=find_inode_generic(ino);

    if ( ! inode ) {

	nreturn=-ENOENT;
	goto out;

    }

    entry=inode->alias;

    if ( ! entry ){

	nreturn=-ENOENT;
	goto out;

    }

    memset(&st, 0, sizeof(statvfs));

    /* should the statvfs be taken of the path or the root ?? */

    res=statvfs("/", &st);

    if ( res==0 ) {

	// take some values from the default

	/* note the fs does not provide opening/reading/writing of files, so info about blocksize etc
	   is useless, so do not override the default from the root */ 

	// st.f_bsize=4096; /* good?? */
	// st.f_frsize=st.f_bsize; /* no fragmentation on this fs */
	st.f_blocks=0;

	st.f_bfree=0;
	st.f_bavail=0;

	st.f_files=get_inoctr();
	st.f_ffree=UINT32_MAX - st.f_files ; /* inodes are of unsigned long int, 4 bytes:32 */
	st.f_favail=st.f_ffree;

	// do not know what to put here... just some default values... no fsid.... just zero

	st.f_fsid=0;
	st.f_flag=0;
	st.f_namemax=255;

    } else {

	nreturn=-errno;

    }

    out:

    if (nreturn==0) {

	fuse_reply_statfs(req, &st);

    } else {

        fuse_reply_err(req, nreturn);

    }

    logoutput("statfs,nreturn: %i", nreturn);

}

static void overlayfs_init (void *userdata, struct fuse_conn_info *conn)
{

    logoutput("INIT");

}

static void overlayfs_destroy (void *userdata)
{

    logoutput("DESTROY");

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
    .releasedir	= overlayfs_releasedir,
    .statfs	= overlayfs_statfs,
};

int process_server_event(struct notifyfs_connection_struct *connection, uint32_t events)
{

    if (events & EPOLLIN) {

	int res=receive_message(connection->fd, connection->data, events, NOTIFYFS_OWNERTYPE_SERVER, recv_buffer, NOTIFYFS_RECVBUFFERSIZE);

    }

    if (events & (EPOLLHUP|EPOLLRDHUP) ) {

	logoutput("process_server_event: hangup of remote site");

    }

    return 0;

}

/* send a client message, from client to server, like:
   - register a client as app or as fs or both
   - signoff as client at server
   - give messagemask, to inform the server about what messages to receive, like mountinfo
   */

void send_register_to_server(int fd, char *path)
{
    uint64_t unique=new_uniquectr();

    if (send_register_message(fd, unique, getpid(), NOTIFYFS_CLIENTTYPE_FUSEFS,(void *) path, strlen(path)+1)>0) {
	int res;

	init_notifyfs_reply(unique);
	res=wait_for_notifyfs_reply(unique, 5);

	if (res==-ETIMEDOUT) {

	    logoutput("send_register_to_server: waiting for reply timed out");

	} else if (res<0) {

	    logoutput("send_register_to_server: error %i waiting a reply", res);

	} else {

	    logoutput("send_register_to_server: received a reply");

	}

    }

}

int main(int argc, char *argv[])
{
    int res, epoll_fd=0;
    struct fuse_args global_fuse_args = FUSE_ARGS_INIT(0, NULL);
    struct workerthreads_queue_struct workerthreads_queue=WORKERTHREADS_QUEUE_INIT;

    umask(0);

    // set logging

    openlog("fuse.overlayfs", 0,0); 

    /* parse commandline options and initialize the fuse options */

    res=parse_arguments(argc, argv, &global_fuse_args);

    if ( res<0 ) {

	res=0;
	goto skipeverything;

    }

    set_max_nr_workerthreads(&workerthreads_queue, 6);
    add_workerthreads(&workerthreads_queue, 6);

    init_changestate(&workerthreads_queue);

    /*
        init the hash lookup tables
    */

    res=init_hashtables();

    if ( res<0 ) {

	fprintf(stderr, "Error, cannot intialize hash tables (error: %i).\n", abs(res));
	exit(1);

    }

    /*
        create the root inode and entry
    */

    res=create_root();

    if ( res<0 ) {

	fprintf(stderr, "Error, failed to create the root entry(error: %i).\n", res);
	exit(1);

    }

    /*
        set default options
    */

    loglevel=overlayfs_options.logging;
    logarea=overlayfs_options.logarea;

    overlayfs_options.attr_timeout=1.0;
    overlayfs_options.entry_timeout=1.0;
    overlayfs_options.negative_timeout=1.0;

    res = fuse_daemonize(0);

    if ( res!=0 ) {

        logoutput("Error daemonize.");
        goto out;

    }

    /* initialize the eventloop (using epoll) */

    epoll_fd=init_eventloop(NULL, 1, 0);

    if ( epoll_fd<0 ) {

        logoutput("Error creating epoll fd, error: %i.", epoll_fd);
        goto out;

    } else {

	logoutput("Init mainloop, epoll fd: %i", epoll_fd);

    }

    /*
	fs notify backends
    */

    initialize_fsnotify_backends();


    /*
        connect to the notifyfs server
    */

    notifyfsserver.fd=0;
    init_xdata(&notifyfsserver.xdata_socket);
    notifyfsserver.data=NULL;
    notifyfsserver.type=0;
    notifyfsserver.allocated=0;
    notifyfsserver.process_event=NULL;

    if (strlen(overlayfs_options.notifyfs_socket)>0) {

	init_handleclientmessage(&workerthreads_queue);

	int socket_fd=create_local_clientsocket(overlayfs_options.notifyfs_socket, &notifyfsserver, NULL, process_server_event);

	if ( socket_fd<=0 ) {

    	    logoutput("Error creating socket fd: %i when connecting to %s", socket_fd, overlayfs_options.notifyfs_socket);
	    res=socket_fd;
    	    goto out;

	}

	recv_buffer=malloc(NOTIFYFS_RECVBUFFERSIZE);

	if (! recv_buffer) {

	    logoutput("Error creating the buffer to receive messages from notifyfs server.");
	    res=-ENOMEM;
	    goto out;

	}

	send_register_to_server(socket_fd, overlayfs_options.mountpoint);

    }

    /* add the fuse channel(=fd) to the mainloop */

    res=initialize_fuse(overlayfs_options.mountpoint, "overlayfs", &overlayfs_oper, sizeof(overlayfs_oper), &global_fuse_args, &workerthreads_queue);
    if (res<0) goto out;

    res=start_epoll_eventloop(NULL);

    out:

    finish_fuse();

    /* remove any remaining xdata from mainloop */

    destroy_eventloop(NULL);
    fuse_opt_free_args(&global_fuse_args);

    destroy_workerthreads_queue(&workerthreads_queue);

    skipeverything:

    closelog();

    return res ? 1 : 0;

}
