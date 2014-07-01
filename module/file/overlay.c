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
#include <sys/vfs.h>

#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif

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

#include "overlay.h"

struct fs_options_struct fs_options;
struct workerthreads_queue_struct workerthreads_queue;

extern const char *rootpath;
extern const char *dotdotname;
extern const char *dotname;

struct workspace_object_struct *overlay_connect(struct workspace_uri_struct *uri, struct workspace_mount_struct *workspace, unsigned int *error)
{
    struct workspace_object_struct *object=NULL;
    struct resource_struct *resource=NULL;
    struct localfile_struct *localfile=NULL;
    struct stat st;

    logoutput("overlay_connect: initialize overlay browsing");

    if (stat(uri->address, &st)==1) {

	*error=errno;
	return NULL;

    } else if (! S_ISDIR(st.st_mode)) {

	*error=ENOTDIR;
	return NULL;

    }

    object=get_workspace_object();

    if (! object) {

	*error=ENOMEM;
	return NULL;

    }

    object->workspace_mount=workspace;
    set_module_calls_overlay(&object->module_calls);

    lock_resources();

    resource=get_next_resource(NULL);

    while(resource) {

	if (resource->group==RESOURCE_GROUP_FILE) {

	    localfile=(struct localfile_struct *) resource->data;

	    if (localfile->pathinfo.path) {

		if (strcmp(localfile->pathinfo.path, uri->address)==0) break;

	    }

	}

	resource=get_next_resource(resource);

    }

    if (resource) {

	resource->refcount++;
	object->resource=resource;

    } else {

	resource=get_resource();
	localfile=malloc(sizeof(struct localfile_struct));

	if (resource && localfile) {
	    unsigned int len=strlen(uri->address);

	    resource->security=RESOURCE_SECURITY_PUBLIC;
	    resource->status=RESOURCE_STATUS_OK;
	    resource->group=RESOURCE_GROUP_FILE;

	    resource->data=(void *) localfile;
	    resource->refcount=1;

	    localfile->options=0;

	    localfile->pathinfo.path=malloc(len + 1);

	    if (localfile->pathinfo.path) {

		strcpy(localfile->pathinfo.path, uri->address);
		localfile->pathinfo.len=len;
		localfile->pathinfo.flags=PATHINFO_FLAGS_ALLOCATED;

	    } else {

		*error=ENOMEM;

	    }

	    insert_resource_list(resource);

	    object->resource=resource;

	} else {

	    if (resource) {

		free_resource(resource);
		resource=NULL;

	    }

	    if (localfile) {

		free(localfile);
		localfile=NULL;

	    }

	    free(object);
	    object=NULL;

	    *error=ENOMEM;

	}

    }

    unlock:

    unlock_resources();

    return object;

}

static void overlay_destroy(struct workspace_object_struct *object)
{

    logoutput("overlay_destroy: destroy overlay browsing");
}

static void overlay_lookup_cached(fuse_req_t req, struct entry_struct *entry, struct call_info_struct *call_info)
{
    struct resource_struct *resource=call_info->object->resource;
    struct localfile_struct *localfile=(struct localfile_struct *) resource->data;
    struct pathinfo_struct *pathinfo=&call_info->pathinfo;
    unsigned int len0=pathinfo->len - call_info->relpath, len1=localfile->pathinfo.len;
    char path[len0 + len1 + 1];
    struct stat st;

    memcpy(path, localfile->pathinfo.path, len1);

    if (len0>0) {

	memcpy(path+len1, pathinfo->path + call_info->relpath, len0);
	len1+=len0;

    }

    path[len1]='\0';

    memset(&st, 0, sizeof(struct stat));

    logoutput("overlayfs_lookup_cached, path %s", path);

    if (lstat(path, &st)==-1) {
	struct inode_struct *inode=entry->inode;
	unsigned int error=0;

	inode=entry->inode;
	inode->alias=NULL;

	remove_entry(entry, &error);
	queue_remove(call_info->object, entry, &error);
	entry=NULL;

	fuse_reply_err(req, ENOENT);

    } else {
	struct fuse_entry_param e;
	struct inode_struct *inode=entry->inode;

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

	    inode->size=st.st_size;
	    e.attr.st_size = st.st_size;

	}

	inode->mtim.tv_sec=st.st_mtim.tv_sec;
	inode->mtim.tv_nsec=st.st_mtim.tv_nsec;

	inode->ctim.tv_sec=st.st_ctim.tv_sec;
	inode->ctim.tv_nsec=st.st_ctim.tv_nsec;

	fuse_reply_entry(req, &e);

    }

    free_path_pathinfo(&call_info->pathinfo);

}

static void overlay_lookup_noncached(fuse_req_t req, struct inode_struct *pinode, struct name_struct *xname, struct call_info_struct *call_info)
{
    struct resource_struct *resource=call_info->object->resource;
    struct localfile_struct *localfile=(struct localfile_struct *) resource->data;
    struct pathinfo_struct *pathinfo=&call_info->pathinfo;
    unsigned int len0=pathinfo->len - call_info->relpath, len1=localfile->pathinfo.len;
    char path[len0 + len1 + 1];
    struct stat st;

    memcpy(path, localfile->pathinfo.path, len1);

    if (len0>0) {

	memcpy(path+len1, pathinfo->path + call_info->relpath, len0);
	len1+=len0;

    }

    path[len1]='\0';

    memset(&st, 0, sizeof(struct stat));

    logoutput("overlayfs_lookup_cached, path %s", path);

    if (lstat(path, &st)==-1) {

	fuse_reply_err(req, ENOENT);

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

		inode->size=st.st_size;
		e.attr.st_size = st.st_size;

	    }

	    inode->mtim.tv_sec=st.st_mtim.tv_sec;
	    inode->mtim.tv_nsec=st.st_mtim.tv_nsec;

	    inode->ctim.tv_sec=st.st_ctim.tv_sec;
	    inode->ctim.tv_nsec=st.st_ctim.tv_nsec;

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

static void overlay_getattr(fuse_req_t req, struct entry_struct *entry, struct call_info_struct *call_info)
{
    struct resource_struct *resource=call_info->object->resource;
    struct localfile_struct *localfile=(struct localfile_struct *) resource->data;
    struct pathinfo_struct *pathinfo=&call_info->pathinfo;
    unsigned int len0=pathinfo->len - call_info->relpath, len1=localfile->pathinfo.len;
    char path[len0 + len1 + 1];
    struct stat st;

    memcpy(path, localfile->pathinfo.path, len1);

    if (len0>0) {

	memcpy(path+len1, pathinfo->path + call_info->relpath, len0);
	len1+=len0;

    }

    path[len1]='\0';

    memset(&st, 0, sizeof(struct stat));

    logoutput("overlayfs_getattr, path %s", path);

    if (lstat(path, &st)==-1) {

	fuse_reply_err(req, ENOENT);

    } else {
	struct inode_struct *inode=entry->inode;

	inode->mode=st.st_mode;
	inode->nlink=st.st_nlink;
	inode->uid=st.st_uid;
	inode->gid=st.st_gid;
	inode->rdev=st.st_rdev;

	if (S_ISDIR(st.st_mode)) {

	    st.st_size=0;

	} else {

	    inode->size=st.st_size;

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

static void overlay_mkdir(fuse_req_t req, struct inode_struct *pinode, struct name_struct *xname, struct call_info_struct *call_info, mode_t mode)
{
    struct resource_struct *resource=call_info->object->resource;
    struct localfile_struct *localfile=(struct localfile_struct *) resource->data;
    struct pathinfo_struct *pathinfo=&call_info->pathinfo;
    unsigned int len0=pathinfo->len - call_info->relpath, len1=localfile->pathinfo.len;
    char path[len0 + len1 + 1];
    struct stat st;
    struct entry_struct *entry=NULL, *parent=pinode->alias;
    struct inode_struct *inode=NULL;

    memcpy(path, localfile->pathinfo.path, len1);

    if (len0>0) {

	memcpy(path+len1, pathinfo->path + call_info->relpath, len0);
	len1+=len0;

    }

    path[len1]='\0';

    entry=create_entry(parent, xname);
    inode=create_inode();

    if (entry && inode) {
	struct entry_struct *result=NULL;
	unsigned int error=0;

	entry->inode=inode;
	inode->alias=entry;

	result=insert_entry(entry, &error, _ENTRY_FLAG_TEMP);

	if (result==entry) {
	    uid_t uid_keep=setfsuid(call_info->uid);
	    gid_t gid_keep=setfsgid(call_info->gid);
	    mode_t umask_keep=umask(call_info->umask);

	    mode = (mode & 01777 & ~call_info->umask ) | S_IFDIR;

	    if (mkdir(path, mode)==0) {
    		struct fuse_entry_param e;

		adjust_pathmax(call_info->pathinfo.len);
		add_inode_hashtable(inode, increase_inodes_workspace, (void *) call_info->workspace_mount);

		/* here complete the insert ?? */

		inode->mode=mode;

		inode->nlink=2;
		inode->uid=call_info->uid;
		inode->gid=call_info->gid;
		inode->nlookup=1;

		inode->rdev=0;
		inode->size=0;

		get_current_time(&inode->mtim);
		memcpy(&inode->ctim, &inode->mtim, sizeof(struct timespec));

		memset(&e, 0, sizeof(e));

		e.ino = inode->ino;
		e.generation = 1;

		e.attr.st_ino = e.ino;
		e.attr.st_mode = inode->mode;
		e.attr.st_nlink = inode->nlink;
		e.attr.st_dev = 0;
		e.attr.st_uid=inode->uid;
		e.attr.st_gid=inode->gid;
		e.attr.st_size=inode->size;
		e.attr.st_rdev=inode->rdev;

		memcpy(&e.attr.st_mtim, &inode->mtim, sizeof(struct timespec));
		memcpy(&e.attr.st_ctim, &inode->mtim, sizeof(struct timespec));
		memcpy(&e.attr.st_atim, &inode->mtim, sizeof(struct timespec));

		e.attr_timeout = fs_options.attr_timeout;
		e.entry_timeout = fs_options.entry_timeout;

		e.attr.st_blksize=4096;
		e.attr.st_blocks=0;

    		fuse_reply_entry(req, &e);

	    } else {
		unsigned int error_delete=0;

		error=errno;

		remove_entry(entry, &error_delete);

		destroy_entry(entry);
		entry=NULL;

		free(inode);
		inode=NULL;

		fuse_reply_err(req, error);

	    }

	    uid_keep=setfsuid(uid_keep);
	    gid_keep=setfsgid(gid_keep);
	    umask_keep=umask(umask_keep);

	} else {

	    destroy_entry(entry);
	    entry=NULL;

	    free(inode);
	    inode=NULL;

	    if (error==0) error=EEXIST;

	    fuse_reply_err(req, error);

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

	fuse_reply_err(req, ENOMEM);

    }

}

static void overlay_mknod(fuse_req_t req, struct inode_struct *pinode, struct name_struct *xname, struct call_info_struct *call_info, mode_t mode, dev_t rdev)
{
    struct resource_struct *resource=call_info->object->resource;
    struct localfile_struct *localfile=(struct localfile_struct *) resource->data;
    struct pathinfo_struct *pathinfo=&call_info->pathinfo;
    unsigned int len0=pathinfo->len - call_info->relpath, len1=localfile->pathinfo.len;
    char path[len0 + len1 + 1];
    struct entry_struct *entry=NULL, *parent=pinode->alias;
    struct inode_struct *inode;


    memcpy(path, localfile->pathinfo.path, len1);

    if (len0>0) {

	memcpy(path+len1, pathinfo->path + call_info->relpath, len0);
	len1+=len0;

    }

    path[len1]='\0';

    entry=create_entry(parent, xname);
    inode=create_inode();

    if (entry && inode) {
	struct entry_struct *result=NULL;
	unsigned int error=0;

	entry->inode=inode;
	inode->alias=entry;

	result=insert_entry(entry, &error, _ENTRY_FLAG_TEMP);

	if (result==entry) {
	    uid_t uid_keep=setfsuid(call_info->uid);
	    gid_t gid_keep=setfsgid(call_info->gid);
	    mode_t umask_keep=umask(call_info->umask);

	    mode = (mode & ~call_info->umask);

	    if (mknod(path, mode, rdev)==0) {
    		struct fuse_entry_param e;

		adjust_pathmax(call_info->pathinfo.len);
		add_inode_hashtable(inode, increase_inodes_workspace, (void *) call_info->workspace_mount);

		/* here complete the insert ?? */

		inode->mode=mode;

		inode->nlink=1;
		inode->uid=call_info->uid;
		inode->gid=call_info->gid;
		inode->nlookup=1;

		inode->rdev=rdev;
		inode->size=0;

		get_current_time(&inode->mtim);
		memcpy(&inode->ctim, &inode->mtim, sizeof(struct timespec));

		memset(&e, 0, sizeof(e));

		e.ino = inode->ino;
		e.generation = 1;

		e.attr.st_ino = e.ino;
		e.attr.st_mode = inode->mode;
		e.attr.st_nlink = inode->nlink;
		e.attr.st_dev = 0;
		e.attr.st_uid=inode->uid;
		e.attr.st_gid=inode->gid;
		e.attr.st_size=inode->size;
		e.attr.st_rdev=inode->rdev;

		memcpy(&e.attr.st_mtim, &inode->mtim, sizeof(struct timespec));
		memcpy(&e.attr.st_ctim, &inode->mtim, sizeof(struct timespec));
		memcpy(&e.attr.st_atim, &inode->mtim, sizeof(struct timespec));

		e.attr_timeout = fs_options.attr_timeout;
		e.entry_timeout = fs_options.entry_timeout;

		e.attr.st_blksize=4096;
		e.attr.st_blocks=0;

    		fuse_reply_entry(req, &e);

	    } else {
		unsigned int error_delete=0;

		error=errno;

		remove_entry(entry, &error_delete);

		destroy_entry(entry);
		entry=NULL;

		free(inode);
		inode=NULL;

		fuse_reply_err(req, error);

	    }

	    uid_keep=setfsuid(uid_keep);
	    gid_keep=setfsgid(gid_keep);
	    umask_keep=umask(umask_keep);

	} else {

	    destroy_entry(entry);
	    entry=NULL;

	    free(inode);
	    inode=NULL;

	    if (error==0) error=EEXIST;

	    fuse_reply_err(req, error);

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

	fuse_reply_err(req, ENOMEM);

    }

}

static void overlay_readlink(fuse_req_t req, struct entry_struct *entry, struct call_info_struct *call_info)
{
    struct resource_struct *resource=call_info->object->resource;
    struct localfile_struct *localfile=(struct localfile_struct *) resource->data;
    struct pathinfo_struct *pathinfo=&call_info->pathinfo;
    unsigned int len0=pathinfo->len - call_info->relpath, len1=localfile->pathinfo.len;
    char path[len0 + len1 + 1];
    char *buff=NULL;
    size_t size=512;
    unsigned int error=0;

    memcpy(path, localfile->pathinfo.path, len1);

    if (len0>0) {

	memcpy(path+len1, pathinfo->path + call_info->relpath, len0);
	len1+=len0;

    }

    path[len1]='\0';

    logoutput("overlayfs_readlink: path %s", call_info->pathinfo.path);

    while(size<=PATH_MAX) {
	ssize_t lenread=0;

	if (buff) {

	    buff = realloc(buff, size);

	} else {

	    buff = malloc(size);

	}

	if ( buff ) {

    	    if ((lenread=readlink(path, buff, size))==-1) {

		error=errno;

		free(buff);
		goto out;

	    }

	    if (lenread < size) {

		/* success */

		buff[lenread] = '\0';
		fuse_reply_readlink(req, buff);

		free(buff);
		free_path_pathinfo(&call_info->pathinfo);

		return;

	    }

	    size+=512;

	    if (size>PATH_MAX) {

		error=ENAMETOOLONG;
		break;

	    }

	} else {

	    error=ENOMEM;
	    break;

	}

    }

    out:

    logoutput("overlayfs_readlink: error %i", error);

    fuse_reply_err(req, error);

    free_path_pathinfo(&call_info->pathinfo);

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

#define _FW_READDIR_MODE_VIRTUAL				1
#define _FW_READDIR_MODE_SIMPLE					2
#define _FW_READDIR_MODE_FULL					4

struct overlay_readdir_struct {
    unsigned char						mode;
    unsigned int 						fd;
    void							*data;
};

static inline int get_direntry(struct overlay_readdir_struct *r, struct name_struct *xname, unsigned char *dtype, unsigned int *error)
{
    struct readdir_struct *readdir=(struct readdir_struct *) r->data;

    return (* readdir->get_direntry) (readdir, xname, dtype, error);
}

static void close_readdir(struct overlay_readdir_struct *r)
{
    struct readdir_struct *readdir=(struct readdir_struct *) r->data;

    if (readdir) (* readdir->close) (readdir);
}

static void overlay_opendir(fuse_req_t req, struct workspace_dh_struct *dh)
{
    struct resource_struct *resource=dh->object->resource;
    struct localfile_struct *localfile=(struct localfile_struct *) resource->data;
    struct pathinfo_struct *pathinfo=&dh->pathinfo;
    unsigned int len0=pathinfo->len - dh->relpath, len1=localfile->pathinfo.len;
    char path[len0 + len1 + 1];
    struct overlay_readdir_struct *overlay_readdir=NULL;
    unsigned int error=0;
    int fd=-1;
    struct directory_struct *directory=dh->directory;
    struct statfs stfs;

    memcpy(path, localfile->pathinfo.path, len1);

    if (len0>0) {

	memcpy(path+len1, pathinfo->path + dh->relpath, len0);
	len1+=len0;

    }

    path[len1]='\0';

    logoutput("overlayfs_opendir: path %s", path);

    fd=open(path, O_RDONLY | O_DIRECTORY);

    if (fd==-1) {

	error=errno;
	goto error;

    }

    if (fstatfs(fd, &stfs)==-1) {

	error=errno;
	goto error;

    }

    overlay_readdir = malloc(sizeof(struct overlay_readdir_struct));

    if ( ! overlay_readdir ) {

	error=ENOMEM;
	goto error;

    }

    memset(overlay_readdir, 0, sizeof(struct overlay_readdir_struct));

    overlay_readdir->fd=(unsigned int) fd;
    overlay_readdir->data=NULL;
    overlay_readdir->mode=0;

    dh->handle.data = (void *) overlay_readdir;

    /*
	determine the type fileystem
	use a portable generic function here??
    */

    if (stfs.f_bfree==0) {

	/*
	    dealing with a system fs: use readdir
	    and a full or simple synchronize
	*/

	overlay_readdir->data=(void *) init_readdir_readdir(path, fd, &error);

	if (! overlay_readdir->data) {

	    if (error==0) error=EIO;
	    goto error;

	}

	if (directory->synctime.tv_sec==0 && directory->synctime.tv_nsec==0) {

	    overlay_readdir->mode |= _FW_READDIR_MODE_FULL;

	} else {

	    overlay_readdir->mode |= _FW_READDIR_MODE_SIMPLE;

	}

    } else {


	if (directory->synctime.tv_sec==0 && directory->synctime.tv_nsec==0) {

	    /* never synced before, a normal fs: use getdents and full sync*/

	    overlay_readdir->data=(void *) init_readdir_getdents(path, fd, &error);

	    if (! overlay_readdir->data) {

		if (error==0) error=EIO;
		goto error;

	    }

	    overlay_readdir->mode |= _FW_READDIR_MODE_FULL;

	} else {
	    struct stat st;

	    if (fstat(fd, &st)==-1) {

		error=errno;
		goto error;

	    }

	    logoutput("overlayfs_opendir: compare modifytime %li:%li with synctime %li:%li", st.st_mtim.tv_sec, st.st_mtim.tv_nsec, directory->synctime.tv_sec, directory->synctime.tv_nsec);

	    if (st.st_mtim.tv_sec>directory->synctime.tv_sec ||
		(st.st_mtim.tv_sec==directory->synctime.tv_sec && st.st_mtim.tv_nsec>directory->synctime.tv_nsec)) {

		/*
		    directory modification time is changed since last check
		    this means entries are added or removed
		*/

		overlay_readdir->data=(void *) init_readdir_getdents(path, fd, &error);

		if (! overlay_readdir->data) {

		    if (error==0) error=EIO;
		    goto error;

		}

		overlay_readdir->mode |= _FW_READDIR_MODE_SIMPLE;

	    } else {

		overlay_readdir->data=(void *) directory->first;
		overlay_readdir->mode |= _FW_READDIR_MODE_VIRTUAL;

	    }

	}

    }

    fuse_reply_open(req, dh->fi);
    //add_pathcache(&dh->pathinfo, dh->parent, dh->object, dh->relpath);
    free_path_pathinfo(&dh->pathinfo);

    return;

    error:

    fuse_reply_err(req, error);

    if (fd>0) {

	close(fd);
	fd=-1;

    }

    if (overlay_readdir) {

	if (overlay_readdir->data && (overlay_readdir->mode & (_FW_READDIR_MODE_SIMPLE | _FW_READDIR_MODE_FULL))) {
	    struct readdir_struct *readdir=(struct readdir_struct *) overlay_readdir->data;

	    if (readdir->close) {

		(* readdir->close) (readdir);

	    } else {

		free(readdir);

	    }

	}

	overlay_readdir->data=NULL;
	free(overlay_readdir);
	overlay_readdir=NULL;

    }

    logoutput("overlayfs_opendir, error %i", error);
    free_path_pathinfo(&dh->pathinfo);

}

static void overlay_readdir_virtual(fuse_req_t req, size_t size, off_t offset, struct workspace_dh_struct *dh)
{
    unsigned int error=0;
    char *buff=NULL;
    size_t pos=0;
    size_t dirent_size;
    struct stat st;
    char *name=NULL;
    struct name_struct xname={NULL, 0, 0};
    struct entry_struct *entry=NULL;
    struct inode_struct *inode=NULL;
    struct directory_struct *directory=dh->directory;
    struct overlay_readdir_struct *overlay_readdir=(struct overlay_readdir_struct *)dh->handle.data;
    unsigned char dtype=0;

    memset(&st, 0, sizeof(struct stat));

    buff=malloc(size);

    if (! buff) {

	error=ENOMEM;
	goto error;

    }

    if (lock_directory(directory, _DIRECTORY_LOCK_READ)==-1) {

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

		readdir:

		entry=(struct entry_struct *) overlay_readdir->data;

		if (entry) {

		    overlay_readdir->data=(void *) entry->name_next;

		} else {

		    dh->mode |= _WORKSPACE_READDIR_MODE_FINISH;
		    break;

		}

		dh->entry=entry;

	    } else {

		entry=dh->entry;

	    }

	    name=entry->name.name;
	    st.st_mode=entry->inode->mode;
	    st.st_ino=entry->inode->ino;

	}

    	dirent_size=fuse_add_direntry(req, buff+pos, size-pos, name, &st, offset+1);

	if (pos + dirent_size > size) {

	    dh->offset=offset + 1;
	    break;

	}

	/* increase counter and clear the various fields */

	offset++;
	pos += dirent_size;
	dh->entry=NULL;

    }

    fuse_reply_buf(req, buff, pos);

    unlock_directory(directory, _DIRECTORY_LOCK_READ);

    free(buff);
    buff=NULL;

    return;

    error:

    fuse_reply_err(req, error);

}

static void overlay_readdir_simple(fuse_req_t req, size_t size, off_t offset, struct workspace_dh_struct *dh)
{
    unsigned int error=0;
    char *buff=NULL;
    size_t pos=0;
    size_t dirent_size;
    struct stat st;
    char *name=NULL;
    struct directory_struct *directory=dh->directory;
    struct overlay_readdir_struct *overlay_readdir=(struct overlay_readdir_struct *)dh->handle.data;
    struct entry_struct *entry, *result;
    struct inode_struct *inode;
    unsigned char dtype=0;
    struct name_struct xname={NULL, 0, 0};
    int res=0;

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

		readdir:

		res=get_direntry(overlay_readdir, &xname, &dtype, &error);

		if (res<=0) {

		    if (res==-1) {

			free(buff);
			unlock_directory(directory, _DIRECTORY_LOCK_EXCL);
			goto error;

		    }

		    dh->mode |= _WORKSPACE_READDIR_MODE_FINISH;
		    break;

		}

		xname.len=strlen(xname.name);
		calculate_nameindex(&xname);

		error=0;

		entry=create_entry(dh->parent, &xname);
		inode=create_inode();

		if (entry && inode) {

		    result=insert_entry_batch(directory, entry, &error, 0);

		    if (result==entry) {

			entry->inode->mode=DTTOIF(dtype);

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

static void overlay_readdir_full(fuse_req_t req, size_t size, off_t offset, struct workspace_dh_struct *dh)
{
    unsigned int error=0;
    char *buff=NULL;
    size_t pos=0;
    size_t dirent_size;
    struct stat st;
    char *name=NULL;
    struct directory_struct *directory=dh->directory;
    struct overlay_readdir_struct *overlay_readdir=(struct overlay_readdir_struct *)dh->handle.data;
    struct entry_struct *entry, *result;
    struct inode_struct *inode;
    struct name_struct xname={NULL, 0, 0};
    unsigned char dtype=0;
    int res;

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

	    if ( ! dh->parent->parent ) {

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

		readdir:

		res=get_direntry(overlay_readdir, &xname, &dtype, &error);

		if (res<=0) {

		    if (res==-1) {

			free(buff);
			unlock_directory(directory, _DIRECTORY_LOCK_EXCL);
			goto error;

		    }

		    dh->mode |= _WORKSPACE_READDIR_MODE_FINISH;
		    break;

		}

		xname.len=strlen(xname.name);
		calculate_nameindex(&xname);

		error=0;

		entry=create_entry(dh->parent, &xname);
		inode=create_inode();

		if (entry && inode) {

		    result=insert_entry_batch(directory, entry, &error, 0);

		    if (result==entry) {

			entry->inode->mode=DTTOIF(dtype);

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

		entry=dh->entry;

		st.st_ino=entry->inode->ino;
		st.st_mode=entry->inode->mode;
		name=entry->name.name;

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

static void overlay_readdirplus_virtual(fuse_req_t req, size_t size, off_t offset, struct workspace_dh_struct *dh)
{
    unsigned int error=0;
    char *buff=NULL;
    size_t pos=0;
    size_t dirent_size;
    struct fuse_entry_param e;
    char *name=NULL;
    struct name_struct xname={NULL, 0, 0};
    unsigned char dtype=0;
    struct directory_struct *directory=dh->directory;
    struct overlay_readdir_struct *overlay_readdir=(struct overlay_readdir_struct *)dh->handle.data;
    struct entry_struct *entry=NULL;
    struct inode_struct *inode=NULL;

    memset(&e, 0, sizeof(struct fuse_entry_param));

    e.generation = 1;
    e.attr_timeout = fs_options.attr_timeout;
    e.entry_timeout = fs_options.entry_timeout;

    e.attr.st_blksize=4096;
    e.attr.st_blocks=0;

    buff=malloc(size);

    if (! buff) {

	error=ENOMEM;
	goto error;

    }

    if (lock_directory(directory, _DIRECTORY_LOCK_READ)==-1) {

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
	    e.attr.st_size = 0;
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

	    if ( ! dh->parent->parent) {

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

	    if (! dh->entry) {

		readdir:

		entry=(struct entry_struct *) overlay_readdir->data;

		if (entry) {

		    overlay_readdir->data=(void *) entry->name_next;

		} else {

		    dh->mode |= _WORKSPACE_READDIR_MODE_FINISH;
		    break;

		}

		dh->entry=entry;

	    } else {

		entry=dh->entry;

	    }

	    inode=entry->inode;

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

		e.attr.st_size = inode->size;

	    }

	    e.attr.st_atim.tv_sec = 0;
	    e.attr.st_atim.tv_nsec = 0;
	    e.attr.st_mtim.tv_sec = inode->mtim.tv_sec;
	    e.attr.st_mtim.tv_nsec = inode->mtim.tv_nsec;
	    e.attr.st_ctim.tv_sec = inode->ctim.tv_sec;
	    e.attr.st_ctim.tv_nsec = inode->ctim.tv_nsec;

	    name=entry->name.name;
	    inode->nlookup++;

	}

    	dirent_size=fuse_add_direntry_plus(req, buff+pos, size-pos, name, &e, offset+1);

	if (pos + dirent_size > size) {

	    dh->offset=offset+1;
	    break;

	}

	/* increase counter and clear the various fields */

	dh->entry=NULL; /* forget current entry to force readdir */
	offset++;
	pos += dirent_size;

    }

    unlock_directory(directory, _DIRECTORY_LOCK_READ);

    fuse_reply_buf(req, buff, pos);

    free(buff);
    buff=NULL;

    return;

    error:

    fuse_reply_err(req, error);

}

static void overlay_readdirplus_simple(fuse_req_t req, size_t size, off_t offset, struct workspace_dh_struct *dh)
{
    unsigned int error=0;
    char *buff=NULL;
    size_t pos=0;
    size_t dirent_size;
    struct fuse_entry_param e;
    char *name=NULL;
    struct directory_struct *directory=dh->directory;
    struct overlay_readdir_struct *overlay_readdir=(struct overlay_readdir_struct *)dh->handle.data;
    struct entry_struct *entry;
    struct inode_struct *inode;
    unsigned char dtype;
    struct name_struct xname={NULL, 0, 0};
    int res=0;

    memset(&e, 0, sizeof(struct fuse_entry_param));

    e.generation = 1;
    e.attr_timeout = fs_options.attr_timeout;
    e.entry_timeout = fs_options.entry_timeout;

    e.attr.st_blksize=4096;
    e.attr.st_blocks=0;

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
	    e.attr.st_size = 0;
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

	    if (! dh->entry) {

		readdir:

		res=get_direntry(overlay_readdir, &xname, &dtype, &error);

		if (res<=0) {

		    if (res==-1) {

			free(buff);
			unlock_directory(directory, _DIRECTORY_LOCK_EXCL);
			goto error;

		    }

		    dh->mode |= _WORKSPACE_READDIR_MODE_FINISH;
		    break;

		}

		if (fstatat(overlay_readdir->fd, xname.name, &e.attr, AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT)==-1) {

		    goto readdir;

		}

		xname.len=strlen(xname.name);
		calculate_nameindex(&xname);

		error=0;

		entry=find_entry_batch(directory, &xname, &error);

		if (! entry) {

		    entry=create_entry(dh->parent, &xname);
		    inode=create_inode();

		    if (entry && inode) {

			add_inode_hashtable(inode, increase_inodes_workspace, (void *) dh->object->workspace_mount);

			insert_entry_batch(directory, entry, &error, 0);

			inode=entry->inode;

			memcpy(&entry->synctime, &dh->synctime, sizeof(struct timespec));

			inode->nlookup++;
			adjust_pathmax(dh->pathinfo.len + 1 + xname.len);

		    } else {

			error=ENOMEM;
			free(buff);

			goto error;

		    }

		} else {

		    inode=entry->inode;
		    memcpy(&entry->synctime, &dh->synctime, sizeof(struct timespec));

		    inode->nlookup++;

		}

		name=entry->name.name;
		dh->entry=entry;

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

		    inode->size=e.attr.st_size;

		}

	    } else {

		entry=dh->entry;

		inode=entry->inode;
		name=entry->name.name;

		e.attr.st_mode = inode->mode;
		e.attr.st_nlink = inode->nlink;
		e.attr.st_uid = inode->uid;
		e.attr.st_gid = inode->gid;
		e.attr.st_rdev = inode->rdev;

		if (S_ISDIR(inode->mode)) {

		    e.attr.st_size = 0;

		} else {

		    e.attr.st_size = inode->size;

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

    	dirent_size=fuse_add_direntry_plus(req, buff+pos, size-pos, name, &e, offset+1);

	if (pos + dirent_size > size) {

	    dh->offset=offset+1;
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

static void overlay_readdirplus_full(fuse_req_t req, size_t size, off_t offset, struct workspace_dh_struct *dh)
{
    unsigned int error=0;
    char *buff=NULL;
    size_t pos=0;
    size_t dirent_size;
    struct fuse_entry_param e;
    char *name=NULL;
    struct directory_struct *directory=dh->directory;
    struct overlay_readdir_struct *overlay_readdir=(struct overlay_readdir_struct *)dh->handle.data;
    struct entry_struct *entry, *result;
    struct inode_struct *inode;
    unsigned char dtype;
    struct name_struct xname={NULL, 0, 0};
    int res=0;

    memset(&e, 0, sizeof(struct fuse_entry_param));

    e.generation = 1;
    e.attr_timeout = fs_options.attr_timeout;
    e.entry_timeout = fs_options.entry_timeout;

    e.attr.st_blksize=4096;
    e.attr.st_blocks=0;

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
	    e.attr.st_size = 0;
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

	    if (! dh->entry) {

		readdir:

		res=get_direntry(overlay_readdir, &xname, &dtype, &error);

		if (res<=0) {

		    if (res==-1) {

			free(buff);
			unlock_directory(directory, _DIRECTORY_LOCK_EXCL);
			goto error;

		    }

		    dh->mode |= _WORKSPACE_READDIR_MODE_FINISH;
		    break;

		}

		if (fstatat(overlay_readdir->fd, xname.name, &e.attr, AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT)==-1) {

		    goto readdir;

		}

		xname.len=strlen(xname.name);
		calculate_nameindex(&xname);

		error=0;

		entry=create_entry(dh->parent, &xname);
		inode=create_inode();

		if (entry && inode) {

		    result=insert_entry_batch(directory, entry, &error, 0);

		    if (result==entry) {

			memcpy(&entry->synctime, &dh->synctime, sizeof(struct timespec));
			inode->mode=DTTOIF(dtype);

			add_inode_hashtable(inode, increase_inodes_workspace, (void *) dh->object->workspace_mount);

			inode->alias=entry;
			entry->inode=inode;

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

		    e.attr.st_ino=inode->ino;
		    e.ino=inode->ino;
		    e.attr.st_rdev = inode->rdev;
		    e.attr.st_dev = 0;
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

		name=entry->name.name;
		dh->entry=entry;

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

		    inode->size=e.attr.st_size;

		}

	    } else {

		entry=dh->entry;
		inode=entry->inode;
		name=entry->name.name;

		e.attr.st_mode = inode->mode;
		e.attr.st_nlink = inode->nlink;
		e.attr.st_uid = inode->uid;
		e.attr.st_gid = inode->gid;
		e.attr.st_rdev = inode->rdev;

		if (S_ISDIR(inode->mode)) {

		    e.attr.st_size = 0;

		} else {

		    e.attr.st_size = inode->size;

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

    	dirent_size=fuse_add_direntry_plus(req, buff+pos, size-pos, name, &e, offset+1);

	if (pos + dirent_size > size) {

	    dh->offset=offset+1;
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

static void overlay_readdir(fuse_req_t req, size_t size, off_t offset, struct workspace_dh_struct *dh)
{
    struct overlay_readdir_struct *overlay_readdir=(struct overlay_readdir_struct *)dh->handle.data;

    if (overlay_readdir->mode & _FW_READDIR_MODE_VIRTUAL) {

	overlay_readdir_virtual(req, size, offset, dh);

    } else if (overlay_readdir->mode & _FW_READDIR_MODE_SIMPLE) {

	overlay_readdir_simple(req, size, offset, dh);

    } else if (overlay_readdir->mode & _FW_READDIR_MODE_FULL) {

	overlay_readdir_full(req, size, offset, dh);

    }

}

static void overlay_readdirplus(fuse_req_t req, size_t size, off_t offset, struct workspace_dh_struct *dh)
{

    struct overlay_readdir_struct *overlay_readdir=(struct overlay_readdir_struct *)dh->handle.data;

    if (overlay_readdir->mode & _FW_READDIR_MODE_VIRTUAL) {

	overlay_readdirplus_virtual(req, size, offset, dh);

    } else if (overlay_readdir->mode & _FW_READDIR_MODE_SIMPLE) {

	overlay_readdirplus_simple(req, size, offset, dh);

    } else if (overlay_readdir->mode & _FW_READDIR_MODE_FULL) {

	overlay_readdirplus_full(req, size, offset, dh);

    }

}

static void overlay_releasedir(fuse_req_t req, struct workspace_dh_struct *dh)
{
    struct overlay_readdir_struct *overlay_readdir=(struct overlay_readdir_struct *)dh->handle.data;
    struct directory_struct *directory=NULL;
    struct timespec synctime;
    unsigned int error=0;
    unsigned int mode=0;

    logoutput("overlay_releasedir");

    directory=dh->directory;

    if (overlay_readdir) {

	mode=overlay_readdir->mode;

	close_readdir(overlay_readdir);

	if (overlay_readdir->fd>0) {

	    close(overlay_readdir->fd);
	    overlay_readdir->fd=0;

	}

	free(overlay_readdir);
	overlay_readdir=NULL;

    }

    fuse_reply_err(req, 0);

    if (directory) {

	/* when synced with backend and there were entries at start test these are not synced */

	if ((dh->mode & _WORKSPACE_READDIR_MODE_NONEMPTY) &&  (mode & (_FW_READDIR_MODE_SIMPLE | _FW_READDIR_MODE_FULL))) remove_old_entries(dh->object, directory, &dh->synctime);

	memcpy(&directory->synctime, &dh->synctime, sizeof(struct timespec));

    }

    // clean_pathcache();

}

void set_module_calls_overlay(struct module_calls_struct *mcalls)
{

	strcpy(mcalls->name, "overlay");

	mcalls->groupid		= 0;

	mcalls->destroy		= overlay_destroy;

	mcalls->lookup_cached	= overlay_lookup_cached;
	mcalls->lookup_noncached= overlay_lookup_noncached;
	mcalls->getattr		= overlay_getattr;

	mcalls->readlink	= overlay_readlink;

	mcalls->mknod		= overlay_mknod;
	mcalls->mkdir		= overlay_mkdir;

	mcalls->opendir		= overlay_opendir;
	mcalls->readdir		= overlay_readdir;
	mcalls->readdirplus	= overlay_readdirplus;
	mcalls->releasedir	= overlay_releasedir;
}
