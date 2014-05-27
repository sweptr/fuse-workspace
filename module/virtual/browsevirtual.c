/*
  2010, 2011, 2012, 2013, 2014 Stef Bon <stefbon@gmail.com>

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
#include <errno.h>
#include <err.h>

#include <inttypes.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/inotify.h>
#include <sys/mount.h>

#include <pthread.h>
#include <dirent.h>

#ifndef ENOATTR
#define ENOATTR ENODATA        /* No such attribute */
#endif

#include "fuse-workspace.h"
#include "entry-management.h"
#include "utils.h"
#include "options.h"
#include "beventloop-utils.h"
#include "workspaces.h"
#include "path-resolution.h"
#include "resources.h"
#include "objects.h"

#ifdef LOGGING

static unsigned char loglevel=1;

#include <syslog.h>

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

#define logoutput(...) dummy_nolog()

#endif

extern struct fs_options_struct fs_options;

extern const char *dotname;
extern const char *dotdotname;



void check_environment_vars(pid_t pid, char **workspace_uri)
{
    char path[32];
    size_t size=1024;
    int fd=0;

    logoutput("log_environment_var: pid %i", (int) pid);

    snprintf(path, 32, "/proc/%i/environ", (int) pid);

    fd=open(path, O_RDONLY);

    if (fd>0) {

	while(1) {
	    char buffer[size];
	    int nr=0;

	    nr=pread(fd, buffer, size, 0);

	    logoutput("log_environment_var: %i read for pid %i", nr, (int) pid);

	    if (nr>0 && nr<size) {
		char *sep=buffer;
		unsigned int len=strlen("WORKSPACE_URI");

		buffer[nr]='\0';

		while(sep<buffer+nr) {

		    if (strncmp(sep, "WORKSPACE_URI", len)==0) {
			char *issign=strchr(sep + len, '=');

			if (issign) {

			    logoutput("check_environment_vars: found %s, value %s", sep, issign+1);

			    if (strncmp(issign+1, "file://", 7)==0) {

				*workspace_uri=malloc(strlen(issign+7));

				if (*workspace_uri) {

				    strcpy(*workspace_uri, issign+7);

				}

			    }

			}

			break;

		    }

		    sep+=strlen(sep) + 1;

		}

		break;

	    } else if (nr==size) {

		size+=1024;

	    } else {

		break;

	    }

	}

	close(fd);

    } else {

	logoutput("log_environment_var: error %i opening path %s", errno, path);

    }

}

static void virt_init(struct workspace_object_struct *object)
{

    logoutput("virt_init: initialize virtual browsing");

}

static void virt_destroy(struct workspace_object_struct *object)
{

    logoutput("virt_destroy: destroy virtual browsing");
}

static void virt_lookup_cached(fuse_req_t req, struct entry_struct *entry, struct call_info_struct *call_info)
{
    struct fuse_entry_param e;
    struct inode_struct *inode=entry->inode;

    /* in the virtual map the entry does exist already */

    logoutput("virt_lookup, %s", entry->name.name);

    inode=entry->inode;
    inode->nlookup++;

    e.attr.st_ino = e.ino;
    e.attr.st_mode = inode->mode;
    e.attr.st_nlink = inode->nlink;
    e.attr.st_uid = inode->uid;
    e.attr.st_gid = inode->gid;
    e.attr.st_rdev = inode->rdev;
    e.attr.st_atim.tv_sec = 0;
    e.attr.st_atim.tv_nsec = 0;
    e.attr.st_mtim.tv_sec = inode->mtim.tv_sec;
    e.attr.st_mtim.tv_nsec = inode->mtim.tv_nsec;
    e.attr.st_ctim.tv_sec = inode->ctim.tv_sec;
    e.attr.st_ctim.tv_nsec = inode->ctim.tv_nsec;

    e.attr.st_blksize=4096;
    e.attr.st_blocks=0;

    if (S_ISDIR(inode->mode)) {

	e.attr.st_size = 0;

    } else {

	e.attr.st_size = inode->size;

    }

    e.ino=entry->inode->ino;
    e.generation=0;

    e.attr_timeout=fs_options.attr_timeout;
    e.entry_timeout=fs_options.entry_timeout;

    fuse_reply_entry(req, &e);

    free_path_pathinfo(&call_info->pathinfo);

}

static void virt_lookup_noncached(fuse_req_t req, struct inode_struct *pinode, struct name_struct *xname, struct call_info_struct *call_info)
{

    fuse_reply_err(req, ENOENT);

}

static void virt_getattr(fuse_req_t req, struct entry_struct *entry, struct call_info_struct *call_info)
{

    logoutput("virt_getattr");

    if (entry->inode) {
	struct stat st;
	struct inode_struct *inode=entry->inode;

	st.st_mode=inode->mode;
	st.st_nlink=inode->nlink;
	st.st_uid=inode->uid;
	st.st_gid=inode->gid;

	st.st_rdev=inode->rdev;

	st.st_size=inode->size;

	memcpy(&st.st_mtim, &inode->mtim, sizeof(struct timespec));
	memcpy(&st.st_ctim, &inode->ctim, sizeof(struct timespec));

	st.st_ino=inode->ino;
	st.st_dev=0;

	fuse_reply_attr(req, &st, fs_options.attr_timeout);

	free_path_pathinfo(&call_info->pathinfo);

	return;

    }

    fuse_reply_err(req, ENOENT); /* good error? */
    free_path_pathinfo(&call_info->pathinfo);

}

static unsigned int generic_virt_setattr(fuse_req_t req, struct inode_struct *inode, struct stat *st, int toset, unsigned int *error)
{

    if ( toset & FUSE_SET_ATTR_MODE ) inode->mode=st->st_mode;

    if (toset & FUSE_SET_ATTR_MTIME) {
	struct timespec rightnow;
	unsigned char clockset=0;

	if (toset&FUSE_SET_ATTR_MTIME_NOW) {

	    get_current_time(&inode->mtim);

	} else if (toset&FUSE_SET_ATTR_MTIME) {

	    memcpy(&inode->mtim, &st->st_mtim, sizeof(struct timespec));

	}

    }

    if (toset & (FUSE_SET_ATTR_UID|FUSE_SET_ATTR_GID)) {
	uid_t uid=(toset & FUSE_SET_ATTR_UID) ? st->st_uid : (uid_t) -1;
	gid_t gid=(toset & FUSE_SET_ATTR_GID) ? st->st_gid : (gid_t) -1;

	/* virtual maps always owned by root and noone else */

	if (uid>0 || gid>0) {

	    *error=EACCES;

	}

    }

    out:

    return *error;

}

static void virt_setattr(fuse_req_t req, struct entry_struct *entry, struct call_info_struct *call_info, struct stat *st, int toset)
{
    unsigned int error=0;
    struct inode_struct *inode=entry->inode;

    logoutput("virt_setattr");

    if (generic_virt_setattr(req, inode, st, toset, &error)==0) {
	struct stat st_set;

	st_set.st_mode=inode->mode;
	st_set.st_nlink=inode->nlink;
	st_set.st_uid=inode->uid;
	st_set.st_gid=inode->gid;
	st_set.st_rdev=inode->rdev;

	memcpy(&st_set.st_mtim, &inode->mtim, sizeof(struct timespec));
	memcpy(&st_set.st_ctim, &inode->ctim, sizeof(struct timespec));

	st_set.st_size=inode->size;
	st_set.st_ino=inode->ino;

	fuse_reply_attr(req, &st_set, fs_options.attr_timeout);

    } else {

	error=(error==0) ? EIO : error;
	fuse_reply_err(req, error);

    }

    free_path_pathinfo(&call_info->pathinfo);

}

static void virt_readlink (fuse_req_t req, struct entry_struct *entry, struct call_info_struct *call_info)
{

    logoutput("virt_readlink");

    /* symbolic links are not supported in virtual maps */

    fuse_reply_err(req, ENOTSUP);
    free_path_pathinfo(&call_info->pathinfo);

}

static void virt_mknod (fuse_req_t req, struct inode_struct *pinode, struct name_struct *xname, struct call_info_struct *call_info, mode_t mode, dev_t rdev)
{

    logoutput("virt_mknod");

    fuse_reply_err(req, EACCES);

    free_path_pathinfo(&call_info->pathinfo);

}

static void virt_symlink (fuse_req_t req, struct inode_struct *inode,  struct name_struct *name, struct call_info_struct *call_info, const char *link)
{

    logoutput("virt_symlink");

    fuse_reply_err(req, ENOTSUP);

    free_path_pathinfo(&call_info->pathinfo);

}


static void virt_mkdir (fuse_req_t req, struct inode_struct *pinode, struct name_struct *xname, struct call_info_struct *call_info, mode_t mode)
{

    logoutput("virt_mkdir");

	    /*
		only root can create a directory

		- test here for environment variables
		for the resource like:
		WORKSPACE_URI=...
	    */


    if (call_info->uid==0 && call_info->gid==0 ) {
	struct entry_struct *entry=NULL, *parent=pinode->alias;
	struct inode_struct *inode;
	unsigned int error=0;
	mode_t umask=call_info->umask;
	char *workspace_uri=NULL;

	/* here look for environment caller */

	check_environment_vars(call_info->pid, &workspace_uri);

	mode = (mode & 01777 & ~umask) | S_IFDIR;

	entry=create_entry(parent, xname);
	inode=create_inode();

	if (entry && inode) {
	    struct entry_struct *result=NULL;

	    entry->inode=inode;
	    inode->alias=entry;

	    result=insert_entry(entry, &error, 0);

	    if (result==entry) {
		struct fuse_entry_param e;

		logoutput("virt_mkdir: inserted %s, mode %i", xname->name, (int) mode);

		adjust_pathmax(call_info->pathinfo.len);
		add_inode_hashtable(inode, increase_inodes_workspace, (void *) call_info->workspace_mount);

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
		e.attr.st_mode = mode;
		e.attr.st_nlink = 2;
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

		if (workspace_uri) {

		    logoutput("virt_mkdir: create workspace uri %s", workspace_uri);

		    /*
			TODO:
			- test the uri it's valid
			- add creation of object
			- attach object to inode
			- create a resource
			- assign the module calls
		    */

		    error=0;

		    if (create_object(&workspace_uri, inode, call_info->workspace_mount, RESOURCE_GROUP_FILE, &error)==-1) {

			logoutput("virt_mkdir: error %i creating file object", error);

		    }

		    if (workspace_uri) {

			free(workspace_uri);
			workspace_uri=NULL;

		    }

		}

		free_path_pathinfo(&call_info->pathinfo);

		return;

	    } else {

		/* insert no success */

		destroy_entry(entry);
		entry=NULL;

		free(inode);
		inode=NULL;

		if (error==0) error=EEXIST;

		fuse_reply_err(req, error);

		free_path_pathinfo(&call_info->pathinfo);

		return;

	    }

	} else {

	    /* unable to allocate entry and/or inode*/

	    if (entry) {

		destroy_entry(entry);
		entry=NULL;

	    }

	    if (inode) {

		free(inode);
		inode=NULL;

	    }

	    fuse_reply_err(req, ENOMEM);

	    free_path_pathinfo(&call_info->pathinfo);

	    return;

	}

    } else {

	/* user is not root */

	fuse_reply_err(req, EACCES);

	free_path_pathinfo(&call_info->pathinfo);

    }

}

static void virt_unlink(fuse_req_t req, struct entry_struct *entry, struct call_info_struct *call_info)
{

    logoutput("virt_unlink");

    fuse_reply_err(req, ENOSYS);

    free_path_pathinfo(&call_info->pathinfo);

}

static void virt_rmdir(fuse_req_t req, struct entry_struct *entry, struct call_info_struct *call_info)
{

    logoutput("virt_rmdir");

    fuse_reply_err(req, ENOSYS);

    free_path_pathinfo(&call_info->pathinfo);

}

void virt_rename_cached(fuse_req_t req, struct entry_struct *entry, struct call_info_struct *call_info, struct entry_struct *entry_new, struct call_info_struct *call_info_new)
{

    logoutput("virt_rename");

    fuse_reply_err(req, ENOSYS);

    free_path_pathinfo(&call_info->pathinfo);
    free_path_pathinfo(&call_info_new->pathinfo);

}

void virt_rename_noncached(fuse_req_t req, struct entry_struct *entry, struct call_info_struct *call_info, struct inode_struct *pinode, struct name_struct *xname, struct call_info_struct *call_info_new)
{

    logoutput("virt_rename");

    fuse_reply_err(req, ENOSYS);

    free_path_pathinfo(&call_info->pathinfo);
    free_path_pathinfo(&call_info_new->pathinfo);

}


static void virt_opendir(fuse_req_t req, struct workspace_dh_struct *dh)
{

    logoutput("virt_opendir");

    dh->handle.data=NULL;

    fuse_reply_open(req, dh->fi);

}

static void virt_readdir(fuse_req_t req, size_t size, off_t offset, struct workspace_dh_struct *dh)
{

    logoutput("virt_readdir: size %i, offset %i", (int) size, (int) offset);

        char *buff=NULL, *name=NULL;
	size_t pos=0, entsize;
	struct stat st;
	unsigned int error=0;
	struct directory_struct *directory=dh->directory;

	buff=malloc(size);

	if (!buff) {

	    fuse_reply_err(req, ENOMEM);
	    return;

	}

	if (offset==0) {

	    /* start at first */

	    dh->handle.data=(void *) directory->first;

	}

	if (lock_directory(directory, _DIRECTORY_LOCK_READ)==-1) {

	    free(buff);
	    buff=NULL;
	    error=EAGAIN;
	    goto error;

	}

	while(1) {

	    if ( offset==0 ) {

    		/* the . entry */

		st.st_ino = dh->parent->inode->ino;
		st.st_mode = S_IFDIR;
		name = (char *) dotname;

	    } else if ( offset==1 ) {

    		/* the .. entry */

		if (dh->parent->parent) {

		    st.st_ino = dh->parent->parent->inode->ino;

		} else {

		    st.st_ino = dh->parent->inode->ino;

		}

		st.st_mode=S_IFDIR;
		name = (char *) dotdotname;

	    } else {

		if (dh->handle.data) {
		    struct entry_struct *entry=(struct entry_struct *) dh->handle.data;
		    struct inode_struct *inode=entry->inode;

		    if (inode) {

			st.st_ino=inode->ino;
			st.st_mode=inode->mode;
			name = entry->name.name;

		    } else {

			entry=entry->name_next;
			dh->handle.data=(void *) entry;
			continue;

		    }

		} else {

		    dh->mode |= _WORKSPACE_READDIR_MODE_FINISH;
		    break;

		}

	    }

	    entsize =  fuse_add_direntry(req, buff + pos, size - pos, name, &st, offset + 1);

	    if (pos + entsize > size) {

		dh->offset=offset+1;
		break;

	    }

	    offset++;
	    pos += entsize;

	}

	if (unlock_directory(directory, _DIRECTORY_LOCK_READ)==-1) {

	    logoutput("READDIR virtual: error unlocking directory READ");

	}

	fuse_reply_buf(req, buff, pos);
	free(buff);
	buff=NULL;

    error:

    fuse_reply_err(req, error);


}

static void virt_readdirplus(fuse_req_t req, size_t size, off_t offset, struct workspace_dh_struct *dh)
{
    unsigned int error=0;

    logoutput("virt_readdirplus: size %i, offset %i", (int) size, (int) offset);

	char *buff=NULL;
	size_t pos=0;
	size_t entsize;
	struct fuse_entry_param e;
	char *name=NULL;
	struct directory_struct *directory=dh->directory;

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

	if (offset==0) {

	    /* start at first */

	    dh->handle.data=(void *) directory->first;

	}

	while (pos<size) {

    	    if (offset==0) {
		struct inode_struct *inode=dh->parent->inode;

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
    		struct inode_struct *inode=NULL;

        	/* the .. entry */

		if (! dh->parent->parent) {

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

		if (dh->handle.data) {
		    struct entry_struct *entry=(struct entry_struct *) dh->handle.data;
		    struct inode_struct *inode=entry->inode;

		    if (inode) {

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

			entry=entry->name_next;
			dh->handle.data=(void *) entry;

		    } else {

			entry=entry->name_next;
			dh->handle.data=(void *) entry;
			continue;

		    }

		} else {

		    dh->mode |= _WORKSPACE_READDIR_MODE_FINISH;
		    break;

		}

	    }

	    logoutput("virt_readdirplus: add %s", name);

	    entsize =  fuse_add_direntry_plus(req, buff + pos, size - pos, name, &e, offset + 1);

	    if (pos + entsize > size) {

		dh->offset=offset+1;
		break;

	    }

	    offset++;
	    pos += entsize;

	}

	if (unlock_directory(directory, _DIRECTORY_LOCK_READ)==-1) {

	    logoutput("READDIR virtual: error unlocking directory READ");

	}

	fuse_reply_buf(req, buff, pos);

	free(buff);
	buff=NULL;

	return;

    error:

    fuse_reply_err(req, error);

}

static void virt_fsyncdir(fuse_req_t req, int datasync, struct workspace_dh_struct *dh)
{

    logoutput("virt_fsyncdir");
    fuse_reply_err(req, ENOSYS);

}

static void virt_closedir(fuse_req_t req, struct workspace_dh_struct *dh)
{


    fuse_reply_err(req, 0);
    logoutput("virt_closedir: ready");

}


static void virt_open(fuse_req_t req, struct workspace_fh_struct *fh)
{

    logoutput("virt_open");

    fuse_reply_err(req, ENOSYS);

    free_path_pathinfo(&fh->pathinfo);

}

static void virt_read(fuse_req_t req, size_t size, off_t off, struct workspace_fh_struct *fh)
{

    logoutput("virt_read");
    fuse_reply_err(req, ENOSYS);

}

static void virt_write(fuse_req_t req, const char *buff, size_t size, off_t off, struct workspace_fh_struct *fh)
{

    logoutput("virt_write");
    fuse_reply_err(req, ENOSYS);

}

static void virt_flush(fuse_req_t req, struct workspace_fh_struct *fh)
{

    logoutput("virt_flush");
    fuse_reply_err(req, ENOSYS);

}

static void virt_fsync(fuse_req_t req, int datasync, struct workspace_fh_struct *fh)
{

    logoutput("virt_fsync");
    fuse_reply_err(req, ENOSYS);

}

static void virt_release(fuse_req_t req, struct workspace_fh_struct *fh)
{

    logoutput("virt_release");
    fuse_reply_err(req, ENOSYS);

}

static void virt_create(fuse_req_t req, struct inode_struct *pinode, struct name_struct *xname, struct workspace_fh_struct *fh, mode_t mode)
{

    logoutput("virt_create");

    fuse_reply_err(req, ENOSYS);
    free_path_pathinfo(&fh->pathinfo);

}

static void virt_fgetattr(fuse_req_t req, struct workspace_fh_struct *fh)
{

    logoutput("virt_fgetattr");
    fuse_reply_err(req, ENOSYS);

}

static void virt_fsetattr(fuse_req_t req, struct workspace_fh_struct *fh, struct stat *st, int toset)
{

    logoutput("virt_fsetattr");
    fuse_reply_err(req, ENOSYS);

}

struct module_calls_struct virtual_module_calls={
	.groupid		= 0,
	.init			= virt_init,
	.destroy		= virt_destroy,
	.lookup_cached		= virt_lookup_cached,
	.lookup_noncached	= virt_lookup_noncached,
	.getattr		= virt_getattr,
	.setattr		= virt_setattr,
	.readlink		= virt_readlink,
	.mknod			= virt_mknod,
	.unlink			= virt_unlink,
	.rename_cached		= virt_rename_cached,
	.rename_noncached	= virt_rename_noncached,
	.open			= virt_open,
	.read			= virt_read,
	.write			= virt_write,
	.flush			= virt_flush,
	.fsync			= virt_fsync,
	.release		= virt_release,
	.create			= virt_create,
	.fgetattr		= virt_fgetattr,
	.fsetattr		= virt_fsetattr,
	.opendir		= virt_opendir,
	.readdir		= virt_readdir,
	.readdirplus    	= virt_readdirplus,
	.releasedir		= virt_closedir,
	.fsyncdir		= virt_fsyncdir,
};

void set_module_calls_virtual(struct module_calls_struct *mcalls)
{

	strcpy(mcalls->name, "virtual");

	mcalls->groupid		= 0;
	mcalls->init		= virt_init;
	mcalls->destroy		= virt_destroy;

	mcalls->lookup_cached	= virt_lookup_cached;
	mcalls->lookup_noncached= virt_lookup_noncached;
	mcalls->getattr		= virt_getattr;
	mcalls->setattr		= virt_setattr;
	mcalls->readlink	= virt_readlink;

	mcalls->mknod		= virt_mknod;
	mcalls->mkdir		= virt_mkdir;
	mcalls->symlink		= virt_symlink;
	mcalls->unlink		= virt_unlink;
	mcalls->rmdir		= virt_rmdir;

	mcalls->rename_cached	= virt_rename_cached;
	mcalls->rename_noncached= virt_rename_noncached;

	mcalls->open		= virt_open;
	mcalls->read		= virt_read;
	mcalls->write		= virt_write;
	mcalls->flush		= virt_flush;
	mcalls->fsync		= virt_fsync;
	mcalls->release		= virt_release;
	mcalls->create		= virt_create;

	mcalls->fgetattr	= virt_fgetattr;
	mcalls->fsetattr	= virt_fsetattr;

	mcalls->opendir		= virt_opendir;
	mcalls->readdir		= virt_readdir;
	mcalls->readdirplus	= virt_readdirplus;
	mcalls->releasedir	= virt_closedir;
	mcalls->fsyncdir	= virt_fsyncdir;
}
