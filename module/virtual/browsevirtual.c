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

#include "browsevirtual.h"

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

static unsigned int size_environment_file=1024;

static void read_workspace_uri_file(char *path, struct workspace_uri_struct *uri, unsigned int *error)
{
    FILE *fp=NULL;

    fp=fopen(path, "r");

    if (fp) {
	char *sep, *value;
	char line[256];
	unsigned int group=0;

	while(fgets(line, 256, fp)) {

	    sep=strchr(line, '=');
	    if (! sep) continue;

	    value=sep+1;
	    *sep='\0';

	    logoutput("read_workspace_uri_file: read option %s, value %s", line, value);

	    convert_to(value, UTILS_CONVERT_SKIPSPACE | UTILS_CONVERT_TOLOWER);

	    if (group==0) {

		if (strcmp(line, "service")==0) {

		    if (strcmp(value, "smb")==0) {

			group=RESOURCE_GROUP_SMB;

			uri->type.smbinfo.authmethod=WORKSPACE_AUTHMETHOD_DEFAULT;
			uri->type.smbinfo.authdata=NULL;
			uri->type.smbinfo.forceuser=WORKSPACE_FORCEUSER_DEFAULT;

		    } else if (strcmp(value, "nfs")==0) {

			group=RESOURCE_GROUP_NFS;

			uri->type.nfsinfo.forceuser=WORKSPACE_FORCEUSER_DEFAULT;

		    }

		}

		uri->group=group;

	    } else {

		if (group==RESOURCE_GROUP_SMB) {

		    if (strcmp(line, "forceuser")==0) {

			if (strcmp(value, "none")==0) {

			    uri->type.smbinfo.forceuser=WORKSPACE_FORCEUSER_NONE;

			} else if (strcmp(value, "owner")==0) {

			    uri->type.smbinfo.forceuser=WORKSPACE_FORCEUSER_OWNER;

			} else if (strcmp(value, "guest")==0) {

			    uri->type.smbinfo.forceuser=WORKSPACE_FORCEUSER_GUEST;

			}

		    } else if (strcmp(line, "authmethod")==0) {

			if (strcmp(value, "guest")==0) {

			    uri->type.smbinfo.authmethod=WORKSPACE_AUTHMETHOD_GUEST;

			} else if (strncmp(value, "password:", 9)==0) {
			    char *file=NULL;

			    file=value + 9;

			    if (strncmp(file, "file://", 7)==0) {
				struct stat st;

				file += 7;

				/* just check the file exist, no futher syntax checking for now */

				if (stat(file, &st)==0) {

				    uri->type.smbinfo.authmethod=WORKSPACE_AUTHMETHOD_PASSWORD;
				    uri->type.smbinfo.authdata=strdup(file);

				    if (! uri->type.smbinfo.authdata) {

					uri->type.smbinfo.authmethod=WORKSPACE_AUTHMETHOD_DEFAULT;

					logoutput("read_workspace_uri_file: error allocating memory for authdata (%s)", file);

				    }

				}

			    }

			} else if (strcmp(value, "kerberos")==0) {

			    uri->type.smbinfo.authmethod=WORKSPACE_AUTHMETHOD_KERBEROS;

			}

		    } else if (strcmp(line, "address")==0) {

			uri->address=strdup(value);

		    }

		} else if (group==RESOURCE_GROUP_NFS) {

		    if (strcmp(line, "forceuser")==0) {

			if (strcmp(value, "none")==0) {

			    uri->type.nfsinfo.forceuser=WORKSPACE_FORCEUSER_NONE;

			} else if (strcmp(value, "owner")==0) {

			    uri->type.nfsinfo.forceuser=WORKSPACE_FORCEUSER_OWNER;

			} else if (strcmp(value, "guest")==0) {

			    uri->type.nfsinfo.forceuser=WORKSPACE_FORCEUSER_GUEST;

			}

		    } else if (strcmp(line, "address")==0) {

			uri->address=strdup(value);

		    }

		}

	    }

	}

	fclose(fp);

    } else {

	*error=errno;

    }

}

int check_environment_vars(pid_t pid, struct workspace_uri_struct *uri, unsigned int *error)
{
    char path[32];
    int fd=0;
    int result=0;

    *error=0;

    logoutput("log_environment_var: pid %i", (int) pid);

    snprintf(path, 32, "/proc/%i/environ", (int) pid);

    fd=open(path, O_RDONLY);

    if (fd>0) {

	while(1) {
	    char buffer[size_environment_file];
	    int size_read=0;

	    size_read=pread(fd, buffer, size_environment_file, 0);

	    logoutput("log_environment_var: %i read for pid %i", size_read, (int) pid);

	    if (size_read>0 && size_read<size_environment_file) {
		char *sep=buffer;
		char *value=NULL;
		unsigned int len0=strlen("WORKSPACE_URI");
		unsigned int len1=strlen("WORKSPACE_URI_FILE");

		buffer[size_read]='\0';

		while(sep<buffer+size_read) {

		    if (strncmp(sep, "WORKSPACE_URI_FILE=", len1+1)==0) {

			value=sep + len1 + 1;

			logoutput("check_environment_vars: found %s, value %s", sep, value);

			/* here : call a function like:

			    object = create_object_advanced(value, &error)

			*/

			read_workspace_uri_file(value, uri, error);

			break;

		    } else if (strncmp(sep, "WORKSPACE_URI=", len0+1)==0) {

			value=sep + len0 + 1;

			logoutput("check_environment_vars: found %s, value %s", sep, value);

			if (strncmp(value, "file://", 7)==0) {
			    unsigned int len=strlen(value+6) + 1;

			    uri->address=malloc(len);

			    if (uri->address) {

				strcpy(uri->address, value+6);
				uri->group=RESOURCE_GROUP_FILE;

				*error=0;

			    } else {

				*error=ENOMEM;
				result=-1;

			    }

			} else if (strncmp(value, "nfs://", 6)==0) {
			    unsigned int len=strlen(value+6) + 1;

			    uri->address=malloc(len);

			    if (uri->address) {

				strcpy(uri->address, value+6);
				uri->group=RESOURCE_GROUP_NFS;
				uri->type.nfsinfo.forceuser=WORKSPACE_FORCEUSER_NONE;

				*error=0;

			    } else {

				*error=ENOMEM;
				result=-1;

			    }

			} else if (strncmp(value, "smb://", 6)==0) {
			    unsigned int len=strlen(value+6) + 1;

			    uri->address=malloc(len);

			    if (uri->address) {

				strcpy(uri->address, value+6);
				uri->group=RESOURCE_GROUP_SMB;
				uri->type.smbinfo.forceuser=WORKSPACE_FORCEUSER_DEFAULT;
				uri->type.smbinfo.authmethod=WORKSPACE_AUTHMETHOD_DEFAULT;

				*error=0;

			    } else {

				*error=ENOMEM;
				result=-1;

			    }

			} else {

			    *error=EINVAL;
			    result=-1;

			}

			/* var WORKSPACE_URI found: ready */

			break;

		    }

		    sep+=strlen(sep) + 1;

		}

		break;

	    } else if (size_read>=size_environment_file) {

		size_environment_file+=1024;

	    } else {

		*error=errno;

		break;

	    }

	}

	close(fd);

    } else {

	logoutput("log_environment_var: error %i opening path %s", errno, path);

	*error=errno;

    }

    return result;

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
    e.attr.st_size = inode->size;
    e.attr.st_atim.tv_sec = 0;
    e.attr.st_atim.tv_nsec = 0;
    e.attr.st_mtim.tv_sec = inode->mtim.tv_sec;
    e.attr.st_mtim.tv_nsec = inode->mtim.tv_nsec;
    e.attr.st_ctim.tv_sec = inode->ctim.tv_sec;
    e.attr.st_ctim.tv_nsec = inode->ctim.tv_nsec;

    e.attr.st_blksize=4096;

    if (inode->size % e.attr.st_blksize == 0) {

	e.attr.st_blocks=inode->size / e.attr.st_blksize;

    } else {

	e.attr.st_blocks=1 + inode->size / e.attr.st_blksize;

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

	st.st_blksize=4096;
	st.st_blocks=1;

	if (inode->size % st.st_blksize == 0) {

	    st.st_blocks = inode->size / st.st_blksize;

	} else {

	    st.st_blocks = 1 + inode->size / st.st_blksize;

	}

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
	struct workspace_object_struct *object=NULL;
	struct workspace_uri_struct uri;

	/* here look in environment of the caller */

	memset(&uri, 0, sizeof(struct workspace_uri_struct));

	uri.group=0;
	uri.address=NULL;

	check_environment_vars(call_info->pid, &uri, &error);

	if (error==0 && uri.address) {

	    object=create_object_simple(&uri, call_info->workspace_mount, &error);

	    free_workspace_uri(&uri);

	    if (! object) {

		if (error==0) error=EINVAL;

		fuse_reply_err(req, error);
		return;

	    }

	} else if (error>0) {

	    free_workspace_uri(&uri);

	    fuse_reply_err(req, error);
	    return;

	}

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
		inode->size=_INODE_DIRECTORY_SIZE;

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

		if (inode->size % e.attr.st_blksize == 0) {

		    e.attr.st_blocks=inode->size / e.attr.st_blksize;

		} else {

		    e.attr.st_blocks=1 + inode->size / e.attr.st_blksize;

		}

    		fuse_reply_entry(req, &e);

		if (object) {

		    object->inode=inode;
		    inode->object=object;

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
    char *buff=NULL, *name=NULL;
    size_t pos=0, entsize;
    struct stat st;
    unsigned int error=0;
    struct directory_struct *directory=dh->directory;

    logoutput("virt_readdir: size %i, offset %i", (int) size, (int) offset);

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

	    if (! dh->entry) {

		if (dh->handle.data) {
		    struct entry_struct *entry=(struct entry_struct *) dh->handle.data;
		    struct inode_struct *inode=entry->inode;

		    st.st_ino=inode->ino;
		    st.st_mode=inode->mode;
		    name = entry->name.name;

		    entry=entry->name_next;
		    dh->handle.data = (void *) entry;

		} else {

		    dh->mode |= _WORKSPACE_READDIR_MODE_FINISH;
		    break;

		}

	    } else {
		struct inode_struct *inode=dh->entry->inode;

		st.st_ino=inode->ino;
		st.st_mode=inode->mode;
		name = dh->entry->name.name;

	    }

	}

	entsize =  fuse_add_direntry(req, buff + pos, size - pos, name, &st, offset + 1);

	if (pos + entsize > size) {

	    dh->offset=offset+1;
	    break;

	}

	offset++;
	pos += entsize;
	dh->entry=NULL;

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

static void virt_readdirplus(fuse_req_t req, size_t size, off_t offset, struct workspace_dh_struct *dh)
{
    unsigned int error=0;
    char *buff=NULL;
    size_t pos=0;
    size_t entsize;
    struct fuse_entry_param e;
    char *name=NULL;
    struct directory_struct *directory=dh->directory;

    logoutput("virt_readdirplus: size %i, offset %i", (int) size, (int) offset);

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

    free_path_pathinfo(&fh->pathinfo);
    fh->fi->fh=0;

    fuse_reply_err(req, ENOSYS);

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

    free_path_pathinfo(&fh->pathinfo);
    fh->fi->fh=0;
    free(fh);

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

void set_module_calls_virtual(struct module_calls_struct *mcalls)
{

	strcpy(mcalls->name, "virtual");

	mcalls->groupid		= 0;
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
