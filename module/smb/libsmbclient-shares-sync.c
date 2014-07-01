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

#include <libsmbclient.h>

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

#include "workspaces.h"
#include "resources.h"
#include "objects.h"

#include "smb-common.h"
#include "libsmbclient-common.h"
#include "libsmbclient-shares-sync.h"

extern const char *dotdotname;
extern const char *dotname;

extern struct fs_options_struct fs_options;
extern struct smb_options_struct smb_options;

static int check_smbcontext_share(struct net_smb_share_struct *smb_share, unsigned int *error)
{
    struct smbclient_manager_struct *smbclient_manager=NULL;
    int result=0;

    pthread_mutex_lock(&smb_share->mutex);

    smbclient_manager=(struct smbclient_manager_struct *) smb_share->context;

    if (! smbclient_manager) {

	smbclient_manager=create_smbclient_manager();

	if (smbclient_manager) {

	    smbclient_manager->smb_share=smb_share;

	    if (create_smbclient_context(smbclient_manager, error)==0) {

		smb_share->context=(void *) smbclient_manager;
		goto unlock;

	    } else {

		result=-1;
		goto unlock;

	    }

	} else {

	    *error=EIO;
	    result=-1;
	    goto unlock;

	}

    }

    if (! smbclient_manager->context) {

	if (create_smbclient_context(smbclient_manager, error)==-1) {

	    result=-1;

	}

    }

    unlock:

    pthread_mutex_unlock(&smb_share->mutex);

    return result;

}


static void workspace_smb_destroy(struct workspace_object_struct *object)
{
    logoutput("smb_destroy: destroy overlay browsing");
}

static void workspace_smb_lookup_cached(fuse_req_t req, struct entry_struct *entry, struct call_info_struct *call_info)
{
    struct resource_struct *resource=call_info->object->resource;
    struct net_smb_share_struct *smb_share=(struct net_smb_share_struct *) resource->data;
    struct smbclient_manager_struct *smbclient_manager=NULL;
    char *path=call_info->pathinfo.path + call_info->relpath;
    struct pathinfo_struct pathinfo={NULL, 0, 0};
    struct stat st;
    int result=0;
    SMBCCTX *smbcontext = NULL;
    unsigned int error = 0;

    logoutput("workspace_smb_lookup_cached: smb share %s, path %s", smb_share->pathinfo.path, path);

    if (check_smbcontext_share(smb_share, &error)==-1) {

	fuse_reply_err(req, error);
	free_path_pathinfo(&call_info->pathinfo);
	return;

    }

    smbclient_manager=(struct smbclient_manager_struct *) smb_share->context;
    smbcontext = smbclient_manager->context;

    memset(&st, 0, sizeof(struct stat));

    pthread_mutex_lock(&smbclient_manager->mutex);

    if (construct_decoded_smb_path(smb_share, path, strlen(path), &pathinfo, &error)==0) {

	logoutput("workspace_smb_lookup_cached, path %s", pathinfo.path);

	if (smbc_getFunctionStat(smbcontext)(smbcontext, pathinfo.path, &st)<0) {

	    error=errno;

	}

    }

    pthread_mutex_unlock(&smbclient_manager->mutex);

    if (error>0) {

	if (error==ENOENT) {
	    struct inode_struct *inode=entry->inode;
	    unsigned int error=0;

	    inode=entry->inode;
	    inode->alias=NULL;

	    remove_entry(entry, &error);
	    queue_remove(call_info->object, entry, &error);
	    entry=NULL;

	}

	fuse_reply_err(req, error);

    } else {
	struct fuse_entry_param e;
	struct inode_struct *inode=entry->inode;
	struct net_smb_server_struct *smb_server=smb_share->server;

	(* smb_server->setuser_stat) (call_info->object->workspace_mount, smb_server, &st);

	inode->mode=st.st_mode;
	inode->nlink=st.st_nlink;
	inode->uid=st.st_uid;
	inode->gid=st.st_gid;

	inode->mtim.tv_sec=st.st_mtim.tv_sec;
	inode->mtim.tv_nsec=st.st_mtim.tv_nsec;

	inode->ctim.tv_sec=st.st_ctim.tv_sec;
	inode->ctim.tv_nsec=st.st_ctim.tv_nsec;

	inode->rdev=st.st_rdev;
	inode->size=st.st_size;

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

	if (inode->size % e.attr.st_blksize == 0) {

	    e.attr.st_blocks=inode->size / e.attr.st_blksize;

	} else {

	    e.attr.st_blocks=1 + inode->size / e.attr.st_blksize;

	}

	e.attr.st_size = st.st_size;

	fuse_reply_entry(req, &e);

    }

    free_path_pathinfo(&pathinfo);
    free_path_pathinfo(&call_info->pathinfo);

}

static void workspace_smb_lookup_noncached(fuse_req_t req, struct inode_struct *pinode, struct name_struct *xname, struct call_info_struct *call_info)
{
    struct resource_struct *resource=call_info->object->resource;
    struct net_smb_share_struct *smb_share=(struct net_smb_share_struct *) resource->data;
    struct smbclient_manager_struct *smbclient_manager=NULL;
    char *path=call_info->pathinfo.path + call_info->relpath;
    struct pathinfo_struct pathinfo={NULL, 0, 0};
    struct stat st;
    SMBCCTX *smbcontext = NULL;
    unsigned int error=0;

    logoutput("workspace_smb_lookup_noncached: smb share %s, path %s", smb_share->pathinfo.path, path);

    if (check_smbcontext_share(smb_share, &error)==-1) {

	fuse_reply_err(req, error);
	free_path_pathinfo(&call_info->pathinfo);
	return;

    }

    logoutput("workspace_smb_lookup_noncached, B");

    smbclient_manager=(struct smbclient_manager_struct *) smb_share->context;
    smbcontext = smbclient_manager->context;

    memset(&st, 0, sizeof(struct stat));

    pthread_mutex_lock(&smbclient_manager->mutex);

    if (construct_decoded_smb_path(smb_share, path, strlen(path), &pathinfo, &error)==0) {

	logoutput("workspace_smb_lookup_noncached, path %s", pathinfo.path);

	if (smbc_getFunctionStat(smbcontext)(smbcontext, pathinfo.path, &st)<0) {

	    error=errno;

	}

    }

    pthread_mutex_unlock(&smbclient_manager->mutex);

    if (error>0) {

	fuse_reply_err(req, errno);

    } else {
	struct entry_struct *entry=NULL, *parent=pinode->alias;
	struct inode_struct *inode;

	entry=create_entry(parent, xname);
	inode=create_inode();

	if (entry && inode) {
	    struct fuse_entry_param e;
	    unsigned int error=0;
	    struct net_smb_server_struct *smb_server=smb_share->server;

	    (* smb_server->setuser_stat) (call_info->object->workspace_mount, smb_server, &st);

	    add_inode_hashtable(inode, increase_inodes_workspace, (void *) call_info->workspace_mount);
	    insert_entry(entry, &error, 0);

	    adjust_pathmax(call_info->pathinfo.len);

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

	    e.attr.st_blksize=4096;

	    if (inode->size % e.attr.st_blksize == 0) {

		e.attr.st_blocks=inode->size / e.attr.st_blksize;

	    } else {

		e.attr.st_blocks=1 + inode->size / e.attr.st_blksize;

	    }

	    e.attr.st_size = st.st_size;

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
    free_path_pathinfo(&pathinfo);

}

static void workspace_smb_getattr(fuse_req_t req, struct entry_struct *entry, struct call_info_struct *call_info)
{
    struct resource_struct *resource=call_info->object->resource;
    struct net_smb_share_struct *smb_share=(struct net_smb_share_struct *) resource->data;
    struct smbclient_manager_struct *smbclient_manager=NULL;
    char *path=call_info->pathinfo.path + call_info->relpath;
    struct pathinfo_struct pathinfo={NULL, 0, 0};
    struct stat st;
    SMBCCTX *smbcontext = NULL;
    unsigned int error=0;

    logoutput("workspace_smb_getattr: smb share %s", smb_share->pathinfo.path);

    if (check_smbcontext_share(smb_share, &error)==-1) {

	fuse_reply_err(req, error);
	free_path_pathinfo(&call_info->pathinfo);
	return;

    }

    smbclient_manager=(struct smbclient_manager_struct *) smb_share->context;
    smbcontext = smbclient_manager->context;

    memset(&st, 0, sizeof(struct stat));

    pthread_mutex_lock(&smbclient_manager->mutex);

    if (construct_decoded_smb_path(smb_share, path, strlen(path), &pathinfo, &error)==0) {

	logoutput("workspace_smb_getattr, path %s", pathinfo.path);

	if (smbc_getFunctionStat(smbcontext)(smbcontext, pathinfo.path, &st)<0) {

	    error=errno;

	}

    }

    pthread_mutex_unlock(&smbclient_manager->mutex);

    if (error>0) {

	fuse_reply_err(req, error);

    } else {
	struct inode_struct *inode=entry->inode;
	struct net_smb_server_struct *smb_server=smb_share->server;

	(* smb_server->setuser_stat) (call_info->object->workspace_mount, smb_server, &st);

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

	st.st_ino=inode->ino;
	st.st_dev=0;

	st.st_blksize=4096;

	if (inode->size % st.st_blksize == 0) {

	    st.st_blocks=inode->size / st.st_blksize;

	} else {

	    st.st_blocks=1 + inode->size / st.st_blksize;

	}

	fuse_reply_attr(req, &st, fs_options.attr_timeout);

    }

    free_path_pathinfo(&pathinfo);
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

static mode_t translate_libsmbclient_type(unsigned int type)
{
    mode_t mode=0;

    if (type==SMBC_FILE) {

	mode=S_IFREG;

    } else if (type==SMBC_DIR) {

	mode=S_IFDIR;

    } else if (type==SMBC_LINK) {

	mode=S_IFLNK;

    }

    return mode;

}

struct workspace_smbc_dh {
    struct pathinfo_struct 	pathinfo;
    SMBCFILE			*handle;
    off_t			offset;
};

static void workspace_smb_opendir(fuse_req_t req, struct workspace_dh_struct *dh)
{
    struct resource_struct *resource=dh->object->resource;
    struct net_smb_share_struct *smb_share=(struct net_smb_share_struct *) resource->data;
    struct smbclient_manager_struct *smbclient_manager=NULL;
    char *path=dh->pathinfo.path + dh->relpath;
    struct workspace_smbc_dh *smbc_dh=NULL;
    unsigned int error=0;

    logoutput("workspace_smb_opendir: smb share %s", smb_share->pathinfo.path);

    if (check_smbcontext_share(smb_share, &error)==-1) {

	fuse_reply_err(req, error);
	free_path_pathinfo(&dh->pathinfo);
	return;

    }

    smbclient_manager=(struct smbclient_manager_struct *) smb_share->context;
    smbc_dh=malloc(sizeof(struct workspace_smbc_dh));

    if (smbc_dh) {

	smbc_dh->pathinfo.path=NULL;
	smbc_dh->pathinfo.len=0;
	smbc_dh->pathinfo.flags=0;
	smbc_dh->handle=NULL;
	smbc_dh->offset=0;

	if (construct_decoded_smb_path(smb_share, path, strlen(path), &smbc_dh->pathinfo, &error)==0) {

	    logoutput("workspace_smb_opendir, path %s", smbc_dh->pathinfo.path);

	}

    } else {

	error=ENOMEM;

    }

    if (error==0) {

	dh->handle.data = (void *) smbc_dh;

        fuse_reply_open(req, dh->fi);
	return;

    }

    /* some error */

    logoutput("workspace_opendir, error %i:%s", error, strerror(error));

    if (smbc_dh) {

	free_path_pathinfo(&smbc_dh->pathinfo);
	free(smbc_dh);

    }

    fuse_reply_err(req, error);

}

static void workspace_smb_readdir_full(fuse_req_t req, size_t size, off_t offset, struct workspace_dh_struct *dh, SMBCCTX *smbcontext)
{
    unsigned int error=0;
    char *buff=NULL;
    size_t pos=0;
    size_t dirent_size;
    char *name=NULL;
    struct directory_struct *directory=dh->directory;
    struct entry_struct *entry, *result;
    struct inode_struct *inode;
    struct name_struct xname={NULL, 0, 0};
    struct stat st;
    struct workspace_smbc_dh *smbc_dh=(struct workspace_smbc_dh *) dh->handle.data;
    struct smbc_dirent *de=NULL;

    memset(&st, 0, sizeof(struct stat));

    buff=malloc(size);

    if (! buff) {

	error=ENOMEM;
	fuse_reply_err(req, error);

    }

    memset(buff, '\0', size);

    while (pos<size) {

	if (! dh->entry) {

	    readdir:

	    de=smbc_getFunctionReaddir(smbcontext) (smbcontext, smbc_dh->handle);

	    if (de) {

		if (strcmp(de->name, ".")==0) {

		    inode=dh->parent->inode;

    		    /* the . entry */

    		    st.st_ino = inode->ino;
		    st.st_mode = S_IFDIR;
		    name = de->name;

    		} else if (strcmp(de->name, "..")==0) {

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
		    name = de->name;

    		} else {

		    if (de->smbc_type==SMBC_FILE || de->smbc_type==SMBC_DIR || de->smbc_type==SMBC_LINK) {

			xname.name=de->name;

			logoutput("smb_readdir_full: name %s", xname.name);

		    } else {

			logoutput("smb_readdir_full: found name %s, skip (type=%i)", de->name, de->smbc_type);
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

			    inode->mode = translate_libsmbclient_type(de->smbc_type);
			    memcpy(&entry->synctime, &dh->synctime, sizeof(struct timespec));

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

				error=0;

			    } else {

				free(buff);
				destroy_entry(entry);
				free(inode);

				if (error==0) error=EIO;

				break;

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

			break;

		    }

		    dh->entry=entry;

		}

	    } else {

		/* no direntry read anymore */

		dh->mode |= _WORKSPACE_READDIR_MODE_FINISH;
		break;

	    }

	} else {

	    st.st_ino=dh->entry->inode->ino;
	    st.st_mode=dh->entry->inode->mode;
	    name=dh->entry->name.name;

	}

    	dirent_size=fuse_add_direntry(req, buff+pos, size-pos, name, &st, offset+1);

	if (pos + dirent_size > size) {

	    dh->offset = offset + 1;
	    smbc_dh->offset = smbc_getFunctionTelldir(smbcontext) (smbcontext, smbc_dh->handle);
	    break;

	}

	/* increase counter and clear the various fields */

	dh->entry=NULL; /* forget current entry to force readdir */
	offset++;
	pos += dirent_size;

    }

    if (error==0) {

	fuse_reply_buf(req, buff, pos);

    } else {

	fuse_reply_err(req, error);

    }

    free(buff);
    buff=NULL;

}

static void workspace_smb_readdir_simple(fuse_req_t req, size_t size, off_t offset, struct workspace_dh_struct *dh, SMBCCTX *smbcontext)
{
    unsigned int error=0;
    char *buff=NULL;
    size_t pos=0;
    size_t dirent_size;
    char *name=NULL;
    struct directory_struct *directory=dh->directory;
    struct entry_struct *entry, *result;
    struct inode_struct *inode;
    struct name_struct xname={NULL, 0, 0};
    struct stat st;
    struct workspace_smbc_dh *smbc_dh=(struct workspace_smbc_dh *) dh->handle.data;
    struct smbc_dirent *de=NULL;

    memset(&st, 0, sizeof(struct stat));

    buff=malloc(size);

    if (! buff) {

	error=ENOMEM;
	fuse_reply_err(req, error);

    }

    memset(buff, '\0', size);

    while (pos<size) {

	if (! dh->entry) {

	    readdir:

	    de=smbc_getFunctionReaddir(smbcontext) (smbcontext, smbc_dh->handle);

	    if (de) {

		if (strcmp(de->name, ".")==0) {

		    inode=dh->parent->inode;

    		    /* the . entry */

    		    st.st_ino = inode->ino;
		    st.st_mode = S_IFDIR;
		    name = de->name;

    		} else if (strcmp(de->name, "..")==0) {

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
		    name = de->name;

    		} else {

		    if (de->smbc_type==SMBC_FILE || de->smbc_type==SMBC_DIR || de->smbc_type==SMBC_LINK) {

			xname.name=de->name;

			logoutput("smb_readdir_simple: name %s", xname.name);

		    } else {

			logoutput("smb_readdir_simple: found name %s, skip (type=%i)", de->name, de->smbc_type);
			goto readdir;

		    }

		    xname.len=strlen(xname.name);
		    calculate_nameindex(&xname);

		    error=0;

		    entry=find_entry_batch(directory, &xname, &error);

		    if ( ! entry) {

			/* name not found: create new entry */

			error=0;

			entry=create_entry(dh->parent, &xname);
			inode=create_inode();

			if (entry && inode) {

			    result=insert_entry_batch(directory, entry, &error, 0);

			    if (result==entry) {

				inode->mode = translate_libsmbclient_type(de->smbc_type);
				memcpy(&entry->synctime, &dh->synctime, sizeof(struct timespec));

				add_inode_hashtable(inode, increase_inodes_workspace, (void *) dh->object->workspace_mount);

				inode->alias=entry;
				entry->inode=inode;

				adjust_pathmax(dh->pathinfo.len + 1 + xname.len);

			    } else {

				if (error==EEXIST) {

				    /* should not happen since already checked for name earlier */

				    destroy_entry(entry);
				    entry=result;

				    memcpy(&entry->synctime, &dh->synctime, sizeof(struct timespec));

				    free(inode);
				    inode=entry->inode;

				    error=0;

				} else {

				    free(buff);
				    destroy_entry(entry);
				    free(inode);

				    if (error==0) error=EIO;

				    break;

				}

			    }

			    st.st_mode=entry->inode->mode;
			    st.st_ino=entry->inode->ino;
			    name=entry->name.name;

			} else {

			    /* inode and/or entry not allocated */

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

			    break;

			}

			dh->entry=entry;

		    } else {

			error=0;

			st.st_ino=entry->inode->ino;
			st.st_mode=entry->inode->mode;
			name=entry->name.name;
			memcpy(&entry->synctime, &dh->synctime, sizeof(struct timespec));

		    }

		}

	    } else {

		/* no direntry read anymore */

		dh->mode |= _WORKSPACE_READDIR_MODE_FINISH;
		break;

	    }

	} else {

	    st.st_ino=dh->entry->inode->ino;
	    st.st_mode=dh->entry->inode->mode;
	    name=dh->entry->name.name;

	}

    	dirent_size=fuse_add_direntry(req, buff+pos, size-pos, name, &st, offset+1);

	if (pos + dirent_size > size) {

	    dh->offset = offset + 1;
	    smbc_dh->offset = smbc_getFunctionTelldir(smbcontext) (smbcontext, smbc_dh->handle);
	    break;

	}

	/* increase counter and clear the various fields */

	dh->entry=NULL; /* forget current entry to force readdir */
	offset++;
	pos += dirent_size;

    }

    if (error==0) {

	fuse_reply_buf(req, buff, pos);

    } else {

	fuse_reply_err(req, error);

    }

    free(buff);
    buff=NULL;

}

static void workspace_smb_readdir(fuse_req_t req, size_t size, off_t offset, struct workspace_dh_struct *dh)
{
    struct resource_struct *resource=dh->object->resource;
    struct net_smb_share_struct *smb_share=(struct net_smb_share_struct *) resource->data;
    struct smbclient_manager_struct *smbclient_manager=(struct smbclient_manager_struct *) smb_share->context;
    SMBCCTX *smbcontext = (SMBCCTX *) smbclient_manager->context;
    struct directory_struct *directory=dh->directory;
    struct workspace_smbc_dh *smbc_dh=(struct workspace_smbc_dh *) dh->handle.data;
    unsigned int error=0;

    if (lock_directory(directory, _DIRECTORY_LOCK_EXCL)==-1) {

	fuse_reply_err(req, EAGAIN);
	return;

    }

    pthread_mutex_lock(&smbclient_manager->mutex);

    smbc_dh->handle = smbc_getFunctionOpendir(smbcontext) (smbcontext, smbc_dh->pathinfo.path);

    if (smbc_dh->handle) {

	smbc_getFunctionLseekdir(smbcontext) (smbcontext, smbc_dh->handle, smbc_dh->offset);

	if (dh->mode & _WORKSPACE_READDIR_MODE_NONEMPTY) {

	    /* there are already entries cached */

	    workspace_smb_readdir_simple(req, size, offset, dh, smbcontext);

	} else {

	    /* no entries cached */

	    workspace_smb_readdir_full(req, size, offset, dh, smbcontext);

	}

	smbc_getFunctionClosedir(smbcontext)(smbcontext, smbc_dh->handle);
	smbc_dh->handle=NULL;

    } else {

	error=errno;

	fuse_reply_err(req, errno);

    }


    pthread_mutex_unlock(&smbclient_manager->mutex);

    unlock_directory(directory, _DIRECTORY_LOCK_EXCL);

}

static void workspace_smb_readdirplus(fuse_req_t req, size_t size, off_t offset, struct workspace_dh_struct *dh)
{

    fuse_reply_err(req, ENOSYS);

}

static void workspace_smb_releasedir(fuse_req_t req, struct workspace_dh_struct *dh)
{
    struct resource_struct *resource=dh->object->resource;
    struct net_smb_share_struct *smb_share=(struct net_smb_share_struct *) resource->data;
    struct smbclient_manager_struct *smbclient_manager=(struct smbclient_manager_struct *) smb_share->context;
    struct directory_struct *directory=NULL;

    logoutput("workspace_smb_releasedir");

    directory=dh->directory;

    if (dh->handle.data) {
	struct workspace_smbc_dh *smbc_dh=(struct workspace_smbc_dh *) dh->handle.data;

	free_path_pathinfo(&smbc_dh->pathinfo);
	free(smbc_dh);

    }

    fuse_reply_err(req, 0);

    if (directory) {

	/* when synced with backend and there were entries at start test these are not synced */

	if (dh->mode & _WORKSPACE_READDIR_MODE_NONEMPTY) remove_old_entries(dh->object, directory, &dh->synctime);
	memcpy(&directory->synctime, &dh->synctime, sizeof(struct timespec));

    }

}

int set_module_calls_libsmbclient_shares(struct module_calls_struct *mcalls)
{

    strcpy(mcalls->name, "libsmbclient-shares-sync");

    mcalls->groupid		= 0;

    mcalls->destroy		= workspace_smb_destroy;

    mcalls->lookup_cached	= workspace_smb_lookup_cached;
    mcalls->lookup_noncached	= workspace_smb_lookup_noncached;
    mcalls->getattr		= workspace_smb_getattr;

    mcalls->opendir		= workspace_smb_opendir;
    mcalls->readdir		= workspace_smb_readdir;
    mcalls->readdirplus		= workspace_smb_readdirplus;
    mcalls->releasedir		= workspace_smb_releasedir;

    return 0;

}
