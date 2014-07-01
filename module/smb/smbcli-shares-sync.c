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

/* specific samba4 includes */

#include <talloc.h>
#include <tevent.h>

#include <util/time.h>
#include <credentials.h>
#include <smb_cli.h>
#include <gensec.h>
#include <param.h>

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
#include "smbcli-common.h"
#include "smbcli-shares-sync.h"

extern const char *dotdotname;
extern const char *dotname;
extern char *smb_rootpath;

extern struct fs_options_struct fs_options;
extern struct smb_options_struct smb_options;

static int check_smbcli_share(struct net_smb_share_struct *smb_share, unsigned int *error)
{
    int result=0;
    struct smbcli_manager_struct *smbcli_manager=NULL;

    pthread_mutex_lock(&smb_share->mutex);

    smbcli_manager=(struct smbcli_manager_struct *) smb_share->context;

    if (! smbcli_manager) {

	if (create_smbcli_manager(smb_share, error)==0) {

	    smbcli_manager=(struct smbcli_manager_struct *) smb_share->context;

	    if (connect_smbcli_manager(smb_share, smbcli_manager, error)==-1) {

		logoutput("check_smbcli_share: connection error %i", *error);
		result=-1;

	    }

	} else {

	    result=-1;

	}

    } else if (! smbcli_manager->cli ) {

	/*
	    test there are previous connection errors
	    if there is an error, do not connect too fast after that
	*/

	if (smbcli_manager->error>0) {
	    struct timespec current_time;

    	    get_current_time(&current_time);

	    logoutput("check_smbcli_share: existing error %i found", smbcli_manager->error);

	    if (is_later(&current_time, &smbcli_manager->connect_time, smb_options.smbclient_retryperiod_onerror, 0)==0) {

		/* wait period after last connection error not expired */

		*error=smbcli_manager->error;
		result=-1;

		goto unlock;

	    }

	}

	if (connect_smbcli_manager(smb_share, smbcli_manager, error)==-1) {

	    logoutput("check_smbcli_share: connection error %i", *error);
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

static int smbcli_getstat_unix(struct smbcli_manager_struct *smbcli_manager, char *path, struct stat *st, unsigned int *error)
{
    union smb_fileinfo 	parms;
    TALLOC_CTX		*mem_ctx;
    int result=0;

    logoutput("smbcli_getstat_unix: path %s", path);

    mem_ctx = talloc_init("smbcli_getstat_unix");

    if (mem_ctx) {
	NTSTATUS status;

	parms.unix_basic_info.level=RAW_FILEINFO_UNIX_BASIC;
	parms.unix_basic_info.in.file.path=path;

	status = smb_raw_pathinfo(smbcli_manager->cli->tree, mem_ctx, &parms);

	talloc_free(mem_ctx);

	if (NT_STATUS_IS_OK(status)) {

	    if (strcmp(path, smb_rootpath)==0) {

		st->st_mode=S_IFDIR;

	    } else {

		/*
		    translate SMB filetype to UNIX mode
		*/

		st->st_mode=unix_filetype_from_wire(parms.unix_basic_info.out.file_type);

	    }

	    /*
		add UNIX permissions from SMB permissions
	    */

	    st->st_mode |= wire_perms_to_unix(parms.unix_basic_info.out.permissions);

	    /*
		size
	    */

	    st->st_size=(size_t) parms.unix_basic_info.out.end_of_file;

	    /*
		uid and gid
	    */

	    st->st_uid=(uid_t) parms.unix_basic_info.out.uid;
	    st->st_gid=(gid_t) parms.unix_basic_info.out.gid;

	    /*
		nlink
	    */

	    st->st_nlink = (nlink_t) parms.unix_basic_info.out.nlink;

	    /*
		times
	    */

	    st->st_atim = nt_time_to_unix_timespec(&parms.unix_basic_info.out.access_time);
	    st->st_mtim = nt_time_to_unix_timespec(&parms.unix_basic_info.out.change_time);
	    st->st_ctim = nt_time_to_unix_timespec(&parms.unix_basic_info.out.status_change_time);


	    /* ignore dev, unique_id etc */

	    st->st_ino=0;
	    st->st_dev=0;
	    st->st_rdev=0; /* good with special files ? */

	    *error=0;

	} else {

	    *error=EIO;
	    result=-1;

	}

    } else {

	*error=ENOMEM;
	result=-1;

    }

    return result;

}

static void workspace_smb_lookup_cached(fuse_req_t req, struct entry_struct *entry, struct call_info_struct *call_info)
{
    struct resource_struct *resource=call_info->object->resource;
    struct net_smb_share_struct *smb_share=(struct net_smb_share_struct *) resource->data;
    struct smbcli_manager_struct *smbcli_manager=NULL;
    char *path=call_info->pathinfo.path + call_info->relpath;
    struct stat st;
    int result=0;
    unsigned int error = 0;

    logoutput("workspace_smb_lookup_cached: smb share %s, path %s", smb_share->pathinfo.path, path);

    if (check_smbcli_share(smb_share, &error)==-1) {

	if (error==EIO && strlen(path)==0) {
	    struct fuse_entry_param e;
	    struct inode_struct *inode=entry->inode;

	    /*
		connection error: allow the rootpath
		set it to some sane defaults?
	    */

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

	} else {

	    fuse_reply_err(req, error);

	}

	free_path_pathinfo(&call_info->pathinfo);
	return;

    }

    smbcli_manager=(struct smbcli_manager_struct *) smb_share->context;

    pthread_mutex_lock(&smbcli_manager->mutex);

    memset(&st, 0, sizeof(struct stat));

    if (strlen(path)==0) {

	logoutput("workspace_smb_lookup_cached: converted path \\");

	smbcli_getstat_unix(smbcli_manager, smb_rootpath, &st, &error);

    } else {
	struct pathinfo_struct pathinfo={NULL, 0, 0};

	convert_path_smb(&pathinfo, path);

	logoutput("workspace_smb_lookup_cached: converted path %s", pathinfo.path);

	smbcli_getstat_unix(smbcli_manager, pathinfo.path, &st, &error);

	convert_path_smb_reverse(&pathinfo);

    }

    pthread_mutex_unlock(&smbcli_manager->mutex);

    if (error>0) {

	if (error==EIO && strlen(path)==0) {
	    struct fuse_entry_param e;
	    struct inode_struct *inode=entry->inode;

	    /*
		connection error: allow the rootpath
		set it to some sane defaults?
	    */

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

	} else {

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

	}

    } else {
	struct fuse_entry_param e;
	struct inode_struct *inode=entry->inode;
	struct net_smb_server_struct *smb_server=smb_share->server;

	(* smb_server->setuser_stat) (call_info->object->workspace_mount, smb_server, &st);

	inode->nlookup++;

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

    free_path_pathinfo(&call_info->pathinfo);

}

static void workspace_smb_lookup_noncached(fuse_req_t req, struct inode_struct *pinode, struct name_struct *xname, struct call_info_struct *call_info)
{
    struct resource_struct *resource=call_info->object->resource;
    struct net_smb_share_struct *smb_share=(struct net_smb_share_struct *) resource->data;
    struct smbcli_manager_struct *smbcli_manager=NULL;
    char *path=call_info->pathinfo.path + call_info->relpath;
    struct stat st;
    unsigned int error=0;

    logoutput("workspace_smb_lookup_noncached: smb share %s, path %s", smb_share->pathinfo.path, path);

    if (check_smbcli_share(smb_share, &error)==-1) {

	fuse_reply_err(req, error);
	free_path_pathinfo(&call_info->pathinfo);
	return;

    }

    smbcli_manager=(struct smbcli_manager_struct *) smb_share->context;

    memset(&st, 0, sizeof(struct stat));

    pthread_mutex_lock(&smbcli_manager->mutex);

    if (strlen(path)==0) {

	logoutput("workspace_smb_lookup_cached: converted path \\");

	smbcli_getstat_unix(smbcli_manager, smb_rootpath, &st, &error);

    } else {
	struct pathinfo_struct pathinfo={NULL, 0, 0};

	convert_path_smb(&pathinfo, path);

	logoutput("workspace_smb_lookup_cached: converted path %s", pathinfo.path);

	smbcli_getstat_unix(smbcli_manager, pathinfo.path, &st, &error);

	convert_path_smb_reverse(&pathinfo);

    }

    pthread_mutex_unlock(&smbcli_manager->mutex);

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

	    inode->alias=entry;
	    entry->inode=inode;

	    add_inode_hashtable(inode, increase_inodes_workspace, (void *) call_info->workspace_mount);
	    insert_entry(entry, &error, 0);

	    adjust_pathmax(call_info->pathinfo.len);

	    inode->nlookup++;

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

}

static void workspace_smb_getattr(fuse_req_t req, struct entry_struct *entry, struct call_info_struct *call_info)
{
    struct resource_struct *resource=call_info->object->resource;
    struct net_smb_share_struct *smb_share=(struct net_smb_share_struct *) resource->data;
    struct smbcli_manager_struct *smbcli_manager=NULL;
    char *path=call_info->pathinfo.path + call_info->relpath;
    struct stat st;
    unsigned int error=0;

    logoutput("workspace_smb_getattr: smb share %s", smb_share->pathinfo.path);

    if (check_smbcli_share(smb_share, &error)==-1) {

	if (error==EIO && strlen(path)==0) {
	    struct inode_struct *inode=entry->inode;

	    /*
		connection error: allow the rootpath
		set it to some sane defaults?
	    */

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

	} else {

	    fuse_reply_err(req, error);

	}

	free_path_pathinfo(&call_info->pathinfo);
	return;

    }

    smbcli_manager=(struct smbcli_manager_struct *) smb_share->context;

    memset(&st, 0, sizeof(struct stat));

    pthread_mutex_lock(&smbcli_manager->mutex);

    if (strlen(path)==0) {

	logoutput("workspace_smb_lookup_cached: converted path \\");

	smbcli_getstat_unix(smbcli_manager, smb_rootpath, &st, &error);

    } else {
	struct pathinfo_struct pathinfo={NULL, 0, 0};

	convert_path_smb(&pathinfo, path);

	logoutput("workspace_smb_lookup_cached: converted path %s", pathinfo.path);

	smbcli_getstat_unix(smbcli_manager, pathinfo.path, &st, &error);

	convert_path_smb_reverse(&pathinfo);

    }

    pthread_mutex_unlock(&smbcli_manager->mutex);

    if (error>0) {

	if (error==EIO && strlen(path)==0) {
	    struct inode_struct *inode=entry->inode;

	    /*
		connection error: allow the rootpath
		set it to some sane defaults?
	    */

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

	} else {

	    fuse_reply_err(req, error);

	}

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

    free_path_pathinfo(&call_info->pathinfo);

}

void smbcli_list_cb(struct clilist_file_info *clilist_fi, const char *path, void *data)
{
    struct workspace_dh_struct *dh=(struct workspace_dh_struct *) data;
    struct entry_struct *parent=NULL, *entry=NULL, *result=NULL;
    struct name_struct xname={NULL, 0, 0};
    struct inode_struct *inode=NULL;
    struct directory_struct *directory=dh->directory;
    unsigned int error=0;

    parent=dh->parent;

    xname.name=clilist_fi->name;

    if (strcmp(xname.name, ".")==0 || strcmp(xname.name, "..")==0) return;

    xname.len=strlen(xname.name);
    calculate_nameindex(&xname);

    entry=find_entry_batch(directory, &xname, &error);

    if ( ! entry) {

	/* name not found: create new entry */

	error=0;

	entry=create_entry(dh->parent, &xname);
	inode=create_inode();

	if (entry && inode) {

	    result=insert_entry_batch(directory, entry, &error, 0);

	    if (result==entry) {

		inode->mode = DTTOIF(DT_UNKNOWN);
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

		    /* some error */

		    destroy_entry(entry);
		    free(inode);

		    if (error==0) error=EIO;

		    logoutput("smbcli_list_cb: error %i:%s for %s", error, strerror(error), xname.name);

		}

	    }

	} else {

	    /* error allocating entry and/or inode */

	    if (entry) {

		destroy_entry(entry);
		entry=NULL;

	    }

	    if (inode) {

		free(inode);
		inode=NULL;

	    }

	    error=ENOMEM;

	    logoutput("smbcli_list_cb: error allocating entry and/or inode for %s", xname.name);

	}

    }

}

int smbcli_list_sync(struct smbcli_manager_struct *smbcli_manager, struct workspace_dh_struct *dh, char *path)
{

    return smbcli_list(smbcli_manager->cli->tree, path, SAMBA_ATTRIBUTES_MASK, smbcli_list_cb, (void *) dh);

}

static void workspace_smb_opendir(fuse_req_t req, struct workspace_dh_struct *dh)
{
    struct resource_struct *resource=dh->object->resource;
    struct net_smb_share_struct *smb_share=(struct net_smb_share_struct *) resource->data;
    struct smbcli_manager_struct *smbcli_manager=NULL;
    char *path=dh->pathinfo.path + dh->relpath;
    struct directory_struct *directory=dh->directory;
    unsigned int error=0;

    logoutput("workspace_smb_opendir: smb share %s", smb_share->pathinfo.path);

    if (check_smbcli_share(smb_share, &error)==-1) {

	fuse_reply_err(req, error);
	return;

    }

    smbcli_manager=(struct smbcli_manager_struct *) smb_share->context;

    /*
	should the following go to the fsyncdir function?
    */

    if (lock_directory(directory, _DIRECTORY_LOCK_EXCL)==-1) {

	fuse_reply_err(req, EAGAIN);
	return;

    }

    pthread_mutex_lock(&smbcli_manager->mutex);

    if (strlen(path)==0) {

	smbcli_list_sync(smbcli_manager, dh, "\\");

    } else {
	struct pathinfo_struct pathinfo={NULL, 0, 0};

	convert_path_smb(&pathinfo, path);

	smbcli_list_sync(smbcli_manager, dh, pathinfo.path);

	convert_path_smb_reverse(&pathinfo);

    }

    pthread_mutex_unlock(&smbcli_manager->mutex);

    unlock_directory(directory, _DIRECTORY_LOCK_EXCL);

    fuse_reply_open(req, dh->fi);


}



int set_module_calls_smbcli_shares_sync(struct module_calls_struct *mcalls)
{

    strcpy(mcalls->name, "smbcli-shares-sync");

    mcalls->groupid		= 0;

    mcalls->destroy		= workspace_smb_destroy;

    mcalls->lookup_cached	= workspace_smb_lookup_cached;
    mcalls->lookup_noncached	= workspace_smb_lookup_noncached;
    mcalls->getattr		= workspace_smb_getattr;

    mcalls->opendir		= workspace_smb_opendir;

    return 0;

}
