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
#include "libsmbclient-servers.h"

#include "libsmbclient-shares-sync.h"
#include "smbcli-shares-sync.h"

extern struct fs_options_struct fs_options;
extern struct smb_options_struct smb_options;
extern const char *rootpath;
extern const char *dotdotname;
extern const char *dotname;

static struct smbclient_manager_struct smbclient_manager_network;
static unsigned char manager_initialized=0;

static void workspace_smb_destroy(struct workspace_object_struct *object)
{
    logoutput("smb_destroy: destroy overlay browsing");
}

static void remove_old_entries(struct workspace_object_struct *object, struct directory_struct *directory, struct timespec *synctime)
{
    struct entry_struct *entry;

    logoutput("remove_old_entries: synctime %li:%li", synctime->tv_sec, synctime->tv_nsec);

    /* TODO: add locking */

    entry=(struct entry_struct *) directory->first;

    while (entry) {

	if (! entry->inode || entry->inode->mode==0) {

	    entry=entry->name_next;
	    continue;

	}

	if (entry->synctime.tv_sec<synctime->tv_sec || 
	    (entry->synctime.tv_sec==synctime->tv_sec && entry->synctime.tv_nsec<synctime->tv_nsec)) {
	    struct entry_struct *next=entry->name_next;
	    unsigned int error=0;

	    logoutput("remove_old_entries: remove %s synctime %li:%li", entry->name.name, entry->synctime.tv_sec, entry->synctime.tv_nsec);

	    /* TODO: disconnect the connection(s)*/

	    remove_entry(entry, &error);

	    if (error==0) queue_remove(object, entry, &error);

	    entry=next;

	} else {

	    entry=entry->name_next;

	}

    }

}

/*

    open a directory representing a smb server
    get all services on this server by doing an opendir("smb://netbiosname")

*/

struct workspace_smbc_dh {
    struct pathinfo_struct		pathinfo;
    SMBCFILE				*handle;
    off_t				offset;
};

static void workspace_smb_opendir(fuse_req_t req, struct workspace_dh_struct *dh)
{
    struct resource_struct *resource=dh->object->resource;
    struct net_smb_server_struct *smb_server=NULL;
    struct workspace_host_struct *host=NULL;
    struct directory_struct *directory=dh->directory;
    char *path=dh->pathinfo.path + dh->relpath;
    unsigned int error=0;
    char *name=NULL;
    struct workspace_smbc_dh *smbc_dh=NULL;

    logoutput("workspace_smb_opendir");

    /* check the resource */

    if (! resource) {

	fuse_reply_err(req, EIO);
	return;

    } else if (!(resource->group=RESOURCE_GROUP_SMB && resource->type==SMB_TYPE_SERVER)) {

	fuse_reply_err(req, EIO);
	return;

    }

    smb_server=(struct net_smb_server_struct *) resource->data;
    host=smb_server->host;

    if (host->hostname) {

	name=host->hostname;

    } else if (strlen(host->ipv4)>0) {

	name=host->ipv4;

    } else if (strlen(host->ipv6)>0) {

	name=host->ipv6;

    } else if (smb_server->netbiosname) {

	/* resolving using the netbiosname as last, cause netbios is not native protocol for unix/linux */

	name=smb_server->netbiosname;

    }

    logoutput("workspace_smb_opendir: look for services on %s", name);

    /* check the smbclient context is initialized */

    if (manager_initialized==0) {

	init_smbclient_manager(&smbclient_manager_network);
	manager_initialized=1;
	get_current_time(&smbclient_manager_network.connect_time);

	if (create_smbclient_context(&smbclient_manager_network, &error)==-1) {

	    logoutput("workspace_smb_opendir: error %i:%s initializing smclient context for network/servers", error, strerror(error));
	    smbclient_manager_network.error=error;
	    fuse_reply_err(req, error);
	    return;

	}

    } else if (smbclient_manager_network.error>0) {
	struct timespec current_time;

	get_current_time(&current_time);

	if (is_later(&current_time, &smbclient_manager_network.connect_time, smb_options.smbclient_retryperiod_onerror, 0)==0) {

	    /* wait period after last connection error not expired */

	    fuse_reply_err(req, smbclient_manager_network.error);
	    return;

	}

	if (create_smbclient_context(&smbclient_manager_network, &error)==-1) {

	    logoutput("smb_opendir: error %i:%s initializing smclient context for network/servers", error, strerror(error));
	    smbclient_manager_network.error=error;
	    fuse_reply_err(req, error);
	    return;

	}

    }

    pthread_mutex_lock(&smbclient_manager_network.mutex);

    while (smbclient_manager_network.inuse==1) {

	pthread_cond_wait(&smbclient_manager_network.cond, &smbclient_manager_network.mutex);

    }

    smbc_dh=malloc(sizeof(struct workspace_smbc_dh));

    if (smbc_dh) {

	smbc_dh->pathinfo.path=NULL;
	smbc_dh->pathinfo.len=0;
	smbc_dh->pathinfo.flags=0;
	smbc_dh->handle=NULL;
	smbc_dh->offset=0;

	smbc_dh->pathinfo.path=smb_server->pathinfo.path;
	smbc_dh->pathinfo.len=smb_server->pathinfo.len;
	smbc_dh->pathinfo.flags=smb_server->pathinfo.flags | PATHINFO_FLAGS_INUSE;

	dh->handle.data = (void *) smbc_dh;

    } else {

	error=ENOMEM;

    }

    logoutput("smb_opendir: open %s", smbc_dh->pathinfo.path);

    smbclient_manager_network.inuse=(error==0) ? 1 : 0;

    pthread_mutex_unlock(&smbclient_manager_network.mutex);

    if (error>0) {

	error=errno;

	logoutput("smb_opendir: error %i:%s opening %s", error, strerror(error), smbc_dh->pathinfo.path);

	fuse_reply_err(req, error);

	if (smbc_dh) {

	    free(smbc_dh);
	    smbc_dh=NULL;

	}

	return;

    } else {

	fuse_reply_open(req, dh->fi);

    }

}

static void smb_readdir_simple(fuse_req_t req, size_t size, off_t offset, struct workspace_dh_struct *dh)
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
    struct smbc_dirent *de=NULL;
    struct workspace_smbc_dh *smbc_dh = (struct workspace_smbc_dh *) dh->handle.data;

    logoutput("smb_readdir_simple");

    memset(&st, 0, sizeof(struct stat));

    buff=malloc(size);

    if (! buff) {

	fuse_reply_err(req, ENOMEM);
	return;

    }

    memset(buff, '\0', size);

    while (pos<size) {

	if (! dh->entry) {

	    readdir:

	    de=smbc_getFunctionReaddir(smbclient_manager_network.context) (smbclient_manager_network.context, smbc_dh->handle);

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

		    if (de->smbc_type==SMBC_FILE_SHARE) {

			xname.name=de->name;

			if (de->comment) {

			    logoutput("smb_readdir_simple: name %s, comment %s", xname.name, de->comment);

			} else {

			    logoutput("smb_readdir_simple: name %s", xname.name);

			}

		    } else {

			logoutput("smb_readdir_simple: found name %s, skip (type=%i)", de->name, de->smbc_type);
			goto readdir;

		    }

		    xname.len=strlen(xname.name);
		    calculate_nameindex(&xname);

		    error=0;

		    entry=find_entry_batch(directory, &xname, &error);

		    if (! entry) {

			/* name not found: create new entry */

			entry=create_entry(dh->parent, &xname);
			inode=create_inode();

			if (entry && inode) {

			    result=insert_entry_batch(directory, entry, &error, 0);

			    if (result==entry) {
				struct workspace_object_struct *share_object=NULL;

				add_inode_hashtable(inode, increase_inodes_workspace, (void *) dh->object->workspace_mount);

				inode->alias=entry;
				entry->inode=inode;

				memcpy(&entry->synctime, &dh->synctime, sizeof(struct timespec));

				/* share is owned by root, has no size and is just detected */

				inode->mode = S_IFDIR | S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH;
				inode->uid=0;
				inode->gid=0;
				inode->size=_INODE_DIRECTORY_SIZE;
				inode->rdev=0;

				memcpy(&inode->mtim, &dh->synctime, sizeof(struct timespec));
				memcpy(&inode->ctim, &dh->synctime, sizeof(struct timespec));

				adjust_pathmax(dh->pathinfo.len + 1 + xname.len);

				/*
				    create a smb share object and resource
				*/

				logoutput("smb_readdir_simple: create share object for %s", xname.name);

				share_object=create_smb_share_object(xname.name, dh->object, &error);

				if (share_object) {
				    int test=-ENOSYS;

				    logoutput("smb_readdir_simple: TODO: create smb context for %s", xname.name);

				    inode->object=share_object;
				    share_object->inode=inode;
				    share_object->primary=1;

				    if (smb_options.share_use_smbclient==1) {

					test=set_module_calls_libsmbclient_shares(&share_object->module_calls);

				    } else if (smb_options.share_use_smbcli==1) {

					test=set_module_calls_smbcli_shares_sync(&share_object->module_calls);

				    }

				    if (test==-ENOSYS) {

					logoutput("smb_readdir_simple: TODO set the module calls to access smb shares");

				    }

				}

			    } else {

				/* insert results in another entry: should not happen */

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

				    break;

				}

			    }

			    st.st_mode=entry->inode->mode;
			    st.st_ino=entry->inode->ino;
			    name=entry->name.name;

			} else {

			    /* allocation of entry and/or inode failed */

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

			/* name found */

			st.st_ino=entry->inode->ino;
			st.st_mode=entry->inode->mode;
			name=entry->name.name;

			memcpy(&entry->synctime, &dh->synctime, sizeof(struct timespec));

		    }

		}


	    } else {

		dh->mode |= _WORKSPACE_READDIR_MODE_FINISH;
		break;

	    }

	} else {

	    entry=dh->entry;

	    st.st_ino=entry->inode->ino;
	    st.st_mode=entry->inode->mode;
	    name=entry->name.name;

	}

    	dirent_size=fuse_add_direntry(req, buff+pos, size-pos, name, &st, offset+1);

	if (pos + dirent_size > size) {

	    dh->offset = offset + 1;
	    smbc_dh->offset = smbc_getFunctionTelldir(smbclient_manager_network.context) (smbclient_manager_network.context, smbc_dh->handle);
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
    struct workspace_smbc_dh *smbc_dh = (struct workspace_smbc_dh *) dh->handle.data;
    struct directory_struct *directory=dh->directory;
    unsigned int error=0;

    if (lock_directory(directory, _DIRECTORY_LOCK_EXCL)==-1) {

	fuse_reply_err(req, EAGAIN);
	return;

    }

    pthread_mutex_lock(&smbclient_manager_network.mutex);

    smbc_dh->handle=smbc_getFunctionOpendir(smbclient_manager_network.context) (smbclient_manager_network.context, smbc_dh->pathinfo.path);

    if (smbc_dh->handle) {

	smbc_getFunctionLseekdir(smbclient_manager_network.context) (smbclient_manager_network.context, smbc_dh->handle, smbc_dh->offset);

	smb_readdir_simple(req, size, offset, dh);

	smbc_getFunctionClosedir(smbclient_manager_network.context) (smbclient_manager_network.context, smbc_dh->handle);

    } else {

	error=errno;
	fuse_reply_err(req, error);

    }

    pthread_mutex_unlock(&smbclient_manager_network.mutex);

    unlock_directory(directory, _DIRECTORY_LOCK_EXCL);

}

static void workspace_smb_readdirplus(fuse_req_t req, size_t size, off_t offset, struct workspace_dh_struct *dh)
{

    fuse_reply_err(req, ENOSYS);

}

static void workspace_smb_releasedir(fuse_req_t req, struct workspace_dh_struct *dh)
{
    struct directory_struct *directory=dh->directory;

    pthread_mutex_lock(&smbclient_manager_network.mutex);

    if (dh->handle.data) {
	struct workspace_smbc_dh *smbc_dh = (struct workspace_smbc_dh *) dh->handle.data;

	free_path_pathinfo(&smbc_dh->pathinfo);
	free(smbc_dh);


    }

    smbclient_manager_network.inuse=0;

    pthread_cond_broadcast(&smbclient_manager_network.cond);
    pthread_mutex_unlock(&smbclient_manager_network.mutex);

    fuse_reply_err(req, 0);

    if (directory) {

	/* when synced with backend and there were entries at start test these are not synced */

	if (dh->mode & _WORKSPACE_READDIR_MODE_NONEMPTY) remove_old_entries(dh->object, directory, &dh->synctime);
	memcpy(&directory->synctime, &dh->synctime, sizeof(struct timespec));

    }

    // clean_pathcache();

}

int set_module_calls_libsmbclient_server(struct module_calls_struct *mcalls)
{

    strcpy(mcalls->name, 	"libsmbclient-server");

    mcalls->groupid		= 0;

    mcalls->destroy		= workspace_smb_destroy;

    mcalls->opendir		= workspace_smb_opendir;
    mcalls->readdir		= workspace_smb_readdir;
    mcalls->readdirplus		= workspace_smb_readdirplus;
    mcalls->releasedir		= workspace_smb_releasedir;

    return 0;

}
