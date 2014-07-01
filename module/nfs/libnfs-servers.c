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
#include "libnfs-servers.h"

struct fs_options_struct fs_options;
struct workerthreads_queue_struct workerthreads_queue;

extern const char *rootpath;
extern const char *dotdotname;
extern const char *dotname;

static void workspace_nfs_destroy(struct workspace_object_struct *object)
{

    logoutput("nfs_destroy: destroy overlay browsing");
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

	    /* TODO: disconnect from nfs server */

	    remove_entry(entry, &error);

	    if (error==0) queue_remove(object, entry, &error);

	    entry=next;

	} else {

	    entry=entry->name_next;

	}

    }

}

struct nfs_server_readdir_struct {
    struct exportnode 						*exportlist;
    struct exportnode						*export;
};

/* open a directory representing a server: show all exports */

static void workspace_nfs_opendir(fuse_req_t req, struct workspace_dh_struct *dh)
{
    struct resource_struct *resource=dh->object->resource;
    struct net_nfs_server_struct *nfs_server=NULL;
    struct nfs_server_readdir_struct *nfs_readdir=NULL;
    struct directory_struct *directory=dh->directory;
    unsigned int error=0;
    struct exportnode  *exportlist=NULL;

    logoutput("nfs_opendir");

    /* check the resource */

    if (! resource) {

	fuse_reply_err(req, EIO);
	return;

    } else if (!(resource->group=RESOURCE_GROUP_NFS && resource->type==NFS_TYPE_SERVER)) {

	fuse_reply_err(req, EIO);
	return;

    }

    nfs_readdir=malloc(sizeof(struct nfs_server_readdir_struct));

    if (! nfs_readdir) {

	fuse_reply_err(req, ENOMEM);
	return;

    }

    nfs_server=(struct net_nfs_server_struct *) resource->data;

    if (nfs_server->host->hostname) {

	logoutput("nfs_opendir: look for exports on %s", nfs_server->host->hostname);

    } else if (strlen(nfs_server->host->ipv4)>0) {

	logoutput("nfs_opendir: look for exports on %s", nfs_server->host->ipv4);

    } else if (strlen(nfs_server->host->ipv6)>0) {

	logoutput("nfs_opendir: look for exports on %s", nfs_server->host->ipv6);

    }

    nfs_readdir->exportlist=mount_getexports(nfs_server->host->ipv4);
    nfs_readdir->export=nfs_readdir->exportlist;

    dh->handle.data=(void *) nfs_readdir;

    fuse_reply_open(req, dh->fi);

    free_path_pathinfo(&dh->pathinfo);

    return;

}

static void nfs_readdir_simple(fuse_req_t req, size_t size, off_t offset, struct workspace_dh_struct *dh)
{
    unsigned int error=0;
    char *buff=NULL;
    size_t pos=0;
    size_t dirent_size;
    char *name=NULL;
    struct directory_struct *directory=dh->directory;
    struct nfs_server_readdir_struct *nfs_readdir=(struct nfs_server_readdir_struct *) dh->handle.data;
    struct entry_struct *entry, *result;
    struct inode_struct *inode;
    struct name_struct xname={NULL, 0, 0};
    struct stat st;
    struct pathinfo_struct pathinfo={NULL, 0, 0};

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

		if (nfs_readdir->export) {
		    char *slash=NULL;

		    pathinfo.path=nfs_readdir->export->ex_dir;
		    pathinfo.len=strlen(pathinfo.path);

		    slash=strrchr(pathinfo.path, '/');

		    if (slash) {

			xname.name=slash+1;

		    } else {

			xname.name=pathinfo.path;

		    }

		    logoutput("nfs_readdir_simple: got dir %s, name %s", pathinfo.path, xname.name);

		    xname.len=strlen(xname.name);
		    calculate_nameindex(&xname);

		    nfs_readdir->export=nfs_readdir->export->ex_next;

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

			inode->mode = S_IFDIR | S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH;

			add_inode_hashtable(inode, increase_inodes_workspace, (void *) dh->object->workspace_mount);

			inode->alias=entry;
			entry->inode=inode;

			memcpy(&entry->synctime, &dh->synctime, sizeof(struct timespec));

			adjust_pathmax(dh->pathinfo.len + 1 + xname.len);

			/*
			    create a nfs export object and resource
			    -connect to server/export
			*/

			logoutput("nfs_readdir_simple: create export object for %s", xname.name);

			export_object=create_nfs_export_object(&pathinfo, dh->object, &error);

			if (export_object) {
			    struct resource_struct *server_resource=dh->object->resource;
			    struct net_nfs_server_struct *nfs_server=(struct net_nfs_server_struct *) server_resource->data;
			    struct workspace_host_struct *host=nfs_server->host;

			    if (host) {
				struct nfs_context *nfs_ctx=NULL;

				/* mount export */

				nfs_ctx=nfs_init_context();

				if (nfs_ctx) {
				    int result=0;

				    logoutput("nfs_readdir_simple: mount for %s", xname.name);

				    result=nfs_mount(nfs_ctx, host->ipv4, pathinfo.path);

				    if (result==0) {
					struct resource_struct *export_resource=export_object->resource;
					struct net_nfs_export_struct *nfs_export=(struct net_nfs_export_struct *) export_resource->data;

					/* success */

					nfs_export->data=(void *) nfs_ctx;

					export_object->inode=inode;
					inode->object=export_object;

				    } else {

					logoutput("nfs_readdir_simple: error %i connecting to nfs://%s%s", abs(result), host->ipv4, pathinfo.path);
					nfs_destroy_context(nfs_ctx);

				    }

				} else {

				    logoutput("nfs_readdir_simple: error allocating memeory for connection nfs://%s%s", host->ipv4, pathinfo.path);

				}

			    }

			}

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

static void nfs_readdirplus_simple(fuse_req_t req, size_t size, off_t offset, struct workspace_dh_struct *dh)
{
    unsigned int error=0;
    char *buff=NULL;
    size_t pos=0;
    size_t dirent_size;
    struct fuse_entry_param e;
    char *name=NULL;
    struct directory_struct *directory=dh->directory;
    struct nfs_server_readdir_struct *nfs_readdir=(struct nfs_server_readdir_struct *)dh->handle.data;
    struct entry_struct *entry, *result;
    struct inode_struct *inode;
    struct name_struct xname={NULL, 0, 0};
    struct pathinfo_struct pathinfo={NULL, 0, 0};

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

		if (nfs_readdir->export) {
		    char *slash=NULL;

		    pathinfo.path=nfs_readdir->export->ex_dir;
		    pathinfo.len=strlen(pathinfo.path);

		    slash=strrchr(pathinfo.path, '/');

		    if (slash) {

			xname.name=slash+1;

		    } else {

			xname.name=pathinfo.path;

		    }

		    logoutput("nfs_readdirplus_simple: got dir %s, name %s", pathinfo.path, xname.name);

		    xname.len=strlen(xname.name);
		    calculate_nameindex(&xname);

		    nfs_readdir->export=nfs_readdir->export->ex_next;

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

			inode->mode = S_IFDIR | S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH;

			add_inode_hashtable(inode, increase_inodes_workspace, (void *) dh->object->workspace_mount);

			inode->alias=entry;
			entry->inode=inode;

			memcpy(&entry->synctime, &dh->synctime, sizeof(struct timespec));

			inode->nlookup++;
			inode->nlink=2;
			inode->uid=0;
			inode->gid=0;
			inode->size=0;

			memcpy(&inode->mtim, &dh->synctime, sizeof(struct timespec));
			memcpy(&inode->ctim, &dh->synctime, sizeof(struct timespec));

			adjust_pathmax(dh->pathinfo.len + 1 + xname.len);

			/* create a nfs export object and resource */

			logoutput("nfs_readdirplus_simple: create export object for %s", xname.name);

			export_object=create_nfs_export_object(&pathinfo, dh->object, &error);

			if (export_object) {
			    struct resource_struct *server_resource=dh->object->resource;
			    struct net_nfs_server_struct *nfs_server=(struct net_nfs_server_struct *) server_resource->data;
			    struct workspace_host_struct *host=nfs_server->host;

			    if (host) {
				struct nfs_context *nfs_ctx=NULL;

				/* mount export */

				nfs_ctx=nfs_init_context();

				if (nfs_ctx) {
				    int result=0;

				    logoutput("nfs_readdir_simple: mount for %s", xname.name);

				    result=nfs_mount(nfs_ctx, host->ipv4, pathinfo.path);

				    if (result==0) {
					struct resource_struct *export_resource=export_object->resource;
					struct net_nfs_export_struct *nfs_export=(struct net_nfs_export_struct *) export_resource->data;

					/* success */

					nfs_export->data=(void *) nfs_ctx;

					export_object->inode=inode;
					inode->object=export_object;

				    } else {

					logoutput("nfs_readdir_simple: error %i connecting to nfs://%s%s", abs(result), host->ipv4, pathinfo.path);
					nfs_destroy_context(nfs_ctx);

				    }

				} else {

				    logoutput("nfs_readdir_simple: error allocating memeory for connection nfs://%s%s", host->ipv4, pathinfo.path);

				}

			    }

			}

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

    nfs_readdir_simple(req, size, offset, dh);

}

static void workspace_nfs_readdirplus(fuse_req_t req, size_t size, off_t offset, struct workspace_dh_struct *dh)
{

    nfs_readdirplus_simple(req, size, offset, dh);

}

static void workspace_nfs_releasedir(fuse_req_t req, struct workspace_dh_struct *dh)
{
    struct nfs_server_readdir_struct *nfs_readdir=(struct nfs_server_readdir_struct *)dh->handle.data;
    struct directory_struct *directory=NULL;
    struct timespec synctime;
    unsigned int error=0;
    unsigned int mode=0;

    logoutput("workspace_nfs_releasedir");

    directory=dh->directory;

    if (nfs_readdir) {

	mount_free_export_list(nfs_readdir->exportlist);

	nfs_readdir->exportlist=NULL;
	nfs_readdir->export=NULL;

	free(nfs_readdir);
	nfs_readdir=NULL;

    }

    fuse_reply_err(req, 0);

    if (directory) {

	/* when synced with backend and there were entries at start test these are not synced */

	if (dh->mode & _WORKSPACE_READDIR_MODE_NONEMPTY) remove_old_entries(dh->object, directory, &dh->synctime);

	memcpy(&directory->synctime, &dh->synctime, sizeof(struct timespec));

    }

}

void set_module_calls_libnfs_server(struct module_calls_struct *mcalls)
{

	strcpy(mcalls->name, "libnfs-server");

	mcalls->groupid		= 0;

	mcalls->destroy		= workspace_nfs_destroy;

	mcalls->opendir		= workspace_nfs_opendir;
	mcalls->readdir		= workspace_nfs_readdir;
	mcalls->readdirplus	= workspace_nfs_readdirplus;
	mcalls->releasedir	= workspace_nfs_releasedir;

}
