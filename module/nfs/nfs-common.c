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

#include <arpa/inet.h>

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

#include "workspaces.h"
#include "resources.h"
#include "objects.h"

#include "module/virtual/browsevirtual.h"
#include "module/nfs/nfs-common.h"
#include "libnfs-servers.h"
#include "libnfs-exports-sync.h"


struct fs_options_struct fs_options;
struct workerthreads_queue_struct workerthreads_queue;

/* struct meant as buffer to test a string is a valid ipv4 or ipv6 string */

struct inet_buff_struct {
    union {
	struct in_addr in;
	struct in6_addr in6;

    } addr;
};

/*
    try a server has exports using libnfs
*/

struct workspace_object_struct *workspace_nfs_connect_server(struct workspace_uri_struct *uri, struct workspace_mount_struct *workspace, unsigned int *error)
{
    struct workspace_object_struct *object=NULL;
    struct resource_struct *resource=NULL;
    struct net_nfs_server_struct *nfs_server;
    struct exportnode *exports_list=NULL;
    struct workspace_host_struct *host=NULL;
    int family=0;
    struct inet_buff_struct inet_buff;

    logoutput("workspace_nfs_connect_server: try %s", uri->address);

    /*
	test path is a valid address (only ip for now, ipv4 or ipv6)
    */

    if (inet_pton(AF_INET, uri->address, &inet_buff.addr)==1) {

	family=AF_INET;
	host=get_host_ipv4(uri->address);

    } else if (inet_pton(AF_INET6, uri->address, &inet_buff.addr)==1) {

	family=AF_INET6;

    } else {

	*error=EINVAL;
	return NULL;

    }

    if (! host) {

	*error=EINVAL;
	return NULL;

    }

    /*
	- test server for exports
    */

    exports_list=mount_getexports(host->ipv4);

    if ( ! exports_list) {

	/* server does not exist or has no exports: fail */

	*error=EINVAL;
	return NULL;	

    } else {

	mount_free_export_list(exports_list);

    }

    object=get_workspace_object();

    if (! object) {

	*error=ENOMEM;
	return NULL;

    }

    object->primary=1;
    object->workspace_mount=workspace;
    set_module_calls_libnfs_server(&object->module_calls);

    lock_resources();

    /* look for existing NFS servers */

    resource=get_next_resource(NULL);

    while(resource) {

	if (resource->group==RESOURCE_GROUP_NFS && resource->type==NFS_TYPE_SERVER) {

	    /* look for public nfs servers (although they are always public....) */

	    if (resource->security==RESOURCE_SECURITY_PUBLIC) {

		nfs_server=(struct net_nfs_server_struct *) resource->data;

		if (nfs_server->host) {

		    if (nfs_server->host==host) break;

		}

	    }

	}

	resource=get_next_resource(resource);

    }

    if (resource) {

	resource->refcount++;
	object->resource=resource;

    } else {

	resource=get_resource();
	nfs_server=malloc(sizeof(struct net_nfs_server_struct));

	if (resource && nfs_server) {

	    resource->security=RESOURCE_SECURITY_PUBLIC;
	    resource->status=RESOURCE_STATUS_OK;
	    resource->group=RESOURCE_GROUP_NFS;
	    resource->type=NFS_TYPE_SERVER;

	    resource->data=(void *) nfs_server;
	    resource->refcount=1;

	    nfs_server->host=host;

	    insert_resource_list(resource);

	    object->resource=resource;

	} else {

	    if (resource) {

		free_resource(resource);
		resource=NULL;

	    }

	    if (nfs_server) {

		free(nfs_server);
		nfs_server=NULL;

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

struct workspace_object_struct *create_nfs_export_object(struct pathinfo_struct *pathinfo, struct workspace_object_struct *server_object, unsigned int *error)
{

    /* here:

	create a nfs_context (per export)
	mount export using nfs_mount

    */

    struct workspace_object_struct *object=NULL;
    struct resource_struct *resource=NULL;
    struct net_nfs_export_struct *nfs_export;

    object=get_workspace_object();

    if (! object) {

	*error=ENOMEM;
	return NULL;

    }

    logoutput("create nfs export object: %s", pathinfo->path);

    object->primary=1;
    object->parent=server_object;
    object->workspace_mount=server_object->workspace_mount;

    set_module_calls_libnfs_export(&object->module_calls);

    lock_resources();

    /* look for existing NFS servers */

    resource=get_next_resource(NULL);

    while(resource) {

	if (resource->group==RESOURCE_GROUP_NFS && resource->type==NFS_TYPE_EXPORT) {

	    /* look for public nfs exports (although they are always public at this moment) */

	    if (resource->security==RESOURCE_SECURITY_PUBLIC) {

		nfs_export=(struct net_nfs_export_struct *) resource->data;

		if (nfs_export->pathinfo.path) {

		    if (strcmp(nfs_export->pathinfo.path, pathinfo->path)==0) break;

		}

	    }

	}

	resource=get_next_resource(resource);

    }

    if (resource) {

	resource->refcount++;
	object->resource=resource;
	object->parent=server_object;
	object->workspace_mount=server_object->workspace_mount;

    } else {

	resource=get_resource();
	nfs_export=malloc(sizeof(struct net_nfs_export_struct));

	if (resource && nfs_export) {

	    /*
		TODO: can NFS exports also be private ?
		I do not know enough about NFS on this topic
	    */

	    resource->security=RESOURCE_SECURITY_PUBLIC;
	    resource->status=RESOURCE_STATUS_OK;
	    resource->group=RESOURCE_GROUP_NFS;
	    resource->type=NFS_TYPE_EXPORT;

	    resource->data=(void *) nfs_export;
	    resource->refcount=1;

	    if (! (pathinfo->flags & PATHINFO_FLAGS_INUSE) && (pathinfo->flags & PATHINFO_FLAGS_ALLOCATED)) {

		/* take over the path */

		nfs_export->pathinfo.path=pathinfo->path;
		nfs_export->pathinfo.len=pathinfo->len;
		nfs_export->pathinfo.flags=pathinfo->flags;

		pathinfo->path=NULL;
		pathinfo->len=0;
		pathinfo->flags=0;

	    } else {

		/* allocate space */

		nfs_export->pathinfo.path=malloc(pathinfo->len + 1);

		if (nfs_export->pathinfo.path) {

		    strcpy(nfs_export->pathinfo.path, pathinfo->path);
		    nfs_export->pathinfo.len=pathinfo->len;
		    nfs_export->pathinfo.flags=PATHINFO_FLAGS_ALLOCATED;

		} else {

		    *error=ENOMEM;

		}

	    }

	    nfs_export->data=NULL;
	    pthread_mutex_init(&nfs_export->mutex, NULL);

	    insert_resource_list(resource);

	    object->resource=resource;

	} else {

	    if (resource) {

		free_resource(resource);
		resource=NULL;

	    }

	    if (nfs_export) {

		free(nfs_export);
		nfs_export=NULL;

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

