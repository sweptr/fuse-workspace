/*
  2010, 2011, 2012, 2013 Stef Bon <stefbon@gmail.com>

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
#include <time.h>

#include <pthread.h>

#ifndef ENOATTR
#define ENOATTR ENODATA        /* No such attribute */
#endif

#include "logging.h"

#include "fuse-workspace.h"
#include "entry-management.h"
#include "utils.h"
#include "beventloop-utils.h"
#include "workspaces.h"
#include "path-resolution.h"

#include "resources.h"
#include "simple-list.h"

extern struct global_options_struct fs_options;

static struct resource_struct *resources=NULL;
static pthread_mutex_t resources_mutex=PTHREAD_MUTEX_INITIALIZER;

static struct workspace_host_struct *hosts=NULL;
static pthread_mutex_t hosts_mutex=PTHREAD_MUTEX_INITIALIZER;

static struct workspace_host_struct *lookup_host_ipv4(char *ipv4)
{
    struct workspace_host_struct *host=NULL;

    host=hosts;

    while (host) {

	if (memcmp(host->ipv4, ipv4, INET_ADDRSTRLEN)==0) break;
	host=host->next;

    }


    return host;

}

static struct workspace_host_struct *create_host()
{
    struct workspace_host_struct *host=malloc(sizeof(struct workspace_host_struct));

    if (host) {

	host->options=0;
	memset(host->ipv4, '\0', INET_ADDRSTRLEN+1);
	memset(host->ipv6, '\0', INET6_ADDRSTRLEN+1);
	host->hostname=NULL;
	host->next=NULL;

    }

    return host;

}

struct workspace_host_struct *get_host_ipv4(char *ipv4)
{
    struct workspace_host_struct *host=NULL;

    pthread_mutex_lock(&hosts_mutex);

    host=lookup_host_ipv4(ipv4);

    if (! host) {

	host=create_host();

	if (host) {

	    memcpy(host->ipv4, ipv4, INET_ADDRSTRLEN);
	    host->next=hosts;
	    hosts=host;

	}

    }

    pthread_mutex_unlock(&hosts_mutex);

    return host;

}


void init_resource(struct resource_struct *resource)
{

    memset(resource, 0, sizeof(struct resource_struct));

    resource->detecttime_cache.tv_sec=0;
    resource->detecttime_cache.tv_nsec=0;

    resource->detecttime_browse.tv_sec=0;
    resource->detecttime_browse.tv_nsec=0;

    resource->next=NULL;
    resource->prev=NULL;
    resource->parent=NULL;

    resource->security=0;
    resource->group=0;
    resource->type=0;
    resource->status=0;

    resource->refcount=0;

    resource->primary=0;

    resource->data=NULL;

}

struct resource_struct *get_resource()
{
    struct resource_struct *resource=NULL;

    resource=malloc(sizeof(struct resource_struct));

    if ( resource ) {

	init_resource(resource);
	pthread_rwlock_init(&resource->rwlock, NULL);

    }

    return resource;

}

int lock_resources()
{
    return pthread_mutex_lock(&resources_mutex);
}

int unlock_resources()
{
    return pthread_mutex_unlock(&resources_mutex);
}

struct resource_struct *get_next_resource(struct resource_struct *resource)
{
    return (resource) ? resource->next : resources;
}

void insert_resource_list(struct resource_struct *resource)
{

    if (resources) {

	resource->next=resources;
	resources->prev=resource;

    }

    resources=resource;

}

void remove_resource_list(struct resource_struct *resource)
{

    if (resource==resources) resources=resource->next;
    if (resource->next) resource->next->prev=resource->prev;
    if (resource->prev) resource->prev->next=resource->next;

}

void free_resource(struct resource_struct *resource)
{

    if (resource->group==RESOURCE_GROUP_FILE){
	struct localfile_struct *localfile=(struct localfile_struct *) resource->data;

	if (localfile) {

	    free_path_pathinfo(&localfile->pathinfo);
	    free(localfile);

	}

    }

    pthread_rwlock_destroy(&resource->rwlock);

    free(resource);

}

void free_workspace_uri(struct workspace_uri_struct *uri)
{

    if (uri->address) {

	free(uri->address);
	uri->address=NULL;

    }

    if (uri->group==RESOURCE_GROUP_SMB) {

	if (uri->type.smbinfo.authdata) {

	    free(uri->type.smbinfo.authdata);
	    uri->type.smbinfo.authdata=NULL;

	}

    }

}