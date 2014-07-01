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
#include <dirent.h>

#ifndef ENOATTR
#define ENOATTR ENODATA        /* No such attribute */
#endif

#include "fuse-workspace.h"
#include "entry-management.h"
#include "utils.h"

#include "beventloop-utils.h"
#include "workspaces.h"
#include "path-resolution.h"
#include "resources.h"
#include "objects.h"

#include "module/virtual/browsevirtual.h"

#include "module/file/overlay.h"
#include "module/nfs/nfs-common.h"
#include "module/smb/smb-common.h"

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

#define logoutput(...) dummy_nolog()

#endif

void init_module_calls(struct module_calls_struct *module_calls)
{

    memset(module_calls->name, '\0', sizeof(module_calls->name));
    module_calls->groupid=0;

    module_calls->destroy=NULL;

    module_calls->lookup_cached=NULL;
    module_calls->lookup_noncached=NULL;
    module_calls->getattr=NULL;
    module_calls->setattr=NULL;

    module_calls->readlink=NULL;

    module_calls->mknod=NULL;
    module_calls->mkdir=NULL;
    module_calls->symlink=NULL;

    module_calls->unlink=NULL;
    module_calls->rmdir=NULL;

    module_calls->rename_cached=NULL;
    module_calls->rename_noncached=NULL;

    module_calls->open=NULL;
    module_calls->read=NULL;
    module_calls->write=NULL;
    module_calls->flush=NULL;
    module_calls->fsync=NULL;
    module_calls->release=NULL;
    module_calls->create=NULL;

    module_calls->fgetattr=NULL;
    module_calls->fsetattr=NULL;

    module_calls->opendir=NULL;
    module_calls->readdir=NULL;
    module_calls->readdirplus=NULL;
    module_calls->releasedir=NULL;
    module_calls->fsyncdir=NULL;

    module_calls->fsnotify=NULL;

    module_calls->next=NULL;

}

struct workspace_object_struct *get_workspace_object()
{
    struct workspace_object_struct *object=NULL;

    object=malloc(sizeof(struct workspace_object_struct));

    if (object) {

	/* connection with fs */

	object->inode=NULL;

	/* structure */

	object->parent=NULL;

	/* general list per workspace */

	object->next=NULL;
	object->prev=NULL;

	/* module calls */

	init_module_calls(&object->module_calls);
	set_module_calls_virtual(&object->module_calls);

	/* workspace */

	object->workspace_mount=NULL;

	object->primary=0;
	object->resource=NULL;

    }

    return object;

}

struct workspace_object_struct *create_object_simple(struct workspace_uri_struct *uri, struct workspace_mount_struct *workspace, unsigned int *error)
{
    struct workspace_object_struct *object=NULL;
    struct workspace_base_struct *base=workspace->workspace_base;

    *error=EINVAL;

    /* here walk through the known modules */

    if (uri->group==RESOURCE_GROUP_FILE) {

	if (base->type==WORKSPACE_TYPE_FILE) {

	    logoutput("create_object: creating file object for %s", uri->address);

	    object=overlay_connect(uri, workspace, error);

	    if (object) {

		object->primary=1;

		*error=0;
		return object;

	    }

	} else {

	    logoutput("create_object: cannot create file object for %s in %s: wrong type", uri->address, workspace->fuseparam.mountpoint);
	    *error=EINVAL;
	    return NULL;

	}

    } else if (uri->group==RESOURCE_GROUP_NFS) {

	if (base->type==WORKSPACE_TYPE_NETWORK) {
	    struct workspace_object_struct *object=NULL;

	    logoutput("create_object: creating nfs object for %s", uri->address);

	    object=workspace_nfs_connect_server(uri, workspace, error);

	    if (object) {

		object->primary=1;

		*error=0;
		return object;

	    }

	} else {

	    logoutput("create_object: cannot create file object for %s in %s: wrong type", uri->address, workspace->fuseparam.mountpoint);
	    *error=EINVAL;
	    return NULL;


	}

    } else if (uri->group==RESOURCE_GROUP_SMB) {

	if (base->type==WORKSPACE_TYPE_NETWORK) {
	    struct workspace_object_struct *object=NULL;

	    logoutput("create_object: creating smb object for %s", uri->address);

	    object=workspace_smb_connect_server(uri, workspace, error);

	    if (object) {

		object->primary=1;

		*error=0;
		return object;

	    }

	} else {

	    logoutput("create_object: cannot create file object for %s in %s: wrong type", uri->address, workspace->fuseparam.mountpoint);
	    *error=EINVAL;
	    return NULL;

	}

    }

    if (*error==0) *error=EINVAL;
    return NULL;

}
