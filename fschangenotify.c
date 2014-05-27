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
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <pthread.h>
#include <sys/inotify.h>

#ifndef ENOATTR
#define ENOATTR ENODATA        /* No such attribute */
#endif

#define WATCHES_TABLESIZE          1024

#include "fuse-workspace.h"

#include "workerthreads.h"
#include "beventloop-utils.h"

#include "entry-management.h"

#include "path-resolution.h"
#include "options.h"
#include "utils.h"
#include "simple-list.h"
#include "workspaces.h"
#include "objects.h"

#include "fschangenotify.h"
#include "fschangenotify-event.h"


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

extern struct fs_options_struct fs_options;
extern struct workerthreads_queue_struct workerthreads_queue;

struct systemwatches_struct {
    struct notifywatch_struct 	*first;
    pthread_mutex_t		mutex;
};

static struct simple_group_struct group_watches_inode;
static struct systemwatches_struct systemwatches = { NULL, PTHREAD_MUTEX_INITIALIZER};

static struct watchbackend_struct os_watchbackend = {0, NULL, NULL, NULL};
extern struct watchbackend_struct fssync_watchbackend;

#ifdef __gnu_linux__

#ifdef HAVE_INOTIFY
#include <sys/inotify.h>

#include "fschangenotify-linux-inotify.c"
#define _FSCHANGENOTIFY_BACKEND

int set_watch_backend_os_specific(struct notifywatch_struct *watch)
{
    return set_watch_backend_inotify(watch);
}

int change_watch_backend_os_specific(struct notifywatch_struct *watch)
{
    return change_watch_backend_inotify(watch);
}

void remove_watch_backend_os_specific(struct notifywatch_struct *watch)
{
    remove_watch_backend_inotify(watch);
}

void initialize_fsnotify_backend(unsigned int *error)
{
    initialize_inotify(error);

}

void close_fsnotify_backend()
{
    close_inotify();

}

#endif
#endif

#ifndef _FSCHANGENOTIFY_BACKEND

static inline int set_watch_backend_os_specific(struct notifywatch_struct *watch)
{
    return -ENOSYS;
}

static inline int change_watch_backend_os_specific(struct notifywatch_struct *watch)
{
    return -ENOSYS;
}

static inline void remove_watch_backend_os_specific(struct notifywatch_struct *watch)
{
    return;
}

static inline void initialize_fsnotify_backend(unsigned int *error)
{
    return;
}

static inline void close_fsnotify_backend()
{
    return;

}

#endif

void lock_watch(struct notifywatch_struct *watch)
{
    pthread_mutex_lock(&watch->mutex);
}

void unlock_watch(struct notifywatch_struct *watch)
{
    pthread_mutex_unlock(&watch->mutex);
}

/*
    function to lookup a watch using the inode
*/

static unsigned int calculate_inode_hash_watch(struct inode_struct *inode)
{
    return inode->ino % group_watches_inode.len;
}

static int watch_inode_hashfunction(void *data)
{
    struct notifywatch_struct *watch=(struct notifywatch_struct *) data;
    if (watch->inode) return calculate_inode_hash_watch(watch->inode);
    return 0;
}

struct notifywatch_struct *lookup_watch_inode(struct inode_struct *inode)
{
    unsigned int hashvalue=calculate_inode_hash_watch(inode);
    void *index=NULL;
    struct notifywatch_struct *watch=NULL;

    watch=(struct notifywatch_struct *) get_next_element(&group_watches_inode, &index, hashvalue);

    while(watch) {

	if (watch->inode==inode) break;
	watch=(struct notifywatch_struct *) get_next_element(&group_watches_inode, &index, hashvalue);

    }

    return watch;

}

void add_watch_inodetable(struct notifywatch_struct *watch)
{
    add_element_to_group(&group_watches_inode, (void *) watch);
}

void remove_watch_inodetable(struct notifywatch_struct *watch)
{
    remove_element_from_group(&group_watches_inode, (void *) watch);
}

/*
    maintain a list of system watches
*/

void add_watch_systemwatches(struct notifywatch_struct *watch)
{

    pthread_mutex_lock(&systemwatches.mutex);

    watch->prev=NULL;
    watch->next=systemwatches.first;

    systemwatches.first=watch;

    pthread_mutex_unlock(&systemwatches.mutex);

}

void remove_watch_systemwatches(struct notifywatch_struct *watch)
{

    pthread_mutex_lock(&systemwatches.mutex);

    if (systemwatches.first==watch) {

	systemwatches.first=watch->next;

	if (systemwatches.first) systemwatches.first->prev=NULL;

    } else {

	if (watch->prev) watch->prev->next=watch->next;
	if (watch->next) watch->next->prev=watch->prev;

    }

    pthread_mutex_unlock(&systemwatches.mutex);

}

struct notifywatch_struct *lookup_watch_systemwatches(struct pathinfo_struct *pathinfo)
{
    struct notifywatch_struct *watch=NULL;

    pthread_mutex_lock(&systemwatches.mutex);

    watch=systemwatches.first;

    while(watch) {

	if (strcmp(pathinfo->path, watch->pathinfo.path)==0) break;

	watch=watch->next;

    }

    pthread_mutex_unlock(&systemwatches.mutex);

    return watch;

}


int init_watch_hashtables()
{
    int result=0;
    unsigned int error=0;

    result=initialize_group(&group_watches_inode, watch_inode_hashfunction, 256, &error);

    out:

    return result;

}

/*
    function to determine the fsnotify mask by comparing the backend (real value) (st) with the cache (inode)
*/

uint32_t determine_fsnotify_mask(struct inode_struct *inode, struct stat *st)
{
    uint32_t fsnotify_mask=0;

    if (inode->mode != st->st_mode) {

	fsnotify_mask |= IN_ATTRIB;
	inode->mode = st->st_mode;

    }

    if (inode->uid != st->st_uid) {

	fsnotify_mask |= IN_ATTRIB;
	inode->uid = st->st_uid;

    }

    if (inode->gid != st->st_gid) {

	fsnotify_mask |= IN_ATTRIB;
	inode->gid = st->st_gid;

    }

    if (inode->mtim.tv_sec != st->st_mtim.tv_sec || inode->mtim.tv_nsec != st->st_mtim.tv_nsec) {

	fsnotify_mask |= IN_MODIFY;
	inode->mtim.tv_sec = st->st_mtim.tv_sec;
	inode->mtim.tv_nsec = st->st_mtim.tv_nsec;

    }

    if (inode->ctim.tv_sec != st->st_ctim.tv_sec || inode->ctim.tv_nsec != st->st_ctim.tv_nsec) {

	/* action ? */

	inode->ctim.tv_sec = st->st_ctim.tv_sec;
	inode->ctim.tv_nsec = st->st_ctim.tv_nsec;

    }

    return fsnotify_mask;

}

static struct notifywatch_struct *lookup_watch_inodetable_bypath(char *path)
{
    unsigned int hashvalue=0;
    void *index=NULL;
    struct notifywatch_struct *watch=NULL;

    while (hashvalue<group_watches_inode.len) {

	index=NULL;

	watch=(struct notifywatch_struct *) get_next_element(&group_watches_inode, &index, hashvalue);

	while(watch) {

	    if (strcmp(watch->pathinfo.path, path)==0) break;

	    watch=(struct notifywatch_struct *) get_next_element(&group_watches_inode, &index, hashvalue);

	}

	hashvalue++;

    }

    return watch;

}

uint32_t get_cbmask(struct watchcb_struct *cb) {

    uint32_t mask=0;

    if (cb->create) mask |= (IN_CREATE | IN_MOVED_TO);
    if (cb->remove) mask |= (IN_DELETE | IN_MOVED_FROM);
    if (cb->change) mask |= (IN_MODIFY | IN_ATTRIB);

    return mask;

}

void assign_watchbackend(struct notifywatch_struct *watch)
{
    int result=0;

    result=(* os_watchbackend.set_watch)(watch);

    if (result>=0) {

	/* success */

	watch->backend=&os_watchbackend;

    } else if (result==-ENOSYS) {

	result=(* fssync_watchbackend.set_watch)(watch);

	if (result>=0) {

	    watch->backend=&fssync_watchbackend;

	} else {

	    logoutput_error("assign_watchbackend: error %i setting fssync watch on %s", abs(result), watch->pathinfo.path);

	}

    } else {

	logoutput_error("assign_watchbackend: error %i setting os watch on %s", abs(result), watch->pathinfo.path);

    }

}

struct notifywatch_struct *add_notifywatch(struct inode_struct *inode, uint32_t mask, struct pathinfo_struct *pathinfo, struct workspace_object_struct *object, unsigned int *error)
{
    struct notifywatch_struct *watch=NULL;
    int result=0;

    if (mask==0) {

	*error=EINVAL;
	goto out;

    } else if (! pathinfo) {

	*error=EINVAL;
	goto out;

    } else if (! pathinfo->path) {

	*error=EINVAL;
	goto out;

    } else if (! inode) {

	*error=EINVAL;
	goto out;

    }

    /* possible here compare the pathinfo->path with the one stored in watch->pathinfo.path*/

    logoutput("add_notifywatch: on %s mask %i", pathinfo->path, (int) mask);

    watch=lookup_watch_inode(inode);
    if (! watch) watch=lookup_watch_systemwatches(pathinfo);

    if ( ! watch ) {

	logoutput("add_notifywatch: no watch found, creating one");

	watch=malloc(sizeof(struct notifywatch_struct));

	if (watch) {

	    watch->flags=NOTIFYWATCH_FLAG_NOTIFY;
	    watch->inode=inode;
	    watch->object=object;
	    watch->notifymask=mask;
	    pthread_mutex_init(&watch->mutex, NULL);

	    watch->backend=NULL;
	    watch->cb=NULL;
	    watch->data=NULL;

	    watch->next=NULL;
	    watch->prev=NULL;

	    /* take over the path only if allocated and not inuse */

	    if ((!(pathinfo->flags & PATHINFOFLAGS_INUSE)) && (pathinfo->flags & PATHINFOFLAGS_ALLOCATED)) {

		watch->pathinfo.path=pathinfo->path;
		watch->pathinfo.len=pathinfo->len;
		watch->pathinfo.flags=PATHINFOFLAGS_INUSE | PATHINFOFLAGS_ALLOCATED;
		pathinfo->flags-=PATHINFOFLAGS_ALLOCATED;
		watch->pathinfo.flags=pathinfo->flags;

	    } else {

		watch->pathinfo.path=malloc(pathinfo->len);

		if (watch->pathinfo.path) {

		    memcpy(watch->pathinfo.path, pathinfo->path, pathinfo->len);
		    watch->pathinfo.len=pathinfo->len;
		    watch->pathinfo.flags=pathinfo->flags;
		    watch->pathinfo.flags=PATHINFOFLAGS_INUSE | PATHINFOFLAGS_ALLOCATED;

		} else {

		    logoutput("add_notifywatch: error allocating memory for path %s", pathinfo->path);
		    free(watch);
		    watch=NULL;
		    goto out;

		}

	    }

	    add_watch_inodetable(watch);
	    watch->mask=mask;

	} else {

	    logoutput("add_notifywatch: unable to allocate a watch");
	    goto out;

	}

	pthread_mutex_lock(&watch->mutex);

	/*
	    assign the backend: inotify, fssync....
	*/

	assign_watchbackend(watch);

	unlock:

	pthread_mutex_unlock(&watch->mutex);

    } else {

	/* existing watch found */

	logoutput("add_notifywatch: existing watch found on %s", pathinfo->path);

	pthread_mutex_lock(&watch->mutex);

	if ( ! (watch->flags & NOTIFYWATCH_FLAG_NOTIFY)) {
	    uint32_t current_mask=0;

	    watch->flags |= NOTIFYWATCH_FLAG_NOTIFY;

	    watch->inode=inode;
	    add_watch_inodetable(watch);

	    current_mask=watch->mask;

	    watch->notifymask=mask;
	    watch->mask = watch->notifymask;
	    if (watch->cb) watch->mask |= get_cbmask(watch->cb);

	    if (watch->mask != current_mask) (* watch->backend->change_watch) (watch);

	} else {

	    *error=EEXIST;

	}

	pthread_mutex_unlock(&watch->mutex);

    }

    out:

    return watch;

}

/*
    change/remove a watch
*/

void change_notifywatch(struct notifywatch_struct *watch, uint32_t mask)
{
    uint32_t current_mask;

    if (! watch->inode) return;

    logoutput("change_notifywatch: new mask %i", (int) mask);

    pthread_mutex_lock(&watch->mutex);

    current_mask=watch->mask;
    watch->notifymask=mask;

    if (watch->notifymask==0) {

	if (watch->flags & NOTIFYWATCH_FLAG_NOTIFY) {

	    watch->flags -= NOTIFYWATCH_FLAG_NOTIFY;

	    remove_watch_inodetable(watch);
	    watch->inode=NULL;

	}

	watch->mask=0;
	if (watch->cb) watch->mask=get_cbmask(watch->cb);

	if (watch->mask==0) {

	    (* watch->backend->remove_watch) (watch);

	    remove_watch_systemwatches(watch);

	} else if (watch->mask != current_mask) {

	    (* watch->backend->change_watch) (watch);

	}

    } else {

	watch->mask = watch->notifymask;
	if (watch->cb) watch->mask |= get_cbmask(watch->cb);

	if (watch->mask != current_mask) (* watch->backend->change_watch) (watch);

    }

    pthread_mutex_unlock(&watch->mutex);

    if (watch->mask==0) {

	pthread_mutex_destroy(&watch->mutex);
	free_path_pathinfo(&watch->pathinfo);

	free(watch);

    }

}

struct notifywatch_struct *add_systemwatch(struct pathinfo_struct *pathinfo, struct watchcb_struct *cb, unsigned int *error)
{
    struct notifywatch_struct *watch=NULL;
    int result=0;

    if (! pathinfo) {

	*error=EINVAL;
	goto out;

    } else if (! pathinfo->path) {

	*error=EINVAL;
	goto out;

    } else if (! cb) {

	*error=EINVAL;
	goto out;

    } else if (get_cbmask(cb)==0) {

	*error=EINVAL;
	goto out;

    }

    watch=lookup_watch_systemwatches(pathinfo);

    if (! watch) {
        struct inode_struct *inode=NULL;

	/*
	    no watch found in the path table of system watches
	    it's possible that there is still watch set on the inode
	    translate path to inode
	*/

	watch=lookup_watch_inodetable_bypath(pathinfo->path);

    }

    if ( ! watch ) {

	logoutput("add_systemwatch: no watch found, creating one");

	watch=malloc(sizeof(struct notifywatch_struct));

	if (watch) {

	    watch->flags=NOTIFYWATCH_FLAG_SYSTEM;
	    watch->inode=NULL;
	    watch->object=NULL;
	    pthread_mutex_init(&watch->mutex, NULL);

	    watch->backend=NULL;
	    watch->cb=cb;
	    watch->data=NULL;

	    watch->notifymask=0;

	    watch->next=NULL;
	    watch->prev=NULL;

	    /* take over the path only if allocated and not inuse */

	    if ((!(pathinfo->flags & PATHINFOFLAGS_INUSE)) && (pathinfo->flags & PATHINFOFLAGS_ALLOCATED)) {

		watch->pathinfo.path=pathinfo->path;
		watch->pathinfo.len=pathinfo->len;
		watch->pathinfo.flags=PATHINFOFLAGS_INUSE | PATHINFOFLAGS_ALLOCATED;
		pathinfo->flags-=PATHINFOFLAGS_ALLOCATED;
		watch->pathinfo.flags=pathinfo->flags;

	    } else {

		watch->pathinfo.path=malloc(pathinfo->len);

		if (watch->pathinfo.path) {

		    memcpy(watch->pathinfo.path, pathinfo->path, pathinfo->len);
		    watch->pathinfo.len=pathinfo->len;
		    watch->pathinfo.flags=pathinfo->flags;
		    watch->pathinfo.flags=PATHINFOFLAGS_INUSE | PATHINFOFLAGS_ALLOCATED;

		} else {

		    logoutput("add_systemwatch: error allocating memory for path %s", pathinfo->path);
		    free(watch);
		    watch=NULL;
		    goto out;

		}

	    }

	    watch->mask=get_cbmask(cb);
	    add_watch_systemwatches(watch);

	} else {

	    logoutput("add_systemwatch: unable to allocate a watch");
	    goto out;

	}

	pthread_mutex_lock(&watch->mutex);

	/*
	    assign the backend: inotify, fssync....
	*/

	logoutput("add_systemwatch: assign watch backend");

	assign_watchbackend(watch);

	pthread_mutex_unlock(&watch->mutex);

    } else {

	/* existing watch found */

	logoutput("add_systemwatch: existing watch found on %s", pathinfo->path);

	pthread_mutex_lock(&watch->mutex);

	if ( ! (watch->flags & NOTIFYWATCH_FLAG_SYSTEM)) {
	    uint32_t current_mask=0;

	    watch->cb=cb;
	    add_watch_systemwatches(watch);

	    watch->flags |= NOTIFYWATCH_FLAG_SYSTEM;

	    current_mask=watch->mask;
	    watch->mask=get_cbmask(cb);
	    if (watch->inode) watch->mask |= watch->notifymask;

	    if (current_mask != watch->mask) (* watch->backend->change_watch) (watch);

	} else {

	    *error=EEXIST;

	}

	pthread_mutex_unlock(&watch->mutex);

    }

    out:

    logoutput("add_systemwatch: ready");

    return watch;

}

void remove_systemwatch(struct notifywatch_struct *watch)
{

    pthread_mutex_lock(&watch->mutex);

    if (watch->flags & NOTIFYWATCH_FLAG_SYSTEM) {

	watch->cb=NULL;
	remove_watch_systemwatches(watch);

	watch->flags -= NOTIFYWATCH_FLAG_SYSTEM;

    }

    if (watch->flags & NOTIFYWATCH_FLAG_NOTIFY) {
	uint32_t current_mask=watch->mask;

	watch->mask=watch->notifymask;

	if (current_mask != watch->mask) (* watch->backend->change_watch) (watch);

    } else {

	watch->mask=0;
	(* watch->backend->remove_watch) (watch);

    }

    pthread_mutex_unlock(&watch->mutex);

    if (watch->mask==0 && ! (watch->flags & NOTIFYWATCH_FLAG_NOTIFY)) {

	pthread_mutex_destroy(&watch->mutex);
	free_path_pathinfo(&watch->pathinfo);
	free(watch);

    }

}

static void remove_notifywatch_cb(void *data)
{
    struct notifywatch_struct *watch=(struct notifywatch_struct *) data;

    if (watch) {

	if (watch->backend) {

	    (* watch->backend->remove_watch) (watch);

	}

	if (watch->flags & NOTIFYWATCH_FLAG_NOTIFY) {

	    watch->flags -= NOTIFYWATCH_FLAG_NOTIFY;

	    remove_watch_inodetable(watch);
	    watch->inode=NULL;

	}

	if (watch->flags & NOTIFYWATCH_FLAG_SYSTEM) {

	    watch->cb=NULL;
	    remove_watch_systemwatches(watch);

	    watch->flags -= NOTIFYWATCH_FLAG_SYSTEM;

	}

	pthread_mutex_destroy(&watch->mutex);
	free_path_pathinfo(&watch->pathinfo);
	free(watch);

    }

}

void remove_systemwatches()
{
    struct notifywatch_struct *watch=NULL;

    pthread_mutex_lock(&systemwatches.mutex);

    watch=systemwatches.first;

    while (watch) {

	systemwatches.first=watch->next;

	remove_systemwatch(watch);

	watch=systemwatches.first;

    }

    pthread_mutex_unlock(&systemwatches.mutex);

}

void remove_notifywatches()
{

    free_group(&group_watches_inode, remove_notifywatch_cb);

}

int init_fschangenotify(unsigned int *error)
{

    *error=0;

    initialize_fsnotify_backend(error);

    if (*error==0) {
	int result=0;

	result=init_watch_hashtables();

	if (result<0) *error=abs(result);

    }

    /* set the watch backend functions for this os*/

    os_watchbackend.type=NOTIFYWATCH_BACKEND_OS;
    os_watchbackend.set_watch=set_watch_backend_os_specific;
    os_watchbackend.change_watch=change_watch_backend_os_specific;
    os_watchbackend.remove_watch=remove_watch_backend_os_specific;

    return (*error>0) ? -1 : 0;

}

void end_fschangenotify()
{

    remove_systemwatches();

    remove_notifywatches();

    close_fsnotify_backend();

}

