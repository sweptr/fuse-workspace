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

#ifndef ENOATTR
#define ENOATTR ENODATA        /* No such attribute */
#endif

#define WATCHES_TABLESIZE          1024

#include "workerthreads.h"
#include "beventloop-utils.h"

#include "entry-management.h"

#include "skiplist.h"
#include "skiplist-utils.h"
#include "skiplist-delete.h"
#include "skiplist-find.h"
#include "skiplist-insert.h"

#include "path-resolution.h"
#include "options.h"
#include "fschangenotify.h"
#include "utils.h"
#include "simple-list.h"
#include "handlefuseevent.h"

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

extern struct overlayfs_options_struct overlayfs_options;

unsigned long watchctr = 1;
pthread_mutex_t watchctr_mutex=PTHREAD_MUTEX_INITIALIZER;

static struct simple_group_struct group_watches_inode;
static struct simple_group_struct group_watches_ctr;

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

static unsigned int calculate_inode_hash(struct inode_struct *inode)
{
    return inode->ino % group_watches_inode.len;
}

static int inode_hashfunction(void *data)
{
    struct notifywatch_struct *watch=(struct notifywatch_struct *) data;
    if (watch->inode) return calculate_inode_hash(watch->inode);
    return 0;
}

struct notifywatch_struct *lookup_watch_inode(struct inode_struct *inode)
{
    unsigned int hashvalue=calculate_inode_hash(inode);
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
    functions to lookup the watch using the (unique) ctr
*/

static unsigned int calculate_ctr_hash(unsigned int ctr)
{
    return ctr % group_watches_ctr.len;
}

static int ctr_hashfunction(void *data)
{
    struct notifywatch_struct *watch=(struct notifywatch_struct *) data;
    return calculate_ctr_hash(watch->ctr);
}

struct notifywatch_struct *lookup_watch_ctr(unsigned int ctr)
{
    unsigned int hashvalue=calculate_ctr_hash(ctr);
    void *index=NULL;
    struct notifywatch_struct *watch=NULL;

    watch=(struct notifywatch_struct *) get_next_element(&group_watches_ctr, &index, hashvalue);

    while(watch) {

	if (watch->ctr==ctr) break;
	watch=(struct notifywatch_struct *) get_next_element(&group_watches_ctr, &index, hashvalue);

    }

    return watch;

}

void add_watch_ctrtable(struct notifywatch_struct *watch)
{
    add_element_to_group(&group_watches_ctr, (void *) watch);
}

void remove_watch_ctrtable(struct notifywatch_struct *watch)
{
    remove_element_from_group(&group_watches_ctr, (void *) watch);
}

int init_watch_hashtables()
{
    int result=0;
    unsigned int error=0;

    result=initialize_group(&group_watches_inode, inode_hashfunction, 256, &error);

    if (result<0) goto out;

    result=initialize_group(&group_watches_ctr, ctr_hashfunction, 256, &error);

    out:

    return result;

}

struct notifywatch_struct *add_notifywatch(struct inode_struct *inode, uint32_t mask, struct pathinfo_struct *pathinfo)
{
    struct notifywatch_struct *watch=NULL;
    unsigned char watchcreated=0;
    int result=0;

    watch=lookup_watch_inode(inode);

    if (pathinfo->path) {

	/* possible here compare the pathinfo->path with the one stored in watch->pathinfo.path*/

	logoutput("add_watch: on %s mask %i", pathinfo->path, (int) mask);

    } else {

	if (! watch) {

	    logoutput("add_watch: on UNKNOWN path, path is required");
	    goto out;

	}

    }

    if ( ! watch ) {

	logoutput("add_watch: no watch found, creating one");

	watch=malloc(sizeof(struct notifywatch_struct));

	if (watch) {

	    watch->inode=inode;
	    watch->mask=mask;
	    pthread_mutex_init(&watch->mutex, NULL);
	    watch->backend=NULL;

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

		    logoutput("add_watch: error allocating memory for path %s", pathinfo->path);
		    free(watch);
		    watch=NULL;
		    goto out;

		}

	    }

	    add_watch_inodetable(watch);
	    add_watch_ctrtable(watch);

	} else {

	    logoutput("add_clientwatch: unable to allocate a watch");
	    goto out;

	}

    } else {

	/* existing watch found */

	logoutput("add_clientwatch: existing watch found on %s", pathinfo->path);

    }

    pthread_mutex_lock(&watch->mutex);

    /* dealing with a normal filesystem */

    result=set_watch_backend_os_specific(watch);

    if (result==-EACCES) {

	logoutput("add_clientwatch: no access to %s", pathinfo->path);

    } else if (result<0) {

	logoutput("add_clientwatch: error %i setting watch on %s", abs(result), pathinfo->path);

    }

    unlock:

    pthread_mutex_unlock(&watch->mutex);

    out:

    return watch;

}

/* change/remove a watch */

void change_notifywatch(struct notifywatch_struct *watch)
{

    pthread_mutex_lock(&watch->mutex);

    if (watch->mask==0) {

	remove_watch_backend_os_specific(watch);

	remove_watch_inodetable(watch);
	remove_watch_ctrtable(watch);

    } else {

	change_watch_backend_os_specific(watch);

    }

    pthread_mutex_unlock(&watch->mutex);

    if (watch->mask==0) {

	pthread_mutex_destroy(&watch->mutex);
	free(watch);

    }

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

    return (*error>0) ? -1 : 0;

}

void end_fschangenotify()
{

    close_fsnotify_backend();

}

