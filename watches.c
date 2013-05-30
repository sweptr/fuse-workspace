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
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/epoll.h>

#ifdef HAVE_INOTIFY
#include <sys/inotify.h>
#endif

#include <pthread.h>

#ifndef ENOATTR
#define ENOATTR ENODATA        /* No such attribute */
#endif

#define LOG_LOGAREA LOG_LOGAREA_WATCHES

#define WATCHES_TABLESIZE          1024

#include <fuse/fuse_lowlevel.h>

#include "logging.h"
#include "epoll-utils.h"
#include "notifyfs-fsevent.h"

#include "workerthreads.h"

#include "entry-management.h"
#include "path-resolution.h"
#include "options.h"
// #include "message.h"
// #include "client.h"
#include "watches.h"
#include "changestate.h"
#include "utils.h"
//#include "socket.h"

#ifdef HAVE_INOTIFY
#include "watches-backend-inotify.c"
#else
#include "watches-backend-inotify-notsup.c"
#endif

struct watch_struct *first_watch;
struct watch_struct *last_watch;
struct watch_struct *watch_table[WATCHES_TABLESIZE];

unsigned long watchctr = 1;
struct watch_struct *watch_list=NULL;
pthread_mutex_t watchctr_mutex=PTHREAD_MUTEX_INITIALIZER;

extern const char *rootpath;

void lock_watch(struct watch_struct *watch)
{
    pthread_mutex_lock(&watch->mutex);
}

void unlock_watch(struct watch_struct *watch)
{
    pthread_mutex_unlock(&watch->mutex);
}


void init_watch_hashtables()
{
    int i;

    for (i=0;i<WATCHES_TABLESIZE;i++) {

	watch_table[i]=NULL;

    }

}

/* here some function to lookup the eff watch, given the mount entry */

void add_watch_to_table(struct watch_struct *watch)
{
    int hash=watch->inode->ino%WATCHES_TABLESIZE;

    if ( watch_table[hash] ) watch_table[hash]->prev_hash=watch;
    watch->next_hash=watch_table[hash];
    watch_table[hash]=watch;

}

void remove_watch_from_table(struct watch_struct *watch)
{
    int hash=watch->inode->ino%WATCHES_TABLESIZE;

    if ( watch_table[hash]==watch ) watch_table[hash]=watch->next_hash;
    if ( watch->next_hash ) watch->next_hash->prev_hash=watch->prev_hash;
    if ( watch->prev_hash ) watch->prev_hash->next_hash=watch->next_hash;

}

/* simple lookup function of watch */

struct watch_struct *lookup_watch_inode(struct inode_struct *inode)
{
    struct watch_struct *watch=NULL;
    int hash=inode->ino%WATCHES_TABLESIZE;

    /* lookup using the ino */

    watch=watch_table[hash];

    while(watch) {

	if (watch->inode==inode) break;

	watch=watch->next_hash;

    }

    return watch;

}

struct watch_struct *lookup_watch_list(unsigned long ctr)
{
    struct watch_struct *watch=NULL;

    /* lookup using the ctr */

    pthread_mutex_lock(&watchctr_mutex);

    watch=watch_list;

    while(watch) {

	if (watch->ctr==ctr) break;

	watch=watch->next;

    }

    pthread_mutex_unlock(&watchctr_mutex);

    return watch;

}



void add_watch_to_list(struct watch_struct *watch)
{

    pthread_mutex_lock(&watchctr_mutex);

    if (watch_list) watch_list->prev=watch;
    watch->next=watch_list;
    watch->prev=NULL;
    watch_list=watch;

    watchctr++;

    watch->ctr=watchctr;

    pthread_mutex_unlock(&watchctr_mutex);

}

void remove_watch_from_list(struct watch_struct *watch)
{

    pthread_mutex_lock(&watchctr_mutex);

    if (watch->next) watch->next->prev=watch->prev;
    if (watch->prev) watch->prev->next=watch->next;

    if (watch_list==watch) watch_list=watch->next;

    pthread_mutex_unlock(&watchctr_mutex);

}

void set_watch_backend_os_specific(struct watch_struct *watch)
{
    set_watch_backend_inotify(watch);
}

void change_watch_backend_os_specific(struct watch_struct *watch)
{
    change_watch_backend_inotify(watch);
}

void remove_watch_backend_os_specific(struct watch_struct *watch)
{
    remove_watch_backend_inotify(watch);
}



int add_clientwatch(struct inode_struct *inode, struct fseventmask_struct *fseventmask, int id, struct pathinfo_struct *pathinfo)
{
    struct watch_struct *watch=NULL;
    unsigned char watchcreated=0;
    int nreturn=0;

    if (pathinfo) {

	if (pathinfo->path) {

	    logoutput("add_clientwatch: on %s id %i, %i:%i:%i:%i", pathinfo->path, id, fseventmask->attrib_event, fseventmask->xattr_event, fseventmask->file_event, fseventmask->move_event);

	} else {

	    logoutput("add_clientwatch: path not set for watch id %i", id);

	}

    } else {

	logoutput("add_clientwatch: path not set for watch id %i", id);

    }

    watch=lookup_watch_inode(inode);

    if ( ! watch ) {

	if (! pathinfo) {

	    logoutput("add_clientwatch: no watch found, and path not set, cannot continue");
	    nreturn=-EINVAL;
	    goto out;

	} else if (! pathinfo->path) {

	    logoutput("add_clientwatch: no watch found, and path not set, cannot continue");
	    nreturn=-EINVAL;
	    goto out;

	}

	logoutput("add_clientwatch: no watch found, creating one");

	watch=malloc(sizeof(struct watch_struct));

	if (watch) {

	    watch->ctr=0;
	    watch->inode=inode;
	    watch->owner_watch_id=id;

	    watch->pathinfo.flags=0;
	    watch->pathinfo.path=pathinfo->path;
	    watch->pathinfo.len=pathinfo->len;

	    /* take over the path only if allocated and not inuse */

	    if ((!(pathinfo->flags & PATHINFOFLAGS_INUSE)) && (pathinfo->flags & PATHINFOFLAGS_ALLOCATED)) {

		watch->pathinfo.flags=PATHINFOFLAGS_INUSE || PATHINFOFLAGS_ALLOCATED;
		pathinfo->flags-=PATHINFOFLAGS_ALLOCATED;

	    }

	    watch->fseventmask.attrib_event=0;
	    watch->fseventmask.xattr_event=0;
	    watch->fseventmask.file_event=0;
	    watch->fseventmask.move_event=0;
	    watch->fseventmask.fs_event=0;

	    pthread_mutex_init(&watch->mutex, NULL);

	    watch->next_hash=NULL;
	    watch->prev_hash=NULL;

	    watch->next=NULL;
	    watch->prev=NULL;

	    add_watch_to_table(watch);
	    add_watch_to_list(watch);

	    watchcreated=1;

	} else {

	    logoutput("add_clientwatch: unable to allocate a watch");
	    goto out;

	}

    }

    pthread_mutex_lock(&watch->mutex);

    if ( merge_fseventmasks(&watch->fseventmask, fseventmask)==1) {

	set_watch_backend_os_specific(watch);

    }

    pthread_mutex_unlock(&watch->mutex);

    out:

    return nreturn;

}


void initialize_fsnotify_backends()
{
    initialize_inotify();
}

void close_fsnotify_backends()
{
    close_inotify();
}

