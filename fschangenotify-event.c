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

#include "fuse-workspace.h"
#include "workerthreads.h"
#include "beventloop-utils.h"

#include "entry-management.h"

#include "path-resolution.h"
#include "options.h"
#include "utils.h"
#include "simple-list.h"
#include "fschangenotify.h"

#include "workspaces.h"
#include "resources.h"
#include "objects.h"

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

struct fsevent_struct {
    unsigned char			status;
    unsigned char			options;
    uint32_t				mask;
    struct entry_struct			*entry;
    struct workspace_object_struct 	*object;
    struct fsevent_struct		*next;
    struct fsevent_struct		*prev;
};

static struct fsevent_struct 		*fseventqueue_first=NULL;
static struct fsevent_struct 		*fseventqueue_last=NULL;
static pthread_mutex_t 			fseventqueue_mutex = PTHREAD_MUTEX_INITIALIZER;

#define _FSEVENT_STATUS_OK			0
#define _FSEVENT_STATUS_PROCESSING		1
#define _FSEVENT_STATUS_QUEUE			2
#define _FSEVENT_STATUS_DONE			5

static void remove_entry_cb(struct entry_struct *entry)
{
    struct inode_struct *inode=entry->inode;

    if (inode) {
	struct notifywatch_struct *notifywatch=lookup_watch_inode(inode);
	struct entry_struct *parent=entry->parent;

	if (notifywatch) {
	    struct workspace_object_struct *object=notifywatch->object;

	    change_notifywatch(notifywatch, 0);

	    if (parent && object) {
		struct workspace_mount_struct *workspace=object->workspace_mount;

		notify_kernel_delete(workspace, parent->inode->ino, inode->ino, entry->name.name);

	    }

	}

    }

}

/*
    function which is run by a seperate thread
    it gets a fsevent from the queue and processes that
*/

static void process_fsevent_job(void *data)
{
    struct fsevent_struct *fsevent=NULL;

    logoutput("process_fsevent_job");

    process:

    /* get a fsevent job from queue */

    pthread_mutex_lock(&fseventqueue_mutex);

    if (fseventqueue_first) {

	fsevent=fseventqueue_first;

	if (fsevent==fseventqueue_last) {

	    fseventqueue_first=NULL;
	    fseventqueue_last=NULL;

	} else {

	    fseventqueue_first=fsevent->next;

	}

	fsevent->status=_FSEVENT_STATUS_PROCESSING;

    }

    pthread_mutex_unlock(&fseventqueue_mutex);

    if (fsevent) {
	struct entry_struct *entry=fsevent->entry;

	/*
	    here process the fsevent:
	    signal the kernel
	    process any more events like recursive removal of directory
	*/

	if (fsevent->mask & (IN_DELETE | IN_MOVED_FROM)) {
	    struct inode_struct *inode=entry->inode;

	    /* delete */

	    if (S_ISDIR(inode->mode)) {
	    	unsigned int error=0;
		struct directory_struct *subdir=get_directory(inode, 0, &error);

		/* when dealing with a directory remove it recursive */

		if (subdir) clear_directory(subdir, remove_entry_cb);

	    }

	    (* remove_entry_cb)(entry);

	    destroy_entry(entry);

	} else {

	    if (fsevent->mask & (IN_CREATE | IN_MOVED_TO)) {
		struct entry_struct *parent=entry->parent;
		struct workspace_object_struct *object=fsevent->object;

		/* create */

		if (parent && object) {
		    struct workspace_mount_struct *workspace=object->workspace_mount;

		    notify_kernel_create(workspace, parent->inode->ino, entry->name.name);

		}

	    }

	    if (fsevent->mask & (IN_ATTRIB | IN_MODIFY)) {
		struct inode_struct *inode=entry->inode;
		struct workspace_object_struct *object=fsevent->object;

		/* change */

		if (object) {
		    struct workspace_mount_struct *workspace=object->workspace_mount;

		    notify_kernel_change(workspace, inode->ino, fsevent->mask);

		}

	    }

	}

	fsevent=NULL;
	goto process;	

    }

}

/*
    function which is called when the fssync timerentry expires
    it puts the fssync job on a "todo" queue
    when the status is CANCEL, clean up the fssync job
    when the status is different (QUEUE, RUNNING) then do nothing
*/

static void queue_fsevent(struct fsevent_struct *fsevent)
{
    unsigned int error=0;

    logoutput("queue_fsevent");

    /*
	only queue fsevent when ok
    */

    if (fsevent->status==_FSEVENT_STATUS_OK) {

	/* queue on jobs to do */

	pthread_mutex_lock(&fseventqueue_mutex);

	if (! fseventqueue_last) {

	    fseventqueue_last=fsevent;
	    fseventqueue_first=fsevent;

	} else {

	    fseventqueue_last->next=fsevent;
	    fseventqueue_last=fsevent;

	}

	fsevent->status=_FSEVENT_STATUS_QUEUE;

	pthread_mutex_unlock(&fseventqueue_mutex);

	/*
	    here make a thread process the queue
	    do not wait for a thread to become available
	    a job on the thread queue will be created and
	    picked up asap
	*/

	work_workerthread(&workerthreads_queue, -1, process_fsevent_job, NULL, &error);

	if (error==EAGAIN) {

	    logoutput_error("queue_fsevent: no thread available to process the fsevent queue direct");

	}

    } else if (fsevent->status==_FSEVENT_STATUS_QUEUE) {

	/* already on queue, actually not possible */

	logoutput_error("queue_fsevent: fsevent already on queue");

    } else if (fsevent->status==_FSEVENT_STATUS_PROCESSING) {

	/* already on running, actually not possible */

	logoutput_error("queue_fsevent: fsevent already running");

    } else {

	logoutput_error("queue_fsevent: fsevent done");

	fsevent->status=_FSEVENT_STATUS_DONE;

    }

    if (fsevent->status==_FSEVENT_STATUS_DONE) {

	free(fsevent);

    }

}

int queue_remove(struct workspace_object_struct *object, struct entry_struct *entry, unsigned int *error)
{
    struct fsevent_struct *fsevent=NULL;

    fsevent=malloc(sizeof(struct fsevent_struct));

    if (fsevent) {

	fsevent->status=_FSEVENT_STATUS_OK;
	fsevent->object=object;
	fsevent->options=0;
	fsevent->mask=IN_DELETE;
	fsevent->entry=entry;
	fsevent->next=NULL;
	fsevent->prev=NULL;

	queue_fsevent(fsevent);

    } else {

	*error=ENOMEM;
	return -1;

    }

    return 0;

}

int queue_create(struct workspace_object_struct *object, struct entry_struct *entry, unsigned int *error)
{
    struct fsevent_struct *fsevent=NULL;

    fsevent=malloc(sizeof(struct fsevent_struct));

    if (fsevent) {

	fsevent->status=_FSEVENT_STATUS_OK;
	fsevent->object=object;
	fsevent->options=0;
	fsevent->mask=IN_CREATE;
	fsevent->entry=entry;
	fsevent->next=NULL;
	fsevent->prev=NULL;

	queue_fsevent(fsevent);

    } else {

	*error=ENOMEM;
	return -1;

    }

    return 0;

}

int queue_change(struct workspace_object_struct *object, struct entry_struct *entry, uint32_t mask, unsigned int *error)
{
    struct fsevent_struct *fsevent=NULL;

    fsevent=malloc(sizeof(struct fsevent_struct));

    if (fsevent) {

	fsevent->status=_FSEVENT_STATUS_OK;
	fsevent->object=object;
	fsevent->options=0;
	fsevent->mask=mask;
	fsevent->entry=entry;
	fsevent->next=NULL;
	fsevent->prev=NULL;

	queue_fsevent(fsevent);

    } else {

	*error=ENOMEM;
	return -1;

    }

    return 0;

}
