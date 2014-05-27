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
#include <sys/vfs.h>

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
#include "readdir-utils.h"

#include "workspaces.h"
#include "objects.h"

#include "fschangenotify.h"
#include "fschangenotify-fssync.h"
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

#define _FSSYNC_STATUS_OK			0
#define _FSSYNC_STATUS_SCHEDULED		1
#define _FSSYNC_STATUS_RUNNING			2
#define _FSSYNC_STATUS_CANCEL			3
#define _FSSYNC_STATUS_QUEUE			4
#define _FSSYNC_STATUS_DONE			5

struct fssync_struct {
    struct timespec				schedule;
    unsigned short 				lapse;
    struct notifywatch_struct			*watch;
    unsigned char 				status;
    struct timerentry_struct 			*timerentry;
    struct fssync_struct			*next;
};

struct fssynccb_struct {
    void (* create)(struct workspace_object_struct *object, struct entry_struct *entry, uint32_t fssync_mask);
    void (* change)(struct workspace_object_struct *object, struct entry_struct *entry, uint32_t event_mask, uint32_t fssync_mask);
    void (* remove)(struct workspace_object_struct *object, struct entry_struct *entry, uint32_t fssync_mask);
};

static struct simple_group_struct group_fssync_watch;

static struct fssync_struct *fssyncqueue_first=NULL;
static struct fssync_struct *fssyncqueue_last=NULL;
static unsigned int fssyncqueue_nr=0;

static pthread_mutex_t fssyncqueue_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t fssyncprocess_mutex = PTHREAD_MUTEX_INITIALIZER;

struct watchbackend_struct fssync_watchbackend = {0, NULL, NULL, NULL};

/*
    function to synchronize the cache with the backend
    full sync
    typically called when not synced before
*/

static void synchronize_directory_full(struct workspace_object_struct *object, struct entry_struct *parent, struct directory_struct *directory, unsigned int fd, struct readdir_struct *readdir, struct timespec *synctime, unsigned int len, struct fssynccb_struct *fssynccb, uint32_t fssync_mask, unsigned int *error)
{
    struct name_struct xname={NULL, 0, 0};
    unsigned char dtype=0;
    int res;
    struct stat st;
    struct entry_struct *entry=NULL, *result=NULL;
    struct inode_struct *inode;

    while(1) {

	res=(* readdir->get_direntry)(readdir, &xname, &dtype, error);

	if (res<=0) {

	    if (res<0) logoutput_error("synchronize_directory_full: error %i reading directory", *error);
	    break;

	}

	if (fstatat(fd, xname.name, &st, AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT)==-1) continue;

	xname.len=strlen(xname.name);
	calculate_nameindex(&xname);

	entry=create_entry(parent, &xname);
	inode=create_inode();

	*error=0;

	if (entry && inode) {

	    result=insert_entry_batch(directory, entry, error, 0);

	    if (result==entry) {

		/* new entry */

		memcpy(&entry->synctime, synctime, sizeof(struct timespec));

		entry->inode=inode;
		inode->alias=entry;

		add_inode_hashtable(inode, increase_inodes_workspace, (void *) object->workspace_mount);

		adjust_pathmax(len + 1 + xname.len);

		inode->nlookup=1;
		inode->mode=st.st_mode;
		inode->nlink=st.st_nlink;
		inode->uid=st.st_uid;
		inode->gid=st.st_gid;

		inode->rdev = st.st_rdev;

		inode->mtim.tv_sec = st.st_mtim.tv_sec;
		inode->mtim.tv_nsec = st.st_mtim.tv_nsec;
		inode->ctim.tv_sec = st.st_ctim.tv_sec;
		inode->ctim.tv_nsec = st.st_ctim.tv_nsec;

		if (! S_ISDIR(st.st_mode)) inode->size=st.st_size;

		(* fssynccb->create)(object, entry, fssync_mask);

	    } else {

		/* result != entry */

		if (*error==EEXIST) {
		    uint32_t event_mask=0;

		    free(entry);
		    entry=result;

		    free(inode);
		    inode=entry->inode;

		    event_mask=determine_fsnotify_mask(inode, &st);
		    memcpy(&entry->synctime, synctime, sizeof(struct timespec));

		    (* fssynccb->change)(object, entry, event_mask, fssync_mask);

		} else {

		    destroy_entry(entry);
		    entry=NULL;

		    free(inode);
		    inode=NULL;

		    break;

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

	    *error=ENOMEM;
	    break;

	}

    }

    if (*error>0) {

	logoutput_error("synchronize_directory_full: error %i:%s", *error, strerror(*error));

    }

}

/*
    function to synchronize the cache with the backend
    simple sync
    typically called when synced before, but changed after that (entry added and/or removed)
*/

static void synchronize_directory_simple(struct workspace_object_struct *object, struct entry_struct *parent, struct directory_struct *directory, unsigned int fd, struct readdir_struct *readdir, struct timespec *synctime, unsigned int len, struct fssynccb_struct *fssynccb, uint32_t fssync_mask, unsigned int *error)
{
    struct name_struct xname={NULL, 0, 0};
    unsigned char dtype=0;
    int res;
    struct stat st;
    struct entry_struct *entry=NULL, *result=NULL;
    struct inode_struct *inode;

    while(1) {

	res=(* readdir->get_direntry)(readdir, &xname, &dtype, error);

	if (res<=0) {

	    if (res<0) logoutput_error("synchronize_directory_simple: error %i reading directory", *error);

	    (*readdir->close)(readdir);
	    break;

	}

	if (fstatat(fd, xname.name, &st, AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT)==-1) continue;

	xname.len=strlen(xname.name);
	calculate_nameindex(&xname);
	*error=0;

	entry=find_entry_batch(directory, &xname, error);

	if (! entry) {

	    entry=create_entry(parent, &xname);
	    inode=create_inode();

	    *error=0;

	    if (entry && inode) {

		result=insert_entry_batch(directory, entry, error, 0);

		if (result==entry) {

		    /* new entry */

		    memcpy(&entry->synctime, synctime, sizeof(struct timespec));

		    entry->inode=inode;
		    inode->alias=entry;

		    add_inode_hashtable(inode, increase_inodes_workspace, (void *) object->workspace_mount);

		    adjust_pathmax(len + 1 + xname.len);

		    inode->nlookup=1;
		    inode->mode=st.st_mode;
		    inode->nlink=st.st_nlink;
		    inode->uid=st.st_uid;
		    inode->gid=st.st_gid;

		    inode->rdev = st.st_rdev;

		    inode->mtim.tv_sec = st.st_mtim.tv_sec;
		    inode->mtim.tv_nsec = st.st_mtim.tv_nsec;
		    inode->ctim.tv_sec = st.st_ctim.tv_sec;
		    inode->ctim.tv_nsec = st.st_ctim.tv_nsec;

		    if (! S_ISDIR(st.st_mode)) inode->size=st.st_size;

		    (* fssynccb->create)(object, entry, fssync_mask);

		} else {

		    /* result != entry */

		    if (*error==EEXIST) {
			uint32_t event_mask=0;

			free(entry);
			entry=result;

			free(inode);
			inode=entry->inode;

			event_mask=determine_fsnotify_mask(inode, &st);
			memcpy(&entry->synctime, synctime, sizeof(struct timespec));

			(* fssynccb->change)(object, entry, event_mask, fssync_mask);

		    } else {

			destroy_entry(entry);
			entry=NULL;

			free(inode);
			inode=NULL;

			break;

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

		*error=ENOMEM;
		break;

	    }

	} else {
	    uint32_t event_mask=0;

	    free(entry);
	    entry=result;

	    free(inode);
	    inode=entry->inode;

	    event_mask=determine_fsnotify_mask(inode, &st);
	    memcpy(&entry->synctime, synctime, sizeof(struct timespec));

	    (* fssynccb->change)(object, entry, event_mask, fssync_mask);

	}

    }

    if (*error>0) {

	logoutput_error("synchronize_directory_full: error %i:%s", *error, strerror(*error));

    }

}

/*
    function to synchronize the cache with the backend
    virtual sync
    typically called when the directory is not modified (no entries removed and added)
*/

static void synchronize_directory_virtual(struct workspace_object_struct *object, struct entry_struct *parent, struct directory_struct *directory, unsigned int fd, struct timespec *synctime, struct fssynccb_struct *fssynccb, uint32_t fssync_mask, unsigned int *error)
{
    struct name_struct *xname=NULL;
    struct stat st;
    struct entry_struct *entry=NULL;
    struct inode_struct *inode;

    entry=directory->first;

    while (entry) {

	inode=entry->inode;
	xname=&entry->name;

	if (fstatat(fd, xname->name, &st, AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT)==-1) {
	    struct entry_struct *next=entry->name_next;

	    /* remove from directory */

	    remove_entry_batch(directory, entry, error);

	    (* fssynccb->remove)(object, entry, fssync_mask);

	    entry=next;

	} else {
	    uint32_t event_mask=0;

	    event_mask=determine_fsnotify_mask(inode, &st);
	    memcpy(&entry->synctime, synctime, sizeof(struct timespec));

	    (* fssynccb->change)(object, entry, event_mask, fssync_mask);

	    entry=entry->name_next;

	}

    }

}

void remove_entries_notfound(struct workspace_object_struct *object, struct directory_struct *directory, struct timespec *synctime, struct fssynccb_struct *fssynccb, uint32_t sync_mask)
{
    struct entry_struct *entry=NULL;

    logoutput("remove_entries_notfound: synctime %li:%li", synctime->tv_sec, synctime->tv_nsec);

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

	    remove_entry_batch(directory, entry, &error);

	    (* fssynccb->remove)(object, entry, sync_mask);

	    entry=next;

	} else {

	    entry=entry->name_next;

	}

    }

}

/*
    generic function to synchronize the directory
    it checks what synchronize function to call (which will do the work)
*/

static void synchronize_directory(struct inode_struct *pinode, struct fssynccb_struct *fssynccb, uint32_t fsnotify_mask, char *path, unsigned int len, struct workspace_object_struct *object)
{
    struct directory_struct *directory=NULL;
    unsigned int error=0;
    int fd=-1;

    directory=get_directory(pinode, 1, &error);

    if (directory) {
	struct entry_struct *parent=pinode->alias;
	struct statfs stfs;
	struct timespec synctime;

	fd=open(path, O_RDONLY | O_DIRECTORY);

	if (fd==-1) {

	    error=errno;
	    goto out;

	}

	if (fstatfs(fd, &stfs)==-1) {

	    error=errno;
	    goto out;

	}

	if (lock_directory(directory, _DIRECTORY_LOCK_EXCL)==-1) {

	    error=EAGAIN;
	    goto out;

	}

	get_current_time(&synctime);

	if (stfs.f_bfree==0) {
	    struct readdir_struct *readdir=NULL;
	    unsigned int count=directory->count;
	    uint32_t sync_mask=0;

	    /*
		dealing with a system filesystem
		- use readdir
	    */

	    readdir=init_readdir_readdir(path, fd, &error);

	    if (! readdir) {

		if (error==0) error=EIO;
		goto unlock;

	    }

	    /* when dealing with a system fs only look at the most basic events */

	    if (fsnotify_mask & (IN_CREATE | IN_MOVED_TO)) sync_mask |= IN_CREATE;
	    if (fsnotify_mask & (IN_DELETE | IN_MOVED_FROM)) sync_mask |= IN_DELETE;

	    error=0;

	    if (directory->synctime.tv_sec==0 && directory->synctime.tv_nsec==0) {

		/*
		    never synced before: full sync
		*/

		synchronize_directory_full(object, parent, directory, fd, readdir, &synctime, len, fssynccb, sync_mask, &error);

	    } else {

		/*
		    synced before and use (cause of system fs) simple sync
		*/

		synchronize_directory_simple(object, parent, directory, fd, readdir, &synctime, len, fssynccb, sync_mask, &error);

	    }

	    (*readdir->close)(readdir);

	    if (error==0 && count>0) remove_entries_notfound(object, directory, &synctime, fssynccb, sync_mask);

	} else if (directory->synctime.tv_sec==0 && directory->synctime.tv_nsec==0) {
	    struct readdir_struct *readdir=NULL;
	    unsigned int count=directory->count;

	    /*
		dealing with a normal filesystem and never synced before:
		- use getdents and full sync
	    */

	    readdir=init_readdir_getdents(path, fd, &error);

	    if (! readdir) {

		if (error==0) error=EIO;
		goto unlock;

	    }

	    error=0;

	    synchronize_directory_full(object, parent, directory, fd, readdir, &synctime, len, fssynccb, fsnotify_mask, &error);
	    (*readdir->close)(readdir);

	    if (error==0 && count>0) remove_entries_notfound(object, directory, &synctime, fssynccb, fsnotify_mask);

	} else {
	    struct stat st;

	    if (fstat(fd, &st)==-1) {

		error=errno;
		goto unlock;

	    }

	    if (st.st_mtim.tv_sec > directory->synctime.tv_sec || 
		    (st.st_mtim.tv_sec==directory->synctime.tv_sec && st.st_mtim.tv_nsec>directory->synctime.tv_nsec)) {
		struct readdir_struct *readdir=NULL;
		unsigned int count=directory->count;

		/*
		    dealing with a normal filesystem and never synced before:
		    - use getdents
		    - directory is changed since last sync: use simple sync
		*/

		readdir=init_readdir_getdents(path, fd, &error);

		if (! readdir) {

		    if (error==0) error=EIO;
		    goto unlock;

		}

		error=0;

		synchronize_directory_simple(object, parent, directory, fd, readdir, &synctime, len, fssynccb, fsnotify_mask, &error);
		(*readdir->close)(readdir);

		if (error==0 && count>0) remove_entries_notfound(object, directory, &synctime, fssynccb, fsnotify_mask);

	    } else {

		/*
		    dealing with a normal filesystem and synced before:
		    - directory is not changed since last sync: use virtual sync
		*/

		error=0;
		synchronize_directory_virtual(object, parent, directory, fd, &synctime, fssynccb, fsnotify_mask, &error);

	    }

	}

	unlock:

	if (unlock_directory(directory, _DIRECTORY_LOCK_EXCL)==-1) {

	    logoutput("synchronize_directory: error unlocking directory EXCL");

	}

    }

    out:

    if (error>0) logoutput("synchronize_directory: error %i:%s", error, strerror(error));

    if (fd>0) {

	close(fd);
	fd=-1;

    }

}

/*
    function which called during the synchronization of a directory when an entry is created
*/

void fssync_create_entry_cb(struct workspace_object_struct *object, struct entry_struct *entry, uint32_t mask)
{
    unsigned int error=0;

    if (mask & IN_CREATE) queue_create(object, entry, &error);

}

void fssync_create_entry_cb_ignore(struct workspace_object_struct *object, struct entry_struct *entry, uint32_t mask)
{
}

/*
    function which called during the synchronization of a directory when an entry is changed
*/

void fssync_change_entry_cb(struct workspace_object_struct *object, struct entry_struct *entry, uint32_t event_mask, uint32_t mask)
{
    unsigned int error=0;

    if (mask & (IN_ATTRIB | IN_MODIFY)) queue_change(object, entry, event_mask, &error);

}

void fssync_change_entry_cb_ignore(struct workspace_object_struct *object, struct entry_struct *entry, uint32_t event_mask, uint32_t mask)
{
}

/*
    function which called during the synchronization of a directory when an entry is removed
*/

void fssync_remove_entry_cb(struct workspace_object_struct *object, struct entry_struct *entry, uint32_t mask)
{
    unsigned int error=0;

    if (mask & (IN_DELETE | IN_MOVED_FROM)) queue_remove(object, entry, &error);
}

void fssync_remove_entry_cb_ignore(struct workspace_object_struct *object, struct entry_struct *entry, uint32_t mask)
{
}

static void run_fssync(void *data);

/*
    function which is run by a seperate thread
    it gets a fssync job from the fssync queue
    to synchronize a directory
*/

static void process_fssync_job(void *data)
{
    struct fssync_struct *fssync=NULL;

    logoutput("process_fssync_job");

    process:

    /* get a fssync job from queue */

    pthread_mutex_lock(&fssyncqueue_mutex);

    if (fssyncqueue_first) {

	fssync=fssyncqueue_first;

	if (fssync==fssyncqueue_last) {

	    fssyncqueue_first=NULL;
	    fssyncqueue_last=NULL;

	} else {

	    fssyncqueue_first=fssync->next;

	}

	fssync->status=_FSSYNC_STATUS_RUNNING;

    }

    pthread_mutex_unlock(&fssyncqueue_mutex);

    if (fssync) {
	struct notifywatch_struct *watch=fssync->watch;
	struct inode_struct *inode=watch->inode;
	struct entry_struct *entry=inode->alias;

	/* here test the watch and inode is still valid ?*/

	if (entry) {

	    logoutput("process_fssync_job: %s", entry->name.name);

	    /*
		when dealing with a directory:
		synchronize directory and create fsevents when nessecary
	    */

	    if (S_ISDIR(inode->mode)) {
		struct fssynccb_struct fssynccb={NULL, NULL, NULL};

		/* synchronize using special functions */

		if (fssync->timerentry) {

		    /*
			when called from (expired) timerentry
			use the normal fssync callbacks to process the changes
		    */

		    fssynccb.create=fssync_create_entry_cb;
		    fssynccb.change=fssync_change_entry_cb;
		    fssynccb.remove=fssync_remove_entry_cb;

		} else {

		    /*
			when called without timerentry
			use the "do nothing" callbacks
			this is the case when synchronized for the first time
		    */

		    fssynccb.create=fssync_create_entry_cb_ignore;
		    fssynccb.change=fssync_change_entry_cb_ignore;
		    fssynccb.remove=fssync_remove_entry_cb;

		}

		synchronize_directory(inode, &fssynccb, watch->mask, watch->pathinfo.path, watch->pathinfo.len, watch->object);

	    }

	}

	if (fssync->status==_FSSYNC_STATUS_RUNNING) {

	    if (fssync->timerentry) {

		/* reschedule */

		get_current_time(&fssync->schedule);
		fssync->schedule.tv_sec+=fssync->lapse;

		fssync->status=_FSSYNC_STATUS_OK;

		logoutput("process_fssync_job: reschedule");

		reschedule_timerentry(fssync->timerentry, &fssync->schedule);

		fssync->status=_FSSYNC_STATUS_SCHEDULED;

	    } else {

		get_current_time(&fssync->schedule);
		fssync->schedule.tv_sec+=fssync->lapse;

		fssync->timerentry=create_timerentry(&fssync->schedule, run_fssync, (void *) fssync, NULL);

		if (fssync->timerentry) {

		    fssync->status=_FSSYNC_STATUS_SCHEDULED;

		} else {

		    /* unable to create a timerentry on the eventloop */

		    free(fssync);
		    fssync=NULL;

		    watch->data=NULL;
		    goto process;

		}

	    }

	} else {

	    if (fssync->timerentry) {

		remove_timerentry(fssync->timerentry);
		fssync->timerentry=NULL;

	    }

	    free(fssync);
	    watch->data=NULL;

	}

	fssync=NULL;
	goto process;

    }

}

/*
    function which is called when the fssync timerentry expires
    it puts the fssync job on a "todo" queue
    when the status is CANCEL, clean up the fssync job
    when the status is different (QUEUE, RUNNING) then do nothing
*/

static void run_fssync(void *data)
{
    struct fssync_struct *fssync=(struct fssync_struct *) data;
    unsigned int error=0;

    logoutput("run_fssync");

    /*
	only queue fssync when ok
	TODO also test watch and inode
    */

    if (fssync->status==_FSSYNC_STATUS_SCHEDULED || fssync->status==_FSSYNC_STATUS_OK) {

	logoutput("run_fssync: put fssync job on queue");

	/* queue on jobs to do */

	pthread_mutex_lock(&fssyncqueue_mutex);

	if (! fssyncqueue_last) {

	    fssyncqueue_last=fssync;
	    fssyncqueue_first=fssync;

	} else {

	    fssyncqueue_last->next=fssync;
	    fssyncqueue_last=fssync;

	}

	fssync->status=_FSSYNC_STATUS_QUEUE;

	fssyncqueue_nr++;

	pthread_mutex_unlock(&fssyncqueue_mutex);

	/*
	    here make a thread process the queue
	    do not wait for a thread to become available
	    a job on the thread queue will be created and
	    picked up asap
	*/

	work_workerthread(&workerthreads_queue, -1, process_fssync_job, NULL, &error);

	if (error==EAGAIN) {

	    logoutput_error("run_fssync: no thread available to process the fssync queue direct");

	} else {

	    logoutput_error("run_fssync: thread started");

	}

    } else if (fssync->status==_FSSYNC_STATUS_QUEUE) {

	/* already on queue, actually not possible */

	logoutput_error("run_fssync: fssync already on queue");

    } else if (fssync->status==_FSSYNC_STATUS_RUNNING) {

	/* already on running, actually not possible */

	logoutput_error("run_fssync: fssync already running");

    } else {

	logoutput_error("run_fssync: fssync done");

	fssync->status=_FSSYNC_STATUS_DONE;

    }

    if (fssync->status==_FSSYNC_STATUS_DONE) {
	struct notifywatch_struct *watch=fssync->watch;

	if (fssync->timerentry) {

	    remove_timerentry(fssync->timerentry);
	    fssync->timerentry=NULL;

	}

	free(fssync);
	watch->data=NULL;

    }

}

/*
    schedule a fssync job for a watch in future
*/

static int schedule_fssync(struct notifywatch_struct *watch, unsigned short synclapse, unsigned int *error)
{
    struct fssync_struct *fssync=NULL;
    int result=0;

    logoutput("schedule_fssync");

    pthread_mutex_lock(&fssyncprocess_mutex);

    /*
	test the parameters
    */

    if (synclapse<=0 || ! watch) {

	*error=EINVAL;
	result = -1;
	goto unlock;

    }

    /*
	test the fssync is already scheduled
    */

    if (watch->backend) {

	if (watch->backend->type==NOTIFYWATCH_BACKEND_FSSYNC) {

	    fssync=(struct fssync_struct *) watch->data;

	    if (fssync) {

		/* watch has already a fssync job */

		*error=EEXIST;
		result = -1;
		goto unlock;

	    }

	}

    }

    /*

	here test a fssync is "near" and merge with that??
	so two fssync jobs merged??

    */

    fssync=malloc(sizeof(struct fssync_struct));

    if (fssync) {

	fssync->watch=watch;
	fssync->status=_FSSYNC_STATUS_OK;
	fssync->lapse=synclapse;
	fssync->timerentry=NULL;

	fssync->schedule.tv_sec=0;
	fssync->schedule.tv_nsec=0;

	watch->data=(void *) fssync;

	/*
	    run the fssync job: actually put it on a queue and activate a thread
	    when successfull it will schedule a timerentry
	*/

	run_fssync((void *) fssync);

    } else {

	*error=ENOMEM;
	result = -1;

    }

    unlock:

    pthread_mutex_unlock(&fssyncprocess_mutex);

    return result;

}

/*
    cancel a fssync job for an inode
*/

void cancel_fssync(struct notifywatch_struct *watch)
{
    struct fssync_struct *fssync=NULL;

    if (watch->backend) {

	if (! (watch->backend->type==NOTIFYWATCH_BACKEND_FSSYNC)) {

	    /* watch has already another backend */

	    return;

	}

	if (watch->backend->type==NOTIFYWATCH_BACKEND_FSSYNC) {

	    if (! watch->data) {

		/* watch has no data */

		return;

	    }

	}

    }


    pthread_mutex_lock(&fssyncprocess_mutex);

    fssync=(struct fssync_struct *) watch->data;

    if (fssync) {

	if (fssync->status==_FSSYNC_STATUS_OK || fssync->status==_FSSYNC_STATUS_RUNNING ) {

	    /* it's running so cannot cancel it now anymore
		just set the status so it wont reschedule
	    */

	    logoutput("cancel_fssync: cancel a running fssync");

	    fssync->status=_FSSYNC_STATUS_CANCEL;

	} else if (fssync->status==_FSSYNC_STATUS_SCHEDULED ) {
	    struct timespec rightnow;

	    logoutput("cancel_fssync: cancel a scheduled fssync");

	    get_current_time(&rightnow);

	    /*	when it's some safe period in future it's safe to remove
		here I take 0,2 seconds, maybe that may be much more or less
		anyway the status is set to CANCEL, so when it's not removed
		and the timer is triggered on this entry, the callback will solve it
		(and do nothing else)
	    */

	    if (is_later(&fssync->schedule, &rightnow, 0, 200000000)>=0) {

		if (fssync->timerentry) {

		    logoutput("cancel_fssync: remove timerentry");

		    remove_timerentry(fssync->timerentry);

		}

		free(fssync);
		watch->data=NULL;

	    }

	    fssync->status=_FSSYNC_STATUS_CANCEL;

	} else if (fssync->status==_FSSYNC_STATUS_QUEUE) {

	    /* the fssync is in the queue, try to remove it there */

	    logoutput("cancel_fssync: cancel a queued fssync");

	    pthread_mutex_lock(&fssyncqueue_mutex);

	    if (fssync==fssyncqueue_first) {

		if (fssync==fssyncqueue_last) {

		    fssyncqueue_first=NULL;
		    fssyncqueue_last=NULL;

		} else {

		    fssyncqueue_first=fssync->next;

		}

		fssync->next=NULL;

	    } else {
		struct fssync_struct *walk=fssyncqueue_first;

		while(walk) {

		    if (walk->next==fssync) {

			if (fssync==fssyncqueue_last) {

			    fssyncqueue_last=walk;

			} else {

			    walk->next=fssync->next;

			}

			fssync->next=NULL;
			break;

		    }

		    walk=walk->next;

		}

	    }

	    if (fssync->timerentry) {

		logoutput("cancel_fssync: remove timerentry");

		remove_timerentry(fssync->timerentry);

	    }

	    free(fssync);

	    watch->data=NULL;

	    pthread_mutex_unlock(&fssyncqueue_mutex);

	}

    }

    pthread_mutex_unlock(&fssyncprocess_mutex);

}

int set_watch_backend_fssync(struct notifywatch_struct *watch)
{
    unsigned int error=0;

    logoutput("set_watch_backend_fssync");

    if (schedule_fssync(watch, 5, &error)==-1) {

	logoutput_error("set_watch_backend_fssync: error %i setting fssync watch", error);


    }

    return -error;

}

int change_watch_backend_fssync(struct notifywatch_struct *watch)
{

    logoutput("change_watch_backend_fssync");

    /* no extra action required: the fssync watches the watch->mask  */

    return 0;

}

void remove_watch_backend_fssync(struct notifywatch_struct *watch)
{

    logoutput("remove_watch_backend_fssync");

    cancel_fssync(watch);

}


int init_fssync(unsigned int *error)
{

    /* set the watch backend functions */

    fssync_watchbackend.type=NOTIFYWATCH_BACKEND_FSSYNC;
    fssync_watchbackend.set_watch=set_watch_backend_fssync;
    fssync_watchbackend.change_watch=change_watch_backend_fssync;
    fssync_watchbackend.remove_watch=remove_watch_backend_fssync;

    /* no error */

    *error=0;

    return 0;

}

