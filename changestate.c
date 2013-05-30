/*

  2010, 2011, 2012 Stef Bon <stefbon@gmail.com>

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

#include <sys/stat.h>
#include <sys/param.h>
#include <fcntl.h>
#include <dirent.h>
#include <pthread.h>

#include <fuse/fuse_lowlevel.h>

#include "entry-management.h"
#include "path-resolution.h"
#include "logging.h"

#include "notifyfs-fsevent.h"

#include "utils.h"
#include "watches.h"

#include "epoll-utils.h"
#include "socket.h"
#include "options.h"

#include "message-base.h"
#include "message-send.h"

#include "workerthreads.h"

#include "changestate.h"

#define LOG_LOGAREA LOG_LOGAREA_FILESYSTEM
#define MAXIMUM_PROCESS_FSEVENTS_NRTHREADS	4

extern struct notifyfs_options_struct notifyfs_options;
extern struct notifyfs_connection_struct notifyfsserver;
extern void notify_kernel_delete(struct entry_struct *entry);

static struct workerthreads_queue_struct *global_workerthreads_queue=NULL;

struct fsevents_queue_struct {
    struct notifyfs_fsevent_struct *first;
    struct notifyfs_fsevent_struct *last;
    pthread_mutex_t mutex;
    int nrthreads;
};

/* initialize the main queue for fsevents */

struct fsevents_queue_struct main_fsevents_queue={NULL, NULL, PTHREAD_MUTEX_INITIALIZER, 0};

static void remove_fsevent_from_queue(struct notifyfs_fsevent_struct *fsevent)
{
    /* remove the previous event from queue */

    if (main_fsevents_queue.first==fsevent) main_fsevents_queue.first=fsevent->next;

    if (fsevent->prev) fsevent->prev->next=fsevent->next;
    if (fsevent->next) fsevent->next->prev=fsevent->prev;

    if (main_fsevents_queue.last==fsevent) main_fsevents_queue.last=fsevent->prev;

}

struct notifyfs_fsevent_struct *create_fsevent(struct entry_struct *entry)
{
    struct notifyfs_fsevent_struct *fsevent=NULL;

    fsevent=malloc(sizeof(struct notifyfs_fsevent_struct));

    if (fsevent) {

	init_notifyfs_fsevent(fsevent);
	fsevent->entry=entry;

    }

    return fsevent;

}

void init_notifyfs_fsevent(struct notifyfs_fsevent_struct *fsevent)
{

    fsevent->status=0;

    fsevent->fseventmask.attrib_event=0;
    fsevent->fseventmask.xattr_event=0;
    fsevent->fseventmask.file_event=0;
    fsevent->fseventmask.move_event=0;
    fsevent->fseventmask.fs_event=0;

    fsevent->entry=NULL;

    fsevent->pathinfo.path=NULL;
    fsevent->pathinfo.flags=0;
    fsevent->pathinfo.len=0;

    fsevent->detect_time.tv_sec=0;
    fsevent->detect_time.tv_nsec=0;
    fsevent->process_time.tv_sec=0;
    fsevent->process_time.tv_nsec=0;

    fsevent->watch=NULL;

    fsevent->next=NULL;
    fsevent->prev=NULL;

}

void destroy_notifyfs_fsevent(struct notifyfs_fsevent_struct *fsevent)
{

    free_path_pathinfo(&fsevent->pathinfo);
    free(fsevent);

}

static unsigned char check_fsevent_applies(struct fseventmask_struct *fseventmaska, struct fseventmask_struct *fseventmaskb, unsigned char indir)
{

    if (fseventmaska->attrib_event & fseventmaskb->attrib_event) {

	if (indir==1) {

	    if (fseventmaska->attrib_event & NOTIFYFS_FSEVENT_ATTRIB_CHILD) {

		return 1;

	    }

	} else {

	    if (fseventmaska->attrib_event & NOTIFYFS_FSEVENT_ATTRIB_SELF) {

		return 1;

	    }

	}

    } else if (fseventmaska->xattr_event & fseventmaskb->xattr_event) {

	if (indir==1) {

	    if (fseventmaska->xattr_event & NOTIFYFS_FSEVENT_XATTR_CHILD) {

		return 1;

	    }

	} else {

	    if (fseventmaska->xattr_event & NOTIFYFS_FSEVENT_XATTR_SELF) {

		return 1;

	    }

	}

    } else if (fseventmaska->file_event & fseventmaskb->file_event) {

	if (indir==1) {

	    if (fseventmaska->file_event & NOTIFYFS_FSEVENT_FILE_CHILD) {

		return 1;

	    }

	} else {

	    if (fseventmaska->file_event & NOTIFYFS_FSEVENT_FILE_SELF) {

		return 1;

	    }

	}

    } else if (fseventmaska->move_event & fseventmaskb->move_event) {

	if (indir==1) {

	    if (fseventmaska->move_event & NOTIFYFS_FSEVENT_MOVE_CHILD) {

		return 1;

	    }

	} else {

	    if (fseventmaska->move_event & NOTIFYFS_FSEVENT_MOVE_SELF) {

		return 1;

	    }

	}

    } else if (fseventmaska->fs_event & fseventmaskb->fs_event) {

	return 1;

    }

    return 0;

}

static void send_fsevent_to_server(struct watch_struct *watch, struct notifyfs_fsevent_struct *fsevent, unsigned char indir)
{

    if (notifyfsserver.fd>0) {
	uint64_t unique=new_uniquectr();

	if (indir==1) {
	    char *name=fsevent->entry->name;

	    /* send message */

	    send_fsevent_message_remote(notifyfsserver.fd, unique, watch->owner_watch_id, &fsevent->fseventmask, name, &fsevent->detect_time);

	} else {

	    send_fsevent_message_remote(notifyfsserver.fd, unique, watch->owner_watch_id, &fsevent->fseventmask, NULL, &fsevent->detect_time);

	}

    }

}

static void notify_server(struct notifyfs_fsevent_struct *fsevent)
{
    struct inode_struct *inode=fsevent->entry->inode;
    struct watch_struct *watch=lookup_watch_inode(inode);

    /* event on inode */

    if (watch) send_fsevent_to_server(watch, fsevent, 0);

    if (isrootentry(fsevent->entry)==0) {
	struct entry_struct *entry=fsevent->entry->parent;

	inode=entry->inode;

	watch=lookup_watch_inode(inode);

	if (watch) {

	    /* event in directory of watch */

	    send_fsevent_to_server(watch, fsevent, 1);

	}

    }

}

/* process a change recursive 


*/

static void process_changestate_remove_recursive(struct entry_struct *parent, unsigned char self, char *path)
{
    int res, nlen;
    
    struct inode_struct *inode;

    logoutput("process_remove_fsevent_recursive");

    inode=parent->inode;

    if (inode) {

	if (S_ISDIR(inode->st.st_mode)) {
	    char *name=NULL;
	    int lenname=0;
	    int nlen=strlen(path);
	    struct entry_struct *entry, *next_entry;

	    /* when a directory: first remove contents (recursive) */

	    entry=get_next_entry(parent, NULL);

	    while(entry) {

		next_entry=get_next_entry(parent, entry);

		name=entry->name;
		lenname=strlen(name);

		*(path+nlen)='/';
		memcpy(path+nlen+1, name, lenname);
		*(path+nlen+lenname)='\0';

    		process_changestate_remove_recursive(entry, 1, path);

		*(path+nlen)='\0';
		entry=next_entry;

	    }

	}

	if (self==1) {
	    struct watch_struct *watch=lookup_watch_inode(inode);

	    if (watch) {

		lock_watch(watch);

		if (notifyfsserver.fd>0) {
		    uint64_t unique=new_uniquectr();

		    /* send message */

		    send_delwatch_message(notifyfsserver.fd, unique, watch->owner_watch_id);

		}

		remove_watch_backend_os_specific(watch);

		remove_watch_from_list(watch);
		remove_watch_from_table(watch);

		unlock_watch(watch);

		pthread_mutex_destroy(&watch->mutex);

		free_path_pathinfo(&watch->pathinfo);

		free(watch);

	    }

	}

    }

    if (self==1) {

	notify_kernel_delete(parent);
	remove_entry_from_name_hash(parent);
	remove_entry(parent);

    }

}

static void process_one_fsevent(struct notifyfs_fsevent_struct *fsevent)
{
    unsigned char catched=0;

    logoutput("process_one_fsevent");

    /* do the actual action */

    if (fsevent->fseventmask.move_event & (NOTIFYFS_FSEVENT_MOVE_MOVED | NOTIFYFS_FSEVENT_MOVE_MOVED_FROM | NOTIFYFS_FSEVENT_MOVE_DELETED )) {
	struct inode_struct *inode=fsevent->entry->inode;

	logoutput("process_one_fsevent: remove/moved, handle %i:%i:%i:%i", fsevent->fseventmask.attrib_event, fsevent->fseventmask.xattr_event, fsevent->fseventmask.file_event, fsevent->fseventmask.move_event);

	if (S_ISDIR(inode->st.st_mode)) {

	    pathstring path;

	    strcpy(path, fsevent->pathinfo.path);

	    catched=1;

	    notify_server(fsevent);
	    process_changestate_remove_recursive(fsevent->entry, 1, path);

	} else {

	    catched=1;

	    notify_server(fsevent);
	    process_changestate_remove_recursive(fsevent->entry, 1, NULL);

	}

    } else {

	if ((fsevent->fseventmask.move_event & (NOTIFYFS_FSEVENT_MOVE_CREATED | NOTIFYFS_FSEVENT_MOVE_MOVED_TO)) ||
	    (fsevent->fseventmask.attrib_event & NOTIFYFS_FSEVENT_ATTRIB_CA) || 
	    (fsevent->fseventmask.xattr_event & NOTIFYFS_FSEVENT_XATTR_CA) || 
	    (fsevent->fseventmask.file_event & (NOTIFYFS_FSEVENT_FILE_MODIFIED | NOTIFYFS_FSEVENT_FILE_SIZE | NOTIFYFS_FSEVENT_FILE_LOCK_CA))) {

	    struct entry_struct *entry=fsevent->entry;
	    struct inode_struct *inode=NULL;

	    /* it's possible that the entry does not have an inode yet */

	    if (entry->inode<0) assign_inode(entry);

	    inode=entry->inode;

	    if (inode) {
		struct stat st;

		if (lstat(fsevent->pathinfo.path, &st)==0) {

		    copy_stat(&inode->st, &st);

		} else {

		    /* what to do here: a fsevent indicating a change, a create, but not a delete, but stat gives an error */

		    logoutput("process_one_fsevent: new/changed, but stat gives error %i", errno);

		}

	    }

	    if (fsevent->fseventmask.move_event & (NOTIFYFS_FSEVENT_MOVE_CREATED | NOTIFYFS_FSEVENT_MOVE_MOVED_TO)) {

		add_to_name_hash_table(entry);
		add_to_inode_hash_table(entry->inode);

	    }

	    catched=1;

	    logoutput("process_one_fsevent: new/changed, handle %i:%i:%i:%i", fsevent->fseventmask.attrib_event, fsevent->fseventmask.xattr_event, fsevent->fseventmask.file_event, fsevent->fseventmask.move_event);

	    notify_server(fsevent);

	}

    }

    if (catched==0) {

	/* not handled here */

	logoutput("process_one_fsevent: event %i:%i:%i:%i not handled here", fsevent->fseventmask.attrib_event, fsevent->fseventmask.xattr_event, fsevent->fseventmask.file_event, fsevent->fseventmask.move_event);

    }

}

/* function which is called by the workerthread to do the actual work 
    it basically looks for the first fsevent with status WAITING
    and process that futher
    when finished with that look for another waiting fsevent
    the queue is locked when reading and/or changing the status of the individual fsevents..
*/

static void process_fsevent(void *data)
{
    struct notifyfs_fsevent_struct *fsevent=NULL;
    struct timespec rightnow;

    logoutput("process_fsevent");

    fsevent=(struct notifyfs_fsevent_struct *) data;

    process:

    get_current_time(&rightnow);

    pthread_mutex_lock(&main_fsevents_queue.mutex);

    if (! fsevent) {

	/* get one from the queue: the first waiting */

	fsevent=main_fsevents_queue.first;

	while(fsevent) {

	    if (fsevent->status==NOTIFYFS_FSEVENT_STATUS_WAITING) {

		break;

	    } else if (fsevent->status==NOTIFYFS_FSEVENT_STATUS_DONE) {

		/* while walking in the queue remove old fsevents */

		/* events long ago are expired and of no use anymore: remove 
		make this period configurable ..*/

		if ( is_later(&rightnow, &fsevent->process_time, 5, 0)==1) {
		    struct notifyfs_fsevent_struct *next_fsevent=fsevent->next;

		    remove_fsevent_from_queue(fsevent);
		    destroy_notifyfs_fsevent(fsevent);

		    fsevent=next_fsevent;
		    continue;

		}

	    }

	    fsevent=fsevent->next;

	}

    }

    if (fsevent) {

	/* found one: change the status */

	fsevent->status=NOTIFYFS_FSEVENT_STATUS_PROCESSED;

    } else {

	main_fsevents_queue.nrthreads--;

    }

    pthread_mutex_unlock(&main_fsevents_queue.mutex);

    if (fsevent) {

	fsevent->process_time.tv_sec=rightnow.tv_sec;
	fsevent->process_time.tv_nsec=rightnow.tv_nsec;

	process_one_fsevent(fsevent);

	/* change the status to done 
	    is it really required to lock the whole queue for that ?? 
	*/

	pthread_mutex_lock(&main_fsevents_queue.mutex);
	fsevent->status=NOTIFYFS_FSEVENT_STATUS_DONE;
	pthread_mutex_unlock(&main_fsevents_queue.mutex);

	fsevent=NULL;

	/* jump back to look for another fsevent */

	goto process;

    }

}



/* function to test queueing a change state entry is necessary 

   note the queue has to be locked 
    TODO: take in account the type of the action, sleep versus remove, what to
    do when both in queue
   */

static unsigned char queue_required(struct notifyfs_fsevent_struct *fsevent)
{
    unsigned char doqueue=0;

    if ( ! main_fsevents_queue.first ) {

        /* queue is empty: put it on queue */

        doqueue=1;

	main_fsevents_queue.first=fsevent;
	main_fsevents_queue.last=fsevent;

	logoutput("queue_required: path %s, queue is empty", fsevent->pathinfo.path);

    } else {
	struct notifyfs_fsevent_struct *fsevent_walk=main_fsevents_queue.last;
        char *path2, *path1=fsevent->pathinfo.path;
        int len1=strlen(path1), len2;

	logoutput("queue_required: path %s, check the queue", path1);

        doqueue=1;

        /* walk through queue to check there is a related call already there */

        while(fsevent_walk) {

	    /* compare this previous event with the new one */

            path2=fsevent_walk->pathinfo.path;
            len2=strlen(path2);

            if ( len1>len2 ) {

                /* test path1 is a real subdirectory of path2 (the previous one)*/

                if ( strncmp(path1+len2, "/", 1)==0 && strncmp(path1, path2, len2)==0 ) {

		    if (fsevent_walk->fseventmask.move_event & (NOTIFYFS_FSEVENT_MOVE_MOVED | NOTIFYFS_FSEVENT_MOVE_MOVED_FROM | NOTIFYFS_FSEVENT_MOVE_DELETED )) {

			/* previous fsevent was a remove */
			/* ignore everything in subtree  */

			if (fsevent_walk->status==NOTIFYFS_FSEVENT_STATUS_WAITING || fsevent_walk->status==NOTIFYFS_FSEVENT_STATUS_PROCESSED) {

			    doqueue=0;
			    break;

			}

		    }

		}

	    } else if (len1==len2) {

		if (strcmp(path2, path1)==0) {

		    /* paths are the same, but it may be another entry ... */

		    if (fsevent_walk->fseventmask.fs_event & NOTIFYFS_FSEVENT_FS_UNMOUNT) {

			if (fsevent->fseventmask.fs_event & NOTIFYFS_FSEVENT_FS_UNMOUNT) {

			    /* there is a previous umount event waiting: anything else here is ignored */

			    if (fsevent_walk->status==NOTIFYFS_FSEVENT_STATUS_WAITING) {

				merge_fseventmasks(&fsevent_walk->fseventmask, &fsevent->fseventmask);
				doqueue=0;
				break;

			    } else if (fsevent_walk->status==NOTIFYFS_FSEVENT_STATUS_DONE) {

				remove_fsevent_from_queue(fsevent_walk);

			    }

			}

		    } else if (fsevent_walk->fseventmask.move_event & (NOTIFYFS_FSEVENT_MOVE_MOVED | NOTIFYFS_FSEVENT_MOVE_MOVED_FROM | NOTIFYFS_FSEVENT_MOVE_DELETED )) {

			if (fsevent->entry==fsevent_walk->entry) {

			    /* ignore everything else on this entry here */

			    doqueue=0;
			    break;

			}

		    } else {

			if (fsevent->fseventmask.move_event & (NOTIFYFS_FSEVENT_MOVE_MOVED | NOTIFYFS_FSEVENT_MOVE_MOVED_FROM | NOTIFYFS_FSEVENT_MOVE_DELETED )) {

			    /* already deleted.. */

			    if (fsevent_walk->status==NOTIFYFS_FSEVENT_STATUS_WAITING) {

				remove_fsevent_from_queue(fsevent_walk);
				doqueue=0;
				break;

			    } else if (fsevent_walk->status==NOTIFYFS_FSEVENT_STATUS_DONE) {

				remove_fsevent_from_queue(fsevent_walk);

			    }

			} else {

			    /* any other event than a remove is safe to merge */

			    if (fsevent_walk->status==NOTIFYFS_FSEVENT_STATUS_WAITING) {

				merge_fseventmasks(&fsevent_walk->fseventmask, &fsevent->fseventmask);
				doqueue=0;
				break;

			    } else if (fsevent_walk->status==NOTIFYFS_FSEVENT_STATUS_DONE) {

				remove_fsevent_from_queue(fsevent_walk);

			    }

			}

		    }

		}

	    } else if (len1<len2) {

                /* test path2 is a real subdirectory of path1 */

                if ( strncmp(path2+len1, "/", 1)==0 && strncmp(path2, path1, len1)==0 ) {

		    /* path is removed and every thing in it */

		    if (fsevent->fseventmask.move_event & (NOTIFYFS_FSEVENT_MOVE_MOVED | NOTIFYFS_FSEVENT_MOVE_MOVED_FROM | NOTIFYFS_FSEVENT_MOVE_DELETED)) {

			if (fsevent_walk->status==NOTIFYFS_FSEVENT_STATUS_DONE) {

			    remove_fsevent_from_queue(fsevent_walk);

			} else if (fsevent_walk->status==NOTIFYFS_FSEVENT_STATUS_WAITING) {

			    /* previous event is not yet processed: replace it by the new one */

			    replace_fseventmask(&fsevent_walk->fseventmask, &fsevent->fseventmask);
			    doqueue=0;
			    break;

			}

		    }

		}

	    }

	    fsevent_walk=fsevent_walk->prev;

	}

	if (doqueue==1) {

	    /* queue/add at tail */

	    if (main_fsevents_queue.last) main_fsevents_queue.last->next=fsevent;
	    fsevent->next=NULL;
	    fsevent->prev=main_fsevents_queue.last;
	    main_fsevents_queue.last=fsevent;

	}

    }

    return doqueue;

}

/*  process an notifyfs fsevent

    when something is reported (by the fs notify backend like inotify) 
    or detected on the fly
    or by the mountmonitor (mount/unmount)
    or by the lockmonitor

    make this effective in the fs

*/

void queue_fsevent(struct notifyfs_fsevent_struct *notifyfs_fsevent)
{
    struct fseventmask_struct *fseventmask=&notifyfs_fsevent->fseventmask;
    int res;

    logoutput("queue_fsevent");

    notifyfs_fsevent->status=NOTIFYFS_FSEVENT_STATUS_WAITING;

    /* lock the queue */

    pthread_mutex_lock(&main_fsevents_queue.mutex);

    res=queue_required(notifyfs_fsevent);

    pthread_mutex_unlock(&main_fsevents_queue.mutex);

    if (res==1) {

	logoutput("queue_fsevent: path: %s, fsevent queued", notifyfs_fsevent->pathinfo.path);

	/* possibly activate a workerthread */

	if (main_fsevents_queue.nrthreads<MAXIMUM_PROCESS_FSEVENTS_NRTHREADS) {
	    struct workerthread_struct *workerthread=NULL;

	    logoutput("queue_fsevent: path: %s, nr threads %i, starting a new thread", notifyfs_fsevent->pathinfo.path, main_fsevents_queue.nrthreads);

	    /* get a thread to do the work */

	    workerthread=get_workerthread(global_workerthreads_queue);

	    if ( workerthread ) {

		/* assign the right callbacks and data */

		workerthread->processevent_cb=process_fsevent;
		workerthread->data=NULL;

		pthread_mutex_lock(&main_fsevents_queue.mutex);
		main_fsevents_queue.nrthreads++;
		pthread_mutex_unlock(&main_fsevents_queue.mutex);

		logoutput("queue_fsevent: sending a signal to workerthread to start");

		/* send signal to start */

		signal_workerthread(workerthread);

	    }

	}

    } else {

	destroy_notifyfs_fsevent(notifyfs_fsevent);

    }

}

void init_changestate(struct workerthreads_queue_struct *workerthreads_queue)
{

    global_workerthreads_queue=workerthreads_queue;

}

