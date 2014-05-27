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
#include <pthread.h>
#include <time.h>

#ifndef ENOATTR
#define ENOATTR ENODATA        /* No such attribute */
#endif

#include "fuse-workspace.h"

#include "skiplist.h"
#include "skiplist-find.h"
#include "skiplist-delete.h"
#include "skiplist-insert.h"

#include "workerthreads.h"
#include "utils.h"
#include "entry-management.h"
#include "options.h"
#include "handlefuseevent.h"

#ifndef SIZE_INODE_HASHTABLE
#define SIZE_INODE_HASHTABLE				10240
#endif

#ifndef SIZE_DIRECTORY_HASHTABLE
#define SIZE_DIRECTORY_HASHTABLE			1024
#endif

#ifdef LOGGING

static unsigned char loglevel=1;

#include <syslog.h>

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
extern const char *dotname;

static struct entry_struct *rootentry=NULL;

static struct inode_struct **inode_hash_table;
static pthread_mutex_t inode_table_mutex=PTHREAD_MUTEX_INITIALIZER;

static struct directory_struct **directory_hash_table;
static pthread_mutex_t directory_table_mutex=PTHREAD_MUTEX_INITIALIZER;

static unsigned long long inoctr=FUSE_ROOT_ID;
static pthread_mutex_t inodectrmutex=PTHREAD_MUTEX_INITIALIZER;
static unsigned long long nrinodes=0;

struct stat default_stat;

void calculate_nameindex(struct name_struct *name)
{
    unsigned char firstletter=*(name->name)-32;

    if (name->len>=6) {
	unsigned char secondletter=*(name->name+1)-32;
	unsigned char thirdletter=*(name->name+2)-32;
	unsigned char fourthletter=*(name->name+3)-32;
	unsigned char fifthletter=*(name->name+4)-32;
	unsigned char sixthletter=*(name->name+5)-32;

	name->index=(firstletter * NAMEINDEX_ROOT5) + (secondletter * NAMEINDEX_ROOT4) + (thirdletter * NAMEINDEX_ROOT3) + 
		    (fourthletter * NAMEINDEX_ROOT2) + (fifthletter * NAMEINDEX_ROOT1) + sixthletter;

    } else if (name->len==5) {
	unsigned char secondletter=*(name->name+1)-32;
	unsigned char thirdletter=*(name->name+2)-32;
	unsigned char fourthletter=*(name->name+3)-32;
	unsigned char fifthletter=*(name->name+4)-32;

	name->index=(firstletter * NAMEINDEX_ROOT5) + (secondletter * NAMEINDEX_ROOT4) + (thirdletter * NAMEINDEX_ROOT3) + 
		    (fourthletter * NAMEINDEX_ROOT2) + (fifthletter * NAMEINDEX_ROOT1);

    } else if (name->len==4) {
	unsigned char secondletter=*(name->name+1)-32;
	unsigned char thirdletter=*(name->name+2)-32;
	unsigned char fourthletter=*(name->name+3)-32;

	name->index=(firstletter * NAMEINDEX_ROOT5) + (secondletter * NAMEINDEX_ROOT4) + (thirdletter * NAMEINDEX_ROOT3) + 
		    (fourthletter * NAMEINDEX_ROOT2);

    } else if (name->len==3) {
	unsigned char secondletter=*(name->name+1)-32;
	unsigned char thirdletter=*(name->name+2)-32;

	name->index=(firstletter * NAMEINDEX_ROOT5) + (secondletter * NAMEINDEX_ROOT4) + (thirdletter * NAMEINDEX_ROOT3);

    } else if (name->len==2) {
	unsigned char secondletter=*(name->name+1)-32;

	name->index=(firstletter * NAMEINDEX_ROOT5) + (secondletter * NAMEINDEX_ROOT4);

    } else {

	/* len is one */

        name->index=(firstletter * NAMEINDEX_ROOT5);

    }

    /*logoutput("calculate_nameindex: index %lli for %s len %i", name->index, name->name, name->len);*/

}

int init_inode_hashtable(unsigned int *error)
{
    int result=0;

    inode_hash_table = calloc(SIZE_INODE_HASHTABLE, sizeof(struct inode_struct *));

    if ( ! inode_hash_table ) {

	*error=ENOMEM;
	result=-1;

    }

    return result;

}

int init_directory_hashtable(unsigned int *error)
{
    int result=0;

    directory_hash_table = calloc(SIZE_DIRECTORY_HASHTABLE, sizeof(struct directory_struct *));

    if ( ! directory_hash_table ) {

	*error=ENOMEM;
	result=-1;

    }

    return result;

}

/*
    function to assign an ino number to the inode and add the inode
    to the inode hash table

    this can be done using one mutex

    note that the ino is required to add to the hash table, so first get a new ino, and than add to the table

*/

void add_inode_hashtable(struct inode_struct *inode, void (*cb) (void *data), void *data)
{
    size_t hash = 0;

    pthread_mutex_lock(&inode_table_mutex);

    inoctr++;
    inode->ino=inoctr;

    hash = inoctr % SIZE_INODE_HASHTABLE;

    inode->id_next = inode_hash_table[hash];
    inode_hash_table[hash] = inode;

    (* cb) (data);

    pthread_mutex_unlock(&inode_table_mutex);

}

void init_entry(struct entry_struct *entry)
{
    entry->inode=NULL;

    entry->name.name=NULL;
    entry->name.len=0;
    entry->name.index=0;

    entry->parent=NULL;
    entry->name_next=NULL;
    entry->name_prev=NULL;

    entry->synctime.tv_sec=0;
    entry->synctime.tv_nsec=0;

    entry->flags=0;

}

struct entry_struct *create_entry(struct entry_struct *parent, struct name_struct *xname)
{
    struct entry_struct *entry;

    entry = malloc(sizeof(struct entry_struct));

    if (entry) {

	memset(entry, 0, sizeof(struct entry_struct));
	init_entry(entry);

	entry->name.name = malloc(xname->len + 1);

	if (!entry->name.name) {

	    free(entry);
	    entry = NULL;

	} else {

	    memcpy(entry->name.name, xname->name, xname->len + 1);

	    entry->name.len=xname->len;
	    entry->name.index=xname->index;
	    entry->parent = parent;

	}

    }

    return entry;

}

void destroy_entry(struct entry_struct *entry)
{

    if ( entry->name.name) {

	free(entry->name.name);
	entry->name.name=NULL;

    }

    if ( entry->inode ) {

	entry->inode->alias=NULL;
	entry->inode=NULL;

    }

    free(entry);

}

void init_inode(struct inode_struct *inode)
{

    memset(inode, 0, sizeof(struct inode_struct));

    inode->nlookup=0;
    inode->ino=0;
    inode->id_next=NULL;
    inode->alias=NULL;

    inode->mode=0;
    inode->nlink=0;
    inode->uid=(uid_t) -1;
    inode->gid=(gid_t) -1;
    inode->rdev=0;

    inode->size=0;

    inode->mtim.tv_sec=0;
    inode->mtim.tv_nsec=0;

    inode->ctim.tv_sec=0;
    inode->ctim.tv_nsec=0;

    inode->object=NULL;

}

struct inode_struct *create_inode()
{
    struct inode_struct *inode=NULL;

    inode = malloc(sizeof(struct inode_struct));

    if (inode) init_inode(inode);

    return inode;

}

struct inode_struct *find_inode(fuse_ino_t ino)
{
    size_t hash=ino % SIZE_INODE_HASHTABLE;
    struct inode_struct *inode=NULL;

    pthread_mutex_lock(&inode_table_mutex);

    inode=inode_hash_table[hash];

    while(inode) {

	if (inode->ino==ino) break;
	inode=inode->id_next;

    }

    pthread_mutex_unlock(&inode_table_mutex);

    return inode;

}

struct inode_struct *remove_inode(fuse_ino_t ino, void (*cb) (void *data), void *data)
{
    size_t hash=ino % SIZE_INODE_HASHTABLE;
    struct inode_struct *inode=NULL, *prev=NULL;

    pthread_mutex_lock(&inode_table_mutex);

    inode=inode_hash_table[hash];

    while(inode) {

	if (inode->ino==ino) {

	    if (prev) {

		prev->id_next=inode->id_next;

	    } else {

		/* no prev: it's the first */

		inode_hash_table[hash]=inode->id_next;

	    }

	    inode->id_next=NULL;

	    (* cb) (data);

	    break;

	}

	prev=inode;
	inode=inode->id_next;

    }

    pthread_mutex_unlock(&inode_table_mutex);

    return inode;

}

struct entry_struct *find_entry(struct entry_struct *parent, struct name_struct *xname, unsigned int *error)
{
    struct inode_struct *inode=parent->inode;
    struct entry_struct *entry=NULL;
    struct directory_struct *directory=get_directory(inode, 0, error);

    if (directory) {
	unsigned int row=0;

	if (directory->flags & _DIRECTORY_FLAG_REMOVE) {

	    *error=ENOTDIR;
	    return NULL;

	}

	*error=0;

	entry=(struct entry_struct *) find_sl(&directory->skiplist, (void *) xname, &row, error);

    }

    return entry;

}

void remove_entry(struct entry_struct *entry, unsigned int *error)
{
    struct entry_struct *parent=entry->parent;
    struct inode_struct *inode=parent->inode;
    struct directory_struct *directory=get_directory(inode, 0, error);

    if (directory) {
	struct name_struct *lookupname=&entry->name;
	unsigned int row=0;

	if (directory->flags & _DIRECTORY_FLAG_REMOVE) {

	    *error=ENOTDIR;
	    return;

	}

	delete_sl(&directory->skiplist, (void *) lookupname, &row, error);

    }

}

struct entry_struct *insert_entry(struct entry_struct *entry, unsigned int *error, unsigned short flags)
{
    struct entry_struct *parent=entry->parent;
    struct inode_struct *inode=parent->inode;
    struct directory_struct *directory=get_directory(inode, 1, error);

    if (directory) {
	struct name_struct *lookupname=&entry->name;
	unsigned int row=0;
	unsigned short sl_flags=0;

	if (directory->flags & _DIRECTORY_FLAG_REMOVE) {

	    *error=ENOTDIR;
	    return NULL;

	}

	if (flags & _ENTRY_FLAG_TEMP) sl_flags |= _SL_INSERT_FLAG_NOLANE;

	return (struct entry_struct *)insert_sl(&directory->skiplist, (void *) lookupname, &row, error, (void *) entry, sl_flags);

    }

    return NULL;

}

struct entry_struct *find_entry_batch(struct directory_struct *directory, struct name_struct *xname, unsigned int *error)
{
    struct entry_struct *entry=NULL;
    unsigned int row=0;

    entry=(struct entry_struct *) find_sl_batch(&directory->skiplist, (void *) xname, &row, error);

    return entry;

}

void remove_entry_batch(struct directory_struct *directory, struct entry_struct *entry, unsigned int *error)
{
    struct name_struct *lookupname=&entry->name;
    unsigned int row=0;

    delete_sl_batch(&directory->skiplist, (void *) lookupname, &row, error);

}

struct entry_struct *insert_entry_batch(struct directory_struct *directory, struct entry_struct *entry, unsigned int *error, unsigned short flags)
{
    struct name_struct *lookupname=&entry->name;
    unsigned int row=0;
    unsigned short sl_flags=0;

    if (flags & _ENTRY_FLAG_TEMP) sl_flags |= _SL_INSERT_FLAG_NOLANE;

    return (struct entry_struct *) insert_sl_batch(&directory->skiplist, (void *) lookupname, &row, error, (void *) entry, sl_flags);

}

/*
    callbacks for the skiplist
    compare two elements to determine the right order
*/

static int compare_entry(void *a, void *b)
{
    int result=0;
    struct entry_struct *entry=(struct entry_struct *) a;
    struct name_struct *name=(struct name_struct *) b;

    if (entry->name.index > name->index) {

	result=1; /* entry->name is bigger */

    } else if (entry->name.index==name->index) {

	if (name->len > 6) {

	    if (entry->name.len > 6) {

		result=strcmp(entry->name.name + 6, name->name + 6);

	    } else {

		result=-1; /* name is bigger */

	    }

	} else if (name->len==6) {

	    if (entry->name.len>6) {

		result=1;

	    } else {

		result=0;

	    }

	} else {

	    result=0;

	}

    } else {

	result=-1;

    }

    // logoutput("compare: %s and %s: result %i", entry->name.name, name->name, result);

    return result;

}

static void *get_next_entry(void *data)
{
    struct entry_struct *entry=(struct entry_struct *) data;

    return (void *) entry->name_next;
}

static void *get_prev_entry(void *data)
{
    struct entry_struct *entry=(struct entry_struct *) data;

    return (void *) entry->name_prev;
}

static void insert_before_entry(void *a, void *b, struct skiplist_struct *sl)
{
    struct entry_struct *entry=(struct entry_struct *) a;
    struct entry_struct *before=(struct entry_struct *) b;
    struct directory_struct *directory=(struct directory_struct *) ( ((char *) sl) - offsetof(struct directory_struct, skiplist));

    if (before==directory->first) {

	entry->name_next=before;
	before->name_prev=entry;

	directory->first=entry;

    } else {
	struct entry_struct *prev=before->name_prev;

	prev->name_next=entry;
	entry->name_prev=prev;

	entry->name_next=before;
	before->name_prev=entry;

    }

    directory->count++;

}

static void insert_after_entry(void *a, void *b, struct skiplist_struct *sl)
{
    struct entry_struct *entry=(struct entry_struct *) a;
    struct entry_struct *after=(struct entry_struct *) b;
    struct directory_struct *directory=(struct directory_struct *) ( ((char *) sl) - offsetof(struct directory_struct, skiplist));

    if ( ! after) after=directory->last;

    if (after==directory->last) {

	if ( ! after) {

	    /* empty */

	    directory->last=entry;
	    directory->first=entry;

	} else {

	    entry->name_prev=after;
	    after->name_next=entry;

	    directory->last=entry;

	}

    } else {
	struct entry_struct *next=after->name_next;

	next->name_prev=entry;
	entry->name_next=next;

	entry->name_prev=after;
	after->name_next=entry;

    }

    directory->count++;

}

static void delete_entry(void *a, struct skiplist_struct *sl)
{
    struct entry_struct *entry=(struct entry_struct *) a;
    struct directory_struct *directory=(struct directory_struct *) ( ((char *) sl) - offsetof(struct directory_struct, skiplist));

    if (entry==directory->first && entry==directory->last) {

	directory->first=NULL;
	directory->last=NULL;

    } else if (entry==directory->first) {

	directory->first=entry->name_next;
	directory->first->name_next=NULL;

    } else if (entry==directory->last) {

	directory->last=entry->name_prev;
	directory->last->name_prev=NULL;

    } else {
	struct entry_struct *next=entry->name_next;
	struct entry_struct *prev=entry->name_prev;

	prev->name_next=next;
	next->name_prev=prev;

    }

    entry->name_next=NULL;
    entry->name_prev=NULL;

    directory->count--;

}

int lock_directory(struct directory_struct *directory, unsigned short flags)
{
    int result=0;

    logoutput("lock_directory: flags %i", flags);

    if (directory->flags & _DIRECTORY_FLAG_REMOVE) return -1;

    if (flags==_DIRECTORY_LOCK_READ) {

	/* increase the readers */

	pthread_mutex_lock(&directory->mutex);

	while (directory->lock & 3) {

	    pthread_cond_wait(&directory->cond, &directory->mutex);

	}

	directory->lock+=4;

	pthread_mutex_unlock(&directory->mutex);

    } else if (flags==_DIRECTORY_LOCK_PREEXCL) {

	/* set a lock to prepare the exclusive lock */

	pthread_mutex_lock(&directory->mutex);

	if (directory->lock & 1) {

	    if (directory->write_thread != pthread_self()) {

		result=-1; /* some other thread else already got it */

	    }

	} else {

	    directory->lock |= 1;
	    directory->write_thread = pthread_self();

	}

	pthread_mutex_unlock(&directory->mutex);

    } else if (flags==_DIRECTORY_LOCK_EXCL) {

	/* set a exclusive lock */

	pthread_mutex_lock(&directory->mutex);

	if (directory->lock & 1) {

	    if (directory->write_thread==pthread_self()) {

		/* wait for readers to finish */

		while(directory->lock>>3 > 1) {

		    pthread_cond_wait(&directory->cond, &directory->mutex);

		}

		directory->lock |= 2;

	    } else {

		/* another thread owns the lock */

		result=-1;

	    }

	} else if (directory->lock & 2) {

	    if (directory->write_thread!=pthread_self()) {

		result=-1;

	    } else {

		directory->lock |= 1;

	    }

	} else {

	    directory->lock |= 1;

	    /* wait for readers to finish */

	    while(directory->lock>>3 > 1) {

		pthread_cond_wait(&directory->cond, &directory->mutex);

	    }

	    directory->lock |= 2;
	    directory->write_thread = pthread_self();

	} 

	pthread_mutex_unlock(&directory->mutex);

    }

    return result;

}

int unlock_directory(struct directory_struct *directory, unsigned short flags)
{
    int result=0;

    logoutput("unlock_directory: flags %i", flags);

    if (directory->flags & _DIRECTORY_FLAG_REMOVE) return -1;

    if (flags==_DIRECTORY_LOCK_READ) {

	/* decrease the readers */

	pthread_mutex_lock(&directory->mutex);

	directory->lock-=4;

	pthread_cond_broadcast(&directory->cond);
	pthread_mutex_unlock(&directory->mutex);

    } else if (flags==_DIRECTORY_LOCK_PREEXCL) {

	/* remove the pre excl lock */

	pthread_mutex_lock(&directory->mutex);

	if (directory->write_thread==pthread_self()) {

	    if (directory->lock & 1) {

		if (directory->lock & 2) {

		    result=-1;

		} else {

		    directory->lock -= 1;
		    directory->write_thread = 0;
		    pthread_cond_broadcast(&directory->cond);

		}

	    }

	} else {

	    result=-1;

	}

	pthread_mutex_unlock(&directory->mutex);

    } else if (flags==_DIRECTORY_LOCK_EXCL) {

	/* set a exclusive lock */

	pthread_mutex_lock(&directory->mutex);

	if (directory->write_thread==pthread_self()) {

	    if (directory->lock & 1) directory->lock -= 1;
	    if (directory->lock & 2) directory->lock -= 2;
	    directory->write_thread = 0;
	    pthread_cond_broadcast(&directory->cond);

	} else {

	    result=-1;

	}

	pthread_mutex_unlock(&directory->mutex);

    }

    return result;

}

/*
    callbacks for the skiplist
*/

static int lock_skiplist(struct skiplist_struct *sl, unsigned short flags)
{
    struct directory_struct *directory=(struct directory_struct *) ( ((char *) sl) - offsetof(struct directory_struct, skiplist));

    return lock_directory(directory, flags);

}

static int unlock_skiplist(struct skiplist_struct *sl, unsigned short flags)
{
    struct directory_struct *directory=(struct directory_struct *) ( ((char *) sl) - offsetof(struct directory_struct, skiplist));

    return unlock_directory(directory, flags);
}

static unsigned int count_entries(struct skiplist_struct *sl)
{
    struct directory_struct *directory=(struct directory_struct *) ( ((char *) sl) - offsetof(struct directory_struct, skiplist));

    return directory->count;
}

static void *first_entry(struct skiplist_struct *sl)
{
    struct directory_struct *directory=(struct directory_struct *) ( ((char *) sl) - offsetof(struct directory_struct, skiplist));

    return (void *) directory->first;
}

static void *last_entry(struct skiplist_struct *sl)
{
    struct directory_struct *directory=(struct directory_struct *) ( ((char *) sl) - offsetof(struct directory_struct, skiplist));

    return (void *) directory->last;
}


static struct directory_struct *create_directory(struct inode_struct *inode, unsigned int *error)
{
    struct directory_struct *directory=NULL;

    directory=malloc(sizeof(struct directory_struct));

    if (directory) {
	int result=0;
	size_t hash = inode->ino % SIZE_DIRECTORY_HASHTABLE;

	directory->flags=0;
	directory->synctime.tv_sec=0;
	directory->synctime.tv_nsec=0;
	directory->inode=inode;
	directory->next=NULL;
	directory->prev=NULL;
	directory->count=0;

	pthread_mutex_init(&directory->mutex, NULL);
	pthread_cond_init(&directory->cond, NULL);

	directory->lock=0;
	directory->write_thread=0;

	directory->first=NULL;
	directory->last=NULL;

	result=init_skiplist(&directory->skiplist, 4, get_next_entry, get_prev_entry,
			    compare_entry, insert_before_entry, insert_after_entry, delete_entry,
			    lock_skiplist, unlock_skiplist, count_entries, first_entry, last_entry, error);

	if (result==-1) {

	    logoutput_error("create_directory: error %i initializing skiplist", *error);

	    free(directory);
	    directory=NULL;

	}

	if (directory_hash_table[hash]) {

	    directory_hash_table[hash]->prev=directory;
	    directory->next=directory_hash_table[hash];

	    directory_hash_table[hash]=directory;

	} else {

	    directory_hash_table[hash]=directory;

	}

    }

    return directory;

}

struct directory_struct *get_directory(struct inode_struct *inode, unsigned char create, unsigned int *error)
{
    struct directory_struct *directory=NULL;

    pthread_mutex_lock(&directory_table_mutex);

    if (S_ISDIR(inode->mode)) {
	size_t hash = inode->ino % SIZE_DIRECTORY_HASHTABLE;

	directory = directory_hash_table[hash];

	while(directory) {

	    if (directory->inode==inode) break;

	    directory=directory->next;

	}

	if (! directory && create==1) directory=create_directory(inode, error);

    } else {

	*error=ENOTDIR;

    }

    pthread_mutex_unlock(&directory_table_mutex);

    return directory;

}

void destroy_directory(struct directory_struct *directory)
{

    pthread_mutex_destroy(&directory->mutex);
    pthread_cond_destroy(&directory->cond);

    free(directory);

}


/*
    remove contents of directory and 
    clear the skiplist
    remove from hash table
    destroy the directory

*/

void clear_directory(struct directory_struct *directory, void (*cb) (struct entry_struct *entry))
{
    struct entry_struct *entry, *next;
    struct inode_struct *inode;
    unsigned int error=0;
    size_t hash = directory->inode->ino % SIZE_DIRECTORY_HASHTABLE;

    lock_directory(directory, _DIRECTORY_LOCK_EXCL);

    directory->flags |= _DIRECTORY_FLAG_REMOVE;

    unlock_directory(directory, _DIRECTORY_LOCK_EXCL);

    entry=(struct entry_struct *) directory->first;

    while(entry) {

	inode=entry->inode;

	if (inode) {

	    if (S_ISDIR(inode->mode)) {
		struct directory_struct *subdir=get_directory(inode, 0, &error);

		if (subdir) clear_directory(subdir, cb);

	    }

	}

	(* cb) (entry);

	next=entry->name_next;
	destroy_entry(entry);
	entry=next;

    }

    clear_skiplist(&directory->skiplist);
    destroy_lock_skiplist(&directory->skiplist);

    /* remove from directory hash table */

    pthread_mutex_lock(&directory_table_mutex);

    if (directory==directory_hash_table[hash]) {

	/* is the first */

	directory_hash_table[hash]=directory->next;
	if (directory_hash_table[hash]) directory_hash_table[hash]->prev=NULL;

    } else {

	directory->prev->next=directory->next;
	if (directory->next) directory->next->prev=directory->prev;

    }

    pthread_mutex_unlock(&directory_table_mutex);

    destroy_directory(directory);

}

