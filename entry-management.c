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

#include "utils.h"
#include "entry-management.h"
#include "options.h"
#include "skiplist.h"
#include "skiplist-find.h"

#ifndef SIZE_INODE_HASHTABLE
#define SIZE_INODE_HASHTABLE			10240
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

extern struct overlayfs_options_struct overlayfs_options;

static struct entry_struct *rootentry=NULL;
static struct inode_struct **inode_hash_table;
static pthread_mutex_t inode_table_mutex=PTHREAD_MUTEX_INITIALIZER;

static unsigned long long inoctr=FUSE_ROOT_ID;
static pthread_mutex_t inodectrmutex=PTHREAD_MUTEX_INITIALIZER;
static unsigned long long nrinodes=0;

struct stat default_stat;

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

void add_inode_hashtable(struct inode_struct *inode)
{
    size_t hash = inode->ino % SIZE_INODE_HASHTABLE;

    pthread_mutex_lock(&inode_table_mutex);

    inode->id_next = inode_hash_table[hash];
    inode_hash_table[hash] = inode;

    pthread_mutex_unlock(&inode_table_mutex);

}


void init_entry(struct entry_struct *entry)
{
    entry->inode=NULL;
    entry->name=NULL;

    entry->parent=NULL;
    entry->name_next=NULL;
    entry->name_prev=NULL;

    entry->nameindex_value=0;

    entry->synctime.tv_sec=0;
    entry->synctime.tv_nsec=0;

}

struct entry_struct *create_entry(struct entry_struct *parent, const char *name, struct inode_struct *inode)
{
    struct entry_struct *entry;

    entry = malloc(sizeof(struct entry_struct));

    if (entry) {

	memset(entry, 0, sizeof(struct entry_struct));
	init_entry(entry);

	entry->name = strdup(name);

	if (!entry->name) {

	    free(entry);
	    entry = NULL;

	} else {

	    entry->parent = parent;

	    if (inode != NULL) {

		entry->inode = inode;
		inode->alias=entry;

	    }

	}

    }

    return entry;

}

void remove_entry(struct entry_struct *entry)
{

    if ( entry->name) {

	free(entry->name);
	entry->name=NULL;

    }

    if ( entry->inode ) {

	entry->inode->alias=NULL;
	entry->inode=NULL;

    }

    free(entry);

}

static struct inode_struct *create_inode()
{
    struct inode_struct *inode=NULL;

    pthread_mutex_lock(&inodectrmutex);

    inode = malloc(sizeof(struct inode_struct));

    if (inode) {

	memset(inode, 0, sizeof(struct inode_struct));

	inode->nlookup=0;
	inode->ino=inoctr;
	inode->id_next=NULL;
	inode->alias=NULL;

	inode->mode=0;
	inode->nlink=0;
	inode->uid=(uid_t) -1;
	inode->gid=(gid_t) -1;
	inode->rdev=0;

	inode->type.size=0;

	inode->mtim.tv_sec=0;
	inode->mtim.tv_nsec=0;

	inode->ctim.tv_sec=0;
	inode->ctim.tv_nsec=0;

	inoctr++;
	nrinodes++;

    }

    pthread_mutex_unlock(&inodectrmutex);

    return inode;

}

void assign_inode(struct entry_struct *entry)
{

    entry->inode=create_inode();

    if ( entry->inode ) entry->inode->alias=entry;

}

/* create the root inode and entry */

int create_root(unsigned int *error)
{

    *error=0;

    if ( ! rootentry ) {

	rootentry=create_entry(NULL, ".", NULL);

	if (rootentry) {

	    assign_inode(rootentry);

	    if (rootentry->inode) {

		logoutput("create_root: created rootentry %s with ino %li", rootentry->name, (long int) rootentry->inode->ino);

		add_inode_hashtable(rootentry->inode);

	    } else {

		*error=ENOMEM;

	    }

	}

    }

    out:

    return (*error>0) ? -1 : 0;

}


unsigned long long get_nrinodes()
{
    return nrinodes;
}

void decrease_nrinodes()
{
    nrinodes--;
}

unsigned char isrootentry(struct entry_struct *entry)
{
    return (entry==rootentry) ? 1 : 0;
}

struct entry_struct *get_rootentry()
{
    return rootentry;
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

struct inode_struct *remove_inode(fuse_ino_t ino)
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
	    break;

	}

	prev=inode;
	inode=inode->id_next;

    }

    pthread_mutex_unlock(&inode_table_mutex);

    return inode;

}

struct entry_struct *find_entry(struct entry_struct *parent, const char *name)
{
    unsigned int row=0;
    unsigned int error=0;

    return find_entry_by_name_sl(parent, name, &row, &error);

}

/*
    callback to create entry and inode

    note: both are not yet added to the lookuptables (skiplist for entry, hashtable for inode)
*/

struct entry_struct *create_entry_cb(struct entry_struct *parent, const char *name)
{
    struct entry_struct *entry=create_entry(parent, name, NULL);

    if (entry) {

	assign_inode(entry);

	if (entry->inode) {

	    add_inode_hashtable(entry->inode);

	} else {

	    if (entry->name) {

		free(entry->name);
		entry->name=NULL;

	    }

	    free(entry);
	    entry=NULL;

	}

    }

    return entry;

}
