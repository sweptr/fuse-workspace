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
#include <sys/types.h>
#include <sys/stat.h>
#include <semaphore.h>
#include <pthread.h>

#ifndef ENOATTR
#define ENOATTR ENODATA        /* No such attribute */
#endif

#include <fuse/fuse_lowlevel.h>

#include "logging.h"
#include "utils.h"
#include "entry-management.h"

#ifndef SIZE_INODE_HASHTABLE
#define SIZE_INODE_HASHTABLE			32768
#endif

#define ENTRY_NAMELEN_AVERAGE			32

/*
    basic setup of index 

*/

#define DIRECTORYINDEX_SIZE			100
#define NAMEINDEX_ROOT1				92
#define NAMEINDEX_ROOT2				8464
#define NAMEINDEX_ROOT3				778688

struct directory_struct {
    int count;
    sem_t readers_sem;
    sem_t writers_sem;
    int nrreaders;
    struct entry_struct *nameindex[NAMEINDEX_ROOT1];
};

typedef struct {
    int size_dirindex;
    int size_nameindex1;
    int size_nameindex2;
    struct directory_struct directory_table[DIRECTORYINDEX_SIZE];
} hash_table_t;

hash_table_t hash_table;

struct inode_struct **inode_hash_table;
struct entry_struct *rootentry=NULL;

unsigned long long inoctr=FUSE_ROOT_ID;

pthread_mutex_t inodectrmutex=PTHREAD_MUTEX_INITIALIZER;

struct stat default_stat;

int init_hashtables()
{
    int nreturn=0, i, j;

    inode_hash_table = calloc(SIZE_INODE_HASHTABLE, sizeof(struct inode_struct *));

    if ( ! inode_hash_table ) {

	nreturn=-ENOMEM;
	goto out;

    }

    /* initialize */

    for (i=1;i<=DIRECTORYINDEX_SIZE;i++) {

	hash_table.directory_table[i-1].count=0;

	/* create a semaphore to be shared between processes 
	*/

	sem_init(&hash_table.directory_table[i-1].readers_sem, 1, 0);
	sem_init(&hash_table.directory_table[i-1].writers_sem, 1, 0);

	for (j=1;j<=NAMEINDEX_ROOT1;j++) {

	    hash_table.directory_table[i-1].nameindex[j-1]=NULL;

	}

	/* make it available ... */

	hash_table.directory_table[i-1].nrreaders=0;

	sem_post(&hash_table.directory_table[i-1].readers_sem);
	sem_post(&hash_table.directory_table[i-1].writers_sem);

    }

    hash_table.size_dirindex=DIRECTORYINDEX_SIZE;
    hash_table.size_nameindex1=NAMEINDEX_ROOT1;
    hash_table.size_nameindex2=NAMEINDEX_ROOT2;

    out:

    return nreturn;

}

void add_to_inode_hash_table(struct inode_struct *inode)
{
    size_t hash = inode->ino % SIZE_INODE_HASHTABLE;

    inode->id_next = inode_hash_table[hash];
    inode_hash_table[hash] = inode;

}

void readlock_directory(struct directory_struct *directory)
{

    /* get the readers semaphore */

    sem_wait(&directory->readers_sem);

    if (directory->nrreaders==0) {

	/* prevent writers */

	sem_wait(&directory->writers_sem);

    }

    directory->nrreaders++;

    sem_post(&directory->readers_sem);

}

void readunlock_directory(struct directory_struct *directory)
{

    /* get the readers semaphore */

    sem_wait(&directory->readers_sem);

    directory->nrreaders--;

    if (directory->nrreaders==0) {

	/* prevent writers */

	sem_post(&directory->writers_sem);

    }

    sem_post(&directory->readers_sem);

}



void writelock_directory(struct directory_struct *directory)
{

    sem_wait(&directory->writers_sem);

}

void writeunlock_directory(struct directory_struct *directory)
{

    sem_post(&directory->writers_sem);

}

int calculate_nameindex_value(char *name)
{
    int nameindex_value=0, lenname=strlen(name);
    unsigned char firstletter=*(name)-31;
    unsigned char secondletter=0;
    unsigned char thirdletter=0;
    unsigned char fourthletter=0;

    if (lenname>=4) {

	secondletter=*(name+1)-31;
	thirdletter=*(name+2)-31;
	fourthletter=*(name+3)-31;

    } else if (lenname==3) {

	secondletter=*(name+1)-31;
	thirdletter=*(name+2)-31;

    } else if (lenname==2) {

	secondletter=*(name+1)-31;

    }

    nameindex_value=firstletter * NAMEINDEX_ROOT3 + secondletter * NAMEINDEX_ROOT2 + thirdletter * NAMEINDEX_ROOT1 + fourthletter;

    return nameindex_value;

}


void add_to_name_hash_table(struct entry_struct *entry)
{
    int nameindex_value=0, res;
    char *name=entry->name;
    unsigned char firstletter=*(name)-31;
    int inoindex=0;
    struct entry_struct *next_entry, *keep_entry=NULL;
    struct directory_struct *directory=NULL;

    if ( ! entry->parent ) {

	logoutput("add_to_name_hash_table: %s has no parent", entry->name);
	return;

    }

    logoutput("add_to_name_hash_table: add %s", entry->name);

    inoindex=entry->parent->inode->ino % DIRECTORYINDEX_SIZE;

    directory=&(hash_table.directory_table[inoindex]);

    /* lock the directory table : set a write lock */

    writelock_directory(directory);

    nameindex_value=calculate_nameindex_value(name);
    entry->nameindex_value=nameindex_value;

    next_entry=directory->nameindex[firstletter];

    while (next_entry) {

	keep_entry=next_entry;

	if (nameindex_value==next_entry->nameindex_value) {

	    /* look futher, indexvalue is the same, but the name may differ */

	    while (next_entry) {

		keep_entry=next_entry;

		res=strcmp(next_entry->name, entry->name);

		if (res>=0) {

		    if (res==0) {

			logoutput("add_to_name_hash_table: %s already present!", entry->name);
			goto out;

		    }

		    goto insert;

		}

		next_entry=next_entry->name_next;

	    }

	    break;

	} else if (nameindex_value<next_entry->nameindex_value) {

	    /* index value bigger, so the name is also "bigger": the right next value is found */

	    break;

	}

	next_entry=next_entry->name_next;

    }

    insert:

    if (next_entry) {

	/* a next entry is found */

	directory->count++;

	entry->name_next=next_entry;

	if (next_entry==directory->nameindex[firstletter]) {

	    directory->nameindex[firstletter]=entry;
	    entry->name_prev=NULL;

	} else {

	    entry->name_prev=next_entry->name_prev;
	    next_entry->name_prev->name_next=entry;

	}

	next_entry->name_prev=entry;

    } else if (keep_entry) {

	/* next entry is empty, but a "prev" entry is found 
	probably at end of list
	*/

	directory->count++;

	keep_entry->name_next=entry;
	entry->name_prev=keep_entry;

	entry->name_next=NULL;

    } else {

	/* no next and prev, probably empty */

	directory->count++;

	directory->nameindex[firstletter]=entry;

	entry->name_next=NULL;
	entry->name_prev=NULL;

    }

    out:

    /* unlock the directory table */

    writeunlock_directory(directory);

}

void remove_entry_from_name_hash(struct entry_struct *entry)
{
    struct entry_struct *next=entry->name_next;
    struct entry_struct *prev=entry->name_prev;
    unsigned char firstletter=*(entry->name)-31;
    int inoindex=0;
    struct nameindex_struct *nameindex=NULL;
    struct directory_struct *directory=NULL;

    if ( ! entry->parent ) return;

    inoindex=entry->parent->inode->ino % DIRECTORYINDEX_SIZE;

    directory=&(hash_table.directory_table[inoindex]);

    /* lock the directory table : set a write lock */
    writelock_directory(directory);

    if (entry==directory->nameindex[firstletter]) directory->nameindex[firstletter]=next;
    if (next) next->name_prev=prev;
    if (prev) prev->name_next=next;

    entry->name_prev=NULL;
    entry->name_next=NULL;

    directory->count--;

    /* unlock the directory table */

    writeunlock_directory(directory);

}

struct inode_struct *find_inode_generic(fuse_ino_t ino)
{
    struct inode_struct *inode = inode_hash_table[ino % SIZE_INODE_HASHTABLE];

    while (inode && inode->ino != ino) inode = inode->id_next;

    return inode;

}

struct entry_struct *find_entry_table(struct entry_struct *parent, const char *name, unsigned char exact)
{
    int nameindex_value=0, lenname=strlen(name);
    unsigned char firstletter=*(name)-31;
    int inoindex=parent->inode->ino % DIRECTORYINDEX_SIZE;
    struct entry_struct *entry=NULL;
    struct directory_struct *directory=NULL;

    logoutput("find_entry_table: search for %s in %s", name, parent->name);

    /* lock the directory table : set a read lock */

    directory=&(hash_table.directory_table[inoindex]);

    readlock_directory(directory);

    if (directory->count==0) goto out;

    nameindex_value=calculate_nameindex_value((char *) name);

    while (firstletter<NAMEINDEX_ROOT1) {

	if (! directory->nameindex[firstletter]) {

	    /* no entries here */

	    if (exact==1) {

		/* when looking for an exact match, then ready: not found */

		entry=NULL;
		break;

	    } else {

		/* when looking for a non exact match (=the first best match), try the next nameindex */

		firstletter++;
		continue;

	    }

	}

	entry=directory->nameindex[firstletter];

	while (entry) {

	    if (nameindex_value>entry->nameindex_value) {

		/* before name */

		entry=entry->name_next;
		continue;

	    } else if (nameindex_value==entry->nameindex_value) {

		while (entry) {

		    /* index value (first 4 letters) is the same : compare full names */

		    if (entry->parent==parent) {

			if (strcmp(entry->name, name)==0) {

			    goto out;

			} else if (strcmp(entry->name, name)>0 && exact==0) {

			    goto out;

			}

		    }

		    entry=entry->name_next;

		    if (! entry) goto out;

		    if (nameindex_value<entry->nameindex_value) {

			if (exact==1) {

			    entry=NULL;
			    goto out;

			} else {

			    goto out;

			}

		    }

		}

	    } else if (nameindex_value<entry->nameindex_value) {

		/* past name */

		if (exact==1) {

		    entry=NULL;
		    break;

		} else {

		    break;

		}

	    }

	}

	if (!entry) {

	    if (exact==0) {

		/* not exact : just try the next nameindex */

		firstletter++;
		continue;

	    }

	}

	break;

    }

    out:

    /* unlock the directory table */

    readunlock_directory(directory);

    return entry;

}

struct entry_struct *find_entry_generic(fuse_ino_t ino, const char *name)
{
    struct inode_struct *inode=find_inode_generic(ino);

    if (inode) {

	if (inode->alias) {

	    /* find the entry in the directory table (exact) */

	    return find_entry_table(inode->alias, name, 1);

	}

    }

    return NULL;

}

static struct entry_struct *lookup_first_entry(struct entry_struct *parent, struct directory_struct *directory, unsigned char i)
{
    struct entry_struct *entry=NULL;

    while ( i<NAMEINDEX_ROOT1 && ! entry) {

	if (directory->nameindex[i]) {

	    entry=directory->nameindex[i];

	    while (entry) {

		if (entry->parent==parent) goto out;

		entry=entry->name_next;

	    }

	}

	i++;

    }

    out:

    return entry;

}

/* function which does a lookup of the next entry with the same parent 
    used for getting the contents of a directory */

struct entry_struct *get_next_entry(struct entry_struct *parent, struct entry_struct *entry)
{
    int inoindex=parent->inode->ino % DIRECTORYINDEX_SIZE;
    struct directory_struct *directory=NULL;

    directory=&(hash_table.directory_table[inoindex]);

    /* lock the directory table : set a read lock */

    readlock_directory(directory);

    if (directory->count==0) {

	entry=NULL;
	goto out;

    }

    if ( ! entry) {

	entry=lookup_first_entry(parent, directory, 0);

    } else {
	unsigned char i=*(entry->name)-31; /* remember the current row */

	entry=entry->name_next;

	/* next entry in the list must have the same parent */

	while (entry) {

	    if (entry->parent==parent) break;

	    entry=entry->name_next;

	}

	if ( ! entry) {

	    /* look in the first next tabel */

	    entry=lookup_first_entry(parent, directory, i+1);

	}

    }

    out:

    /* unlock the directory table */

    readunlock_directory(directory);

    return entry;

}

void init_entry(struct entry_struct *entry)
{
    entry->inode=NULL;
    entry->name=NULL;

    entry->parent=NULL;
    entry->name_next=NULL;
    entry->name_prev=NULL;

    entry->nameindex_value=0;

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

void clear_stat(struct stat *st)
{
    st->st_dev=0;
    st->st_ino=0;
    st->st_mode=0;
    st->st_nlink=0;
    st->st_uid=0;
    st->st_gid=0;
    st->st_rdev=0;
    st->st_size=0;
    st->st_blksize=0;
    st->st_blocks=0;
    st->st_atim.tv_sec=0;
    st->st_atim.tv_nsec=0;
    st->st_mtim.tv_sec=0;
    st->st_mtim.tv_nsec=0;
    st->st_ctim.tv_sec=0;
    st->st_ctim.tv_nsec=0;

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
	inode->status=FSEVENT_INODE_STATUS_OK;

	clear_stat(&inode->st);

	inoctr++;

    }

    pthread_mutex_unlock(&inodectrmutex);

    return inode;

}

void assign_inode(struct entry_struct *entry)
{

    entry->inode=create_inode();

    if ( entry->inode ) {

	entry->inode->alias=entry;

    }

}

/* create the root inode and entry */

int create_root()
{
    int nreturn=0;

    if ( rootentry ) goto out;

    /* rootentry (no parent) */

    rootentry=create_entry(NULL, ".", NULL);

    if (rootentry) {

	assign_inode(rootentry);

	if (rootentry->inode) {

	    logoutput("create_root: created rootentry %s with ino %li", rootentry->name, rootentry->inode->ino);

	    add_to_inode_hash_table(rootentry->inode);
	    add_to_name_hash_table(rootentry);

	} else {

	    nreturn=-ENOMEM;

	}

    } else {

	nreturn=-ENOMEM;

    }

    out:

    return nreturn;

}


unsigned long long get_inoctr()
{
    return inoctr;
}

unsigned char isrootentry(struct entry_struct *entry)
{
    return (entry==rootentry) ? 1 : 0;
}

struct entry_struct *get_rootentry()
{
    return rootentry;
}

