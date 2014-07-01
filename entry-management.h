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

#ifndef OVERLAYFS_ENTRY_MANAGEMENT_H
#define OVERLAYFS_ENTRY_MANAGEMENT_H

#include <fuse3/fuse_lowlevel.h>

#define MODEMASK 07777

#ifndef FUSE_SET_ATTR_ATIME_NOW
#define FUSE_SET_ATTR_ATIME_NOW (1 << 7)
#endif

#ifndef FUSE_SET_ATTR_MTIME_NOW
#define FUSE_SET_ATTR_MTIME_NOW (1 << 8)
#endif

#define NAMEINDEX_ROOT1						92			/* number of valid chars*/
#define NAMEINDEX_ROOT2						8464			/* 92 ^ 2 */
#define NAMEINDEX_ROOT3						778688			/* 92 ^ 3 */
#define NAMEINDEX_ROOT4						71639296		/* 92 ^ 4 */
#define NAMEINDEX_ROOT5						6590815232		/* 92 ^ 5 */

#define _ENTRY_FLAG_TEMP					1

#define _DIRECTORY_FLAG_REMOVE					1

#define _DIRECTORY_LOCK_READ					1
#define _DIRECTORY_LOCK_PREEXCL					2
#define _DIRECTORY_LOCK_EXCL					3

#define _INODE_DIRECTORY_SIZE					4096
#define _DEFAULT_BLOCKSIZE					4096

#include "skiplist.h"


struct inode_struct {
    fuse_ino_t 				ino;
    uint64_t 				nlookup;
    struct inode_struct 		*id_next;
    struct entry_struct 		*alias;
    mode_t				mode;
    nlink_t				nlink;
    uid_t				uid;
    gid_t				gid;
    dev_t				rdev;
    off_t				size;
    struct timespec			mtim;
    struct timespec			ctim;
    struct workspace_object_struct	*object;
};

struct entry_struct {
    struct name_struct			name;
    struct inode_struct 		*inode;
    struct entry_struct 		*name_next;
    struct entry_struct 		*name_prev;
    struct entry_struct 		*parent;
    struct timespec			synctime;
    unsigned char			flags;
};

struct directory_struct {
    unsigned char 			flags;
    struct timespec 			synctime;
    struct skiplist_struct		skiplist;
    struct inode_struct 		*inode;
    struct directory_struct		*next;
    struct directory_struct		*prev;
    unsigned int			count;
    pthread_mutex_t			mutex;
    pthread_cond_t			cond;
    pthread_t				write_thread;
    unsigned int			lock;
    struct entry_struct			*first;
    struct entry_struct			*last;
};

// Prototypes

void calculate_nameindex(struct name_struct *name);

int init_hashtables();

int init_inode_hashtable(unsigned int *error);
int init_directory_hashtable(unsigned int *error);

void init_entry(struct entry_struct *entry);
struct entry_struct *create_entry(struct entry_struct *parent, struct name_struct *xname);
void destroy_entry(struct entry_struct *entry);

void init_inode(struct inode_struct *inode);
struct inode_struct *create_inode();
void add_inode_hashtable(struct inode_struct *inode, void (*cb) (void *data), void *data);

struct inode_struct *find_inode(fuse_ino_t ino);
struct inode_struct *remove_inode(fuse_ino_t ino, void (*cb) (void *data), void *data);

struct entry_struct *find_entry(struct entry_struct *parent, struct name_struct *xname, unsigned int *error);
void remove_entry(struct entry_struct *entry, unsigned int *error);
struct entry_struct *insert_entry(struct entry_struct *entry, unsigned int *error, unsigned short flags);

struct entry_struct *find_entry_batch(struct directory_struct *directory, struct name_struct *xname, unsigned int *error);
void remove_entry_batch(struct directory_struct *directory, struct entry_struct *entry, unsigned int *error);
struct entry_struct *insert_entry_batch(struct directory_struct *directory, struct entry_struct *entry, unsigned int *error, unsigned short flags);

struct directory_struct *get_directory(struct inode_struct *inode, unsigned char create, unsigned int *error);
void clear_directory(struct directory_struct *directory, void (*cb) (struct entry_struct *entry));
void destroy_directory(struct directory_struct *directory);

int lock_directory(struct directory_struct *directory, unsigned short flags);
int unlock_directory(struct directory_struct *directory, unsigned short flags);

#endif
