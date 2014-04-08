/*
  2010, 2011 Stef Bon <stefbon@gmail.com>

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
    union {
	off_t				size;
	void 				*directory;
    } type;
    struct timespec			mtim;
    struct timespec			ctim;
};

struct entry_struct {
    char 				*name;
    struct inode_struct 		*inode;
    struct entry_struct 		*name_next;
    struct entry_struct 		*name_prev;
    struct entry_struct 		*parent;
    unsigned int 			nameindex_value;
    struct timespec			synctime;
};

// Prototypes

int init_hashtables();

int init_inode_hashtable(unsigned int *error);

void init_entry(struct entry_struct *entry);
struct entry_struct *create_entry(struct entry_struct *parent, const char *name, struct inode_struct *inode);
void remove_entry(struct entry_struct *entry);

void assign_inode(struct entry_struct *entry);
void add_inode_hashtable(struct inode_struct *inode);

int create_root(unsigned int *error);

unsigned char isrootentry(struct entry_struct *entry);
struct entry_struct *get_rootentry();

unsigned long long get_nrinodes();
void decrease_nrinodes();

struct inode_struct *find_inode(fuse_ino_t ino);
struct inode_struct *remove_inode(fuse_ino_t ino);
struct entry_struct *find_entry(struct entry_struct *parent, const char *name);

struct entry_struct *create_entry_cb(struct entry_struct *parent, const char *name);

#endif
