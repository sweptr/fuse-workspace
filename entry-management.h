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

#include <fuse/fuse_lowlevel.h>

#define FSEVENT_INODE_STATUS_OK			1
#define FSEVENT_INODE_STATUS_TOBEREMOVED	2
#define FSEVENT_INODE_STATUS_REMOVED		3
#define FSEVENT_INODE_STATUS_TOBEUNMOUNTED	4
#define FSEVENT_INODE_STATUS_UNMOUNTED		5
#define FSEVENT_INODE_STATUS_SLEEP		6

struct inode_struct {
    fuse_ino_t ino;
    uint64_t nlookup;
    struct inode_struct *id_next;
    struct entry_struct *alias;
    unsigned char status;
    struct stat st;
};

struct entry_struct {
    char *name;
    struct inode_struct *inode;
    struct entry_struct *name_next;
    struct entry_struct *name_prev;
    struct entry_struct *parent;
    int nameindex_value;
};

// Prototypes

int init_hashtables();

void add_to_inode_hash_table(struct inode_struct *inode);
void add_to_name_hash_table(struct entry_struct *entry);
void remove_entry_from_name_hash(struct entry_struct *entry);

struct inode_struct *find_inode_generic(fuse_ino_t inode);

struct entry_struct *find_entry_table(struct entry_struct *parent, const char *name, unsigned char exact);
struct entry_struct *find_entry_generic(fuse_ino_t parent, const char *name);

struct entry_struct *create_entry(struct entry_struct *parent, const char *name, struct inode_struct *inode);
void remove_entry(struct entry_struct *entry);

void init_entry(struct entry_struct *entry);
void assign_inode(struct entry_struct *entry);
int create_root();
unsigned char isrootentry(struct entry_struct *entry);
struct entry_struct *get_rootentry();
unsigned long long get_inoctr();

struct entry_struct *get_next_entry(struct entry_struct *parent, struct entry_struct *entry);

#endif
