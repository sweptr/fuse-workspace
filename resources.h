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

#ifndef FUSE_WORKSPACE_RESOURCES_H
#define FUSE_WORKSPACE_RESOURCES_H

#include <netinet/in.h>

#define RESOURCE_GROUP_DISK			1
#define RESOURCE_GROUP_CDROM			2
#define RESOURCE_GROUP_SMB			3
#define RESOURCE_GROUP_FTP			4
#define RESOURCE_GROUP_FILE			5
#define RESOURCE_GROUP_NFS			6

#define RESOURCE_GROUP_MAX			6

#define RESOURCE_SECURITY_NOTSET                0
#define RESOURCE_SECURITY_PRIVATE               1
#define RESOURCE_SECURITY_PUBLIC                2
#define RESOURCE_SECURITY_UNKNOWN               3

#define RESOURCE_STATUS_OK                      1
#define RESOURCE_STATUS_NOTAVAIL                2
#define RESOURCE_STATUS_NOTVALID                3
#define RESOURCE_STATUS_NOPARENT		4

struct localfile_struct {
    unsigned char 			options;
    struct pathinfo_struct 		pathinfo;
};

struct resource_struct {
    unsigned char security;
    unsigned char group;
    unsigned char type;
    unsigned char status;
    int refcount;
    struct timespec detecttime_cache;
    struct timespec detecttime_browse;
    struct resource_struct *next;
    struct resource_struct *prev;
    struct resource_struct *parent;
    void *data;
    unsigned char primary;
    pthread_rwlock_t rwlock;
};

// Prototypes

/* manage resources */

void init_resource(struct resource_struct *resource);
struct resource_struct *get_resource();
void free_resource(struct resource_struct *resource);

int lock_resources();
int unlock_resources();
struct resource_struct *get_next_resource(struct resource_struct *resource);
void insert_resource_list(struct resource_struct *resource);
void remove_resource_list(struct resource_struct *resource);

#endif
