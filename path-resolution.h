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

#ifndef OVERLAYFS_PATH_RESOLUTION_H
#define OVERLAYFS_PATH_RESOLUTION_H

typedef char pathstring[PATH_MAX+1];

#define CALL_INFO_INIT	{NULL, {NULL, 0, 0}, 0, 0, 0, 0, 0}

#define PATHINFOFLAGS_NONE		0
#define PATHINFOFLAGS_ALLOCATED		1
#define PATHINFOFLAGS_INUSE		2

#define _OVERLAYFS_MODE_FINISH		1
#define _OVERLAYFS_MODE_VIRTUAL		2

struct pathinfo_struct {
    char *path;
    int len;
    unsigned char flags;
};

struct call_info_struct {
    struct entry_struct *entry;
    struct pathinfo_struct pathinfo;
    pid_t pid;
    uid_t uid;
    gid_t gid;
    mode_t umask;
    unsigned int error;
};

struct overlayfs_dirp_struct {
    struct entry_struct *parent;
    struct entry_struct *entry;
    off_t offset;
    unsigned int fd;
    unsigned char mode;
    struct timespec synctime;
    char *buffer;
    size_t size;
    unsigned int pos;
    unsigned int read;
    unsigned int lenpath;
};

// Prototypes

int get_path(struct call_info_struct *call_info, unsigned int *error);
int get_path_extra(struct call_info_struct *call_info, const char *name, unsigned int *error);

void free_path_pathinfo(struct pathinfo_struct *pathinfo);

int init_pathcache_group(unsigned int *error);
void clean_pathcache();
void add_pathcache(struct pathinfo_struct *pathinfo, struct entry_struct *entry);

void adjust_pathmax(unsigned int len);
unsigned int get_pathmax();

#endif
