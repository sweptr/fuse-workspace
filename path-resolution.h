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

struct generic_dirp_struct {
    struct entry_struct *parent;
    char *name;
    struct stat st;
    off_t upperfs_offset;
    void *data;
    unsigned char virtual;
};

// Prototypes

int get_path(struct call_info_struct *call_info, const char *name);
void free_path_pathinfo(struct pathinfo_struct *pathinfo);
struct entry_struct *check_notifyfs_path(char *path);

#endif
