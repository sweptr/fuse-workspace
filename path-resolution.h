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

#define PATH_INFO_INIT	{NULL, NULL, 0, NULL}

struct path_info_struct {
    struct entry_struct *parent;
    char *path;
    unsigned char freepath;
    const struct fuse_ctx *ctx;
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

int get_path(struct path_info_struct *path_info, const char *name);
void clear_path_info(struct path_info_struct *path_info);

#endif
