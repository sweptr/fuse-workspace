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

#ifndef FUSE_WORKSPACE_OBJECTS_H
#define FUSE_WORKSPACE_OBJECTS_H

#define _WORKSPACE_READDIR_MODE_FINISH				1
#define _WORKSPACE_READDIR_MODE_NONEMPTY			2

struct workspace_dh_struct {
    struct entry_struct 		*parent;
    struct entry_struct 		*entry;
    struct workspace_object_struct 	*object;
    unsigned int			relpath;
    struct fuse_file_info 		*fi;
    struct pathinfo_struct 		pathinfo;
    struct timespec			synctime;
    struct directory_struct 		*directory;
    off_t 				offset;
    unsigned char 			mode;
    union {
	DIR *dp;
	void *data;
	int nr;
    } handle;
};

struct workspace_fh_struct {
    struct entry_struct *entry;
    struct workspace_object_struct *object;
    struct fuse_file_info *fi;
    unsigned int flags;
    struct pathinfo_struct pathinfo;
    union {
	int fd;
	void *data;
    } handle;
};

struct module_calls_struct {

    char name[32];
    unsigned char groupid;

    void (*init) (struct workspace_object_struct *object);
    void (*destroy) (struct workspace_object_struct *object);

    void (*lookup_cached) (fuse_req_t req, struct entry_struct *entry, struct call_info_struct *call_info);
    void (*lookup_noncached) (fuse_req_t req, struct inode_struct *pinode, struct name_struct *xname, struct call_info_struct *call_info);

    void (*getattr) (fuse_req_t req, struct entry_struct *entry, struct call_info_struct *call_info);
    void (*setattr) (fuse_req_t req, struct entry_struct *entry, struct call_info_struct *call_info, struct stat *st, int fuse_set);

    void (*readlink) (fuse_req_t req, struct entry_struct *entry, struct call_info_struct *call_info);

    void (*mkdir) (fuse_req_t req, struct inode_struct *inode,  struct name_struct *name, struct call_info_struct *call_info, mode_t mode);
    void (*mknod) (fuse_req_t req, struct inode_struct *inode,  struct name_struct *name, struct call_info_struct *call_info, mode_t mode, dev_t rdev);
    void (*symlink) (fuse_req_t req, struct inode_struct *inode,  struct name_struct *name, struct call_info_struct *call_info, const char *link);

    void (*unlink) (fuse_req_t req, struct entry_struct *entry, struct call_info_struct *call_info);
    void (*rmdir) (fuse_req_t req, struct entry_struct *entry, struct call_info_struct *call_info);

    void (*rename_cached) (fuse_req_t req, struct entry_struct *entry, struct call_info_struct *call_info, struct entry_struct *entry_new, struct call_info_struct *call_info_new);
    void (*rename_noncached) (fuse_req_t req, struct entry_struct *entry, struct call_info_struct *call_info, struct inode_struct *pinode, struct name_struct *xname, struct call_info_struct *call_info_new);

    void (*open) (fuse_req_t req, struct workspace_fh_struct *fh);
    void (*read) (fuse_req_t req, size_t size, off_t off, struct workspace_fh_struct *fh);
    void (*write) (fuse_req_t req, const char *buff, size_t size, off_t off, struct workspace_fh_struct *fh);
    void (*flush) (fuse_req_t req, struct workspace_fh_struct *fh);
    void (*fsync) (fuse_req_t req, int datasync, struct workspace_fh_struct *fh);
    void (*release) (fuse_req_t req, struct workspace_fh_struct *fh);
    void (*create) (fuse_req_t req, struct inode_struct *pinode, struct name_struct *xname, struct workspace_fh_struct *fh, mode_t mode);

    void (*fgetattr) (fuse_req_t req, struct workspace_fh_struct *fh);
    void (*fsetattr) (fuse_req_t req, struct workspace_fh_struct *fh, struct stat *st, int fuse_set);

    void (*opendir) (fuse_req_t req, struct workspace_dh_struct *dh);
    void (*readdir) (fuse_req_t req, size_t size, off_t offset, struct workspace_dh_struct *dh);
    void (*readdirplus) (fuse_req_t req, size_t size, off_t offset, struct workspace_dh_struct *dh);
    void (*releasedir) (fuse_req_t req, struct workspace_dh_struct *dh);
    void (*fsyncdir) (fuse_req_t req, int datasync, struct workspace_dh_struct *dh);

    void (*fsnotify) (fuse_req_t req, struct entry_struct *entry, struct call_info_struct *call_info, uint32_t mask);

    struct module_calls_struct *next;

};

struct workspace_object_struct {
    struct inode_struct *inode;
    struct module_calls_struct module_calls;
    struct workspace_object_struct *parent;
    struct workspace_object_struct *next;
    struct workspace_object_struct *prev;
    struct workspace_mount_struct *workspace_mount;
    struct timespec *refresh_time;
    struct timespec *detect_time;
    unsigned char primary;
    struct resource_struct *resource;
};


// Prototypes

void init_module_calls(struct module_calls_struct *module_calls);
struct workspace_object_struct *get_workspace_object();

int create_object(char **uri, struct inode_struct *inode, struct workspace_mount_struct *workspace, unsigned char group, unsigned int *error);


#endif
