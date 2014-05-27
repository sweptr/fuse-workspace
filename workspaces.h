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

#ifndef FUSE_WORKSPACE_WORKSPACES_H
#define FUSE_WORKSPACE_WORKSPACES_H

#define WORKSPACE_RULE_POLICY_NONE		0
#define WORKSPACE_RULE_POLICY_SUFFICIENT	1
#define WORKSPACE_RULE_POLICY_REQUIRED		2

#define WORKSPACE_TYPE_DEVICES			1
#define WORKSPACE_TYPE_NETWORK			2
#define WORKSPACE_TYPE_FILE			3

#define WORKSPACE_FLAG_OK			1
#define WORKSPACE_FLAG_MOUNTED			2

struct workspace_user_struct {
    char *temp_files;
    uid_t private_uidnr;
    gid_t private_gidnr;
    char *private_user;
    char *private_home;
    int nrsessions;
    struct workspace_user_struct *next;
    struct workspace_user_struct *prev;
};

struct workspace_base_struct {
    unsigned int flags;
    unsigned char type;
    char *mount_path_template;
    char *name;
    gid_t ingroup;
    unsigned char ingrouppolicy;
    char *filehastoexist;
    unsigned char filepolicy;
    struct workspace_base_struct *next;
    struct workspace_base_struct *prev;
};

struct fuseparam_struct {
    char 					*mountpoint;
    struct fuse_session 			*session;
    struct fuse_chan 				*chan;
    struct fuse_buf 				buff;
    size_t 					buffsize;
    pthread_mutex_t 				mutex;
    unsigned char				initialized;
};

struct workspace_mount_struct {
    unsigned int 				flags;
    struct workspace_user_struct 		*workspace_user;
    struct workspace_base_struct 		*workspace_base;
    struct inode_struct 			rootinode;
    unsigned long long 				nrinodes;
    struct beventloop_struct 			*beventloop;
    struct fuseparam_struct			fuseparam;
    struct bevent_xdata_struct			bevent_xdata;
    struct workspace_mount_struct 		*next;
    struct workspace_mount_struct 		*prev;
};

void read_workspace_files(char *path);
void update_workspaces(char *user, uid_t uid, unsigned char what);

void increase_inodes_workspace(void *data);
void decrease_inodes_workspace(void *data);

unsigned char isrootentry(struct entry_struct *entry);

void notify_kernel_create(struct workspace_mount_struct *workspace, fuse_ino_t pino, char *name);
void notify_kernel_delete(struct workspace_mount_struct *workspace, fuse_ino_t pino, fuse_ino_t ino, char *name);
void notify_kernel_change(struct workspace_mount_struct *workspace, fuse_ino_t ino, uint32_t mask);

void clear_workspace_mount(struct workspace_mount_struct *workspace_mount);
void clear_all_workspaces();

#endif
