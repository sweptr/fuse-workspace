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

#ifndef NOTIFYFS_WATCHES_H
#define NOTIFYFS_WATCHES_H

#define NOTIFYFS_FSEVENT_DATANAME_LEN				255

#define NOTIFYFS_FSEVENT_STATUS_NONE				0
#define NOTIFYFS_FSEVENT_STATUS_WAITING				1
#define NOTIFYFS_FSEVENT_STATUS_PROCESSED			2
#define NOTIFYFS_FSEVENT_STATUS_DONE				3

/*
    create a structure to distinguish the different watch masks

    first a client can ask for a certain mask, with certain flags

    for example it wants to watch creation and deletion of files and directories in a directory
    and of the directry self

    this means the move_attrib set with flags SELF and CHILDFILES and CHILDMAPS set

    in some cases the backend is not capable to do what the client wants
    for example the clients wants to monitor the attributes of every
    entry in a directory (map and file) but inotify is only
    capable of monitor the changes in files in the directory, 
    and not directory

    for example the creation of a map inside a child directory, will change the mtime and ctime of that
    child directory (nlinks is changed -> ctime is changed, an entry is created ->mtime is changed).
    this change is not detected by inotify

    but when doing a touch of this child directory, this change is detected by inotify

*/

#define NOTIFYFS_WATCHMASK_SELF					1
#define NOTIFYFS_WATCHMASK_CHILDS				2

struct watch_struct {
    unsigned long ctr;
    struct inode_struct *inode;
    struct pathinfo_struct pathinfo;
    struct fseventmask_struct fseventmask;
    pthread_mutex_t mutex;
    int owner_watch_id;
    struct watch_struct *next_hash;
    struct watch_struct *prev_hash;
    struct watch_struct *next;
    struct watch_struct *prev;
};

/* struct to identify and process an event 
    like:
    a create, change or delete of a file/directory
    a mount or unmount
    a lock
*/

struct notifyfs_fsevent_struct {
    unsigned char status;
    struct fseventmask_struct fseventmask;
    struct entry_struct *entry;
    struct pathinfo_struct pathinfo;
    struct timespec detect_time;
    struct timespec process_time;
    struct watch_struct *watch;
    struct notifyfs_fsevent_struct *next;
    struct notifyfs_fsevent_struct *prev;
};


// Prototypes

void init_watch_hashtables();

void lock_watch(struct watch_struct *watch);
void unlock_watch(struct watch_struct *watch);

void add_watch_to_table(struct watch_struct *watch);
void remove_watch_from_table(struct watch_struct *watch);
struct watch_struct *lookup_watch_inode(struct inode_struct *inode);
struct watch_struct *lookup_watch_list(unsigned long ctr);

void add_watch_to_list(struct watch_struct *watch);
void remove_watch_from_list(struct watch_struct *watch);

int add_clientwatch(struct inode_struct *inode, struct fseventmask_struct *fseventmask, int id, struct pathinfo_struct *pathinfo);

void initialize_fsnotify_backends();
void close_fsnotify_backends();

void init_notifyfs_fsevent(struct notifyfs_fsevent_struct *fsevent);
void destroy_notifyfs_fsevent(struct notifyfs_fsevent_struct *fsevent);

void set_watch_backend_os_specific(struct watch_struct *watch);
void change_watch_backend_os_specific(struct watch_struct *watch);
void remove_watch_backend_os_specific(struct watch_struct *watch);

#endif
