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

#ifndef NOTIFYFS_MAIN_H
#define NOTIFYFS_MAIN_H

#define NOTIFYFS_FSEVENT_NOTSET					0
#define NOTIFYFS_FSEVENT_META					1
#define NOTIFYFS_FSEVENT_FILE					2
#define NOTIFYFS_FSEVENT_MOVE					4
#define NOTIFYFS_FSEVENT_FS					8

#define NOTIFYFS_FSEVENT_META_NOTSET				1
#define NOTIFYFS_FSEVENT_META_ATTRIB_NOTSET			2
#define NOTIFYFS_FSEVENT_META_ATTRIB_MODE			4
#define NOTIFYFS_FSEVENT_META_ATTRIB_OWNER			8
#define NOTIFYFS_FSEVENT_META_ATTRIB_GROUP			16
#define NOTIFYFS_FSEVENT_META_ATTRIB_CA				28
#define NOTIFYFS_FSEVENT_META_XATTR_NOTSET			32
#define NOTIFYFS_FSEVENT_META_XATTR_CREATE			64
#define NOTIFYFS_FSEVENT_META_XATTR_MODIFY			128
#define NOTIFYFS_FSEVENT_META_XATTR_DELETE			256
#define NOTIFYFS_FSEVENT_META_XATTR_CA				448

#define NOTIFYFS_FSEVENT_FILE_NOTSET				1
#define NOTIFYFS_FSEVENT_FILE_MODIFIED				2
#define NOTIFYFS_FSEVENT_FILE_SIZE				4
#define NOTIFYFS_FSEVENT_FILE_OPEN				8
#define NOTIFYFS_FSEVENT_FILE_READ				16
#define NOTIFYFS_FSEVENT_FILE_CLOSE_WRITE			32
#define NOTIFYFS_FSEVENT_FILE_CLOSE_NOWRITE			64
#define NOTIFYFS_FSEVENT_FILE_LOCK_ADD				128
#define NOTIFYFS_FSEVENT_FILE_LOCK_CHANGE			256
#define NOTIFYFS_FSEVENT_FILE_LOCK_REMOVE			512
#define NOTIFYFS_FSEVENT_FILE_LOCK_CA				896
#define NOTIFYFS_FSEVENT_FILE_CA				1022

#define NOTIFYFS_FSEVENT_MOVE_NOTSET				1
#define NOTIFYFS_FSEVENT_MOVE_CREATED				2
#define NOTIFYFS_FSEVENT_MOVE_MOVED				4
#define NOTIFYFS_FSEVENT_MOVE_MOVED_FROM			8
#define NOTIFYFS_FSEVENT_MOVE_MOVED_TO				16
#define NOTIFYFS_FSEVENT_MOVE_DELETED				32
#define NOTIFYFS_FSEVENT_MOVE_NLINKS				64
#define NOTIFYFS_FSEVENT_MOVE_CA				126

#define NOTIFYFS_FSEVENT_FS_NOTSET				1
#define NOTIFYFS_FSEVENT_FS_MOUNT				2
#define NOTIFYFS_FSEVENT_FS_UNMOUNT				4

#define NOTIFYFS_INDEX_TYPE_NONE				0
#define NOTIFYFS_INDEX_TYPE_NAME				1

typedef char pathstring[PATH_MAX+1];

struct nameview_struct {
    char *first_name;
    char *last_name;
};

struct view_struct {
    int first_entry;
    int last_entry;
    int max_nrentries;
    unsigned char type_order;
    union {
	struct nameview_struct name;
    } order;
};

struct fseventmask_struct {
    int type;
    int meta_attrib_event;
    int meta_xattr_event;
    int file_event;
    int move_event;
    int fs_event;
};

#endif
