/*
  2010, 2011, 2012, 2103, 2014 Stef Bon <stefbon@gmail.com>

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

#include "global-defines.h"

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <err.h>
#include <sys/time.h>
#include <time.h>
#include <pthread.h>
#include <ctype.h>
#include <inttypes.h>

#include <sys/param.h>
#include <sys/types.h>
#include <sys/fsuid.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <math.h>
#include <sys/vfs.h>

#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif

#ifndef ENOATTR
#define ENOATTR ENODATA        /* No such attribute */
#endif

#ifdef LOGGING

#include <syslog.h>

static unsigned char loglevel=1;

static inline void open_logoutput()
{
    openlog("fuse-workspace", 0, LOG_SYSLOG);
}

static inline void close_logoutput()
{
    closelog();

}

#define logoutput_debug(...) if (loglevel >= 5) syslog(LOG_DEBUG, __VA_ARGS__)
#define logoutput_info(...) if (loglevel >= 4) syslog(LOG_INFO, __VA_ARGS__)
#define logoutput_notice(...) if (loglevel >= 3) syslog(LOG_NOTICE, __VA_ARGS__)
#define logoutput_warning(...) if (loglevel >= 2) syslog(LOG_WARNING, __VA_ARGS__)
#define logoutput_error(...) if (loglevel >= 1) syslog(LOG_ERR, __VA_ARGS__)

#define logoutput(...) if (loglevel >= 1) syslog(LOG_DEBUG, __VA_ARGS__)

#else

static inline void open_logoutput()
{
    return;

}

static inline void close_logoutput()
{
    return;

}

static inline void dummy_nolog()
{
    return;

}

#define logoutput_debug(...) dummy_nolog()
#define logoutput_info(...) dummy_nolog()
#define logoutput_notice(...) dummy_nolog()
#define logoutput_warning(...) dummy_nolog()
#define logoutput_error(...) dummy_nolog()

#endif

#include "fuse-workspace.h"
#include "workerthreads.h"
#include "beventloop-utils.h"

#include "entry-management.h"

#include "path-resolution.h"
#include "utils.h"
#include "options.h"

#include "fschangenotify.h"
#include "fschangenotify-event.h"
#include "fschangenotify-fssync.h"

#include "monitorsessions.h"
#include "readdir-utils.h"

#include "workspaces.h"
#include "resources.h"
#include "objects.h"

struct fs_options_struct fs_options;
struct workerthreads_queue_struct workerthreads_queue;
char *program_name=NULL;

extern const char *rootpath;
extern const char *dotdotname;
extern const char *dotname;

pid_t gettid()
{
    return (pid_t) syscall(SYS_gettid);
}

static void workspace_lookup(fuse_req_t req, fuse_ino_t ino, const char *name)
{
    struct inode_struct *pinode=NULL;
    struct workspace_mount_struct *workspace_mount=(struct workspace_mount_struct *) fuse_req_userdata(req);

    logoutput("LOOKUP: name %s, parent ino %li (thread %i)", name, (long) ino, (int) gettid());

    if (ino==FUSE_ROOT_ID) {

	pinode=&workspace_mount->rootinode;

    } else {

	pinode=find_inode(ino);

    }

    if (pinode) {
	struct entry_struct *entry = NULL;
	struct entry_struct *parent = pinode->alias;
	struct name_struct xname={NULL, 0, 0};
	unsigned int error=0;
	struct call_info_struct call_info=CALL_INFO_INIT;
	const struct fuse_ctx *ctx=fuse_req_ctx(req);

	xname.name=(char *) name;
	xname.len=strlen(name);

	calculate_nameindex(&xname);

	call_info.pid=ctx->pid;
	call_info.uid=ctx->uid;
	call_info.gid=ctx->gid;
	call_info.umask=ctx->umask;

	call_info.pathinfo.path=NULL;
	call_info.pathinfo.len=0;
	call_info.pathinfo.flags=0;

	call_info.workspace_mount=workspace_mount;

	entry=find_entry(parent, &xname, &error);

	if (entry) {

	    if (get_path(&call_info, entry, &error)==0) {
		struct workspace_object_struct *object=call_info.object;

		(* object->module_calls.lookup_cached) (req, entry, &call_info);

		return;

	    } else {

		free_path_pathinfo(&call_info.pathinfo);
		fuse_reply_err(req, error);


	    }

	} else {

	    if (get_path_extra(&call_info, parent, &xname, &error)==0) {
		struct workspace_object_struct *object=call_info.object;

		(* object->module_calls.lookup_noncached) (req, pinode, &xname, &call_info);

		return;

	    } else {

		free_path_pathinfo(&call_info.pathinfo);
		fuse_reply_err(req, error);

	    }

	}

    } else {

	fuse_reply_err(req, ENOENT);

    }

}

static void workspace_forget(fuse_req_t req, fuse_ino_t ino, uint64_t nlookup)
{
    struct inode_struct *inode;
    struct workspace_mount_struct *workspace_mount=(struct workspace_mount_struct *) fuse_req_userdata(req);

    logoutput("FORGET: ino %li (thread %i)", (long) ino, (int) gettid());

    inode = remove_inode(ino, decrease_inodes_workspace, (void *) workspace_mount);

    if (inode) {

	if (inode->alias) {
	    struct entry_struct *entry=inode->alias;

	    logoutput("forget, entry %s does still exist", entry->name.name);

	} else {
	    if ( inode->nlookup < nlookup ) {

		logoutput("internal error: forget ino=%llu %llu from %llu", (unsigned long long) ino, (unsigned long long) nlookup, (unsigned long long) inode->nlookup);
		inode->nlookup=0;

	    } else {

    		inode->nlookup -= nlookup;

		logoutput("forget, current nlookup value %llu", (unsigned long long) inode->nlookup);

	    }

	    free(inode);

	}

    }

    out:

    fuse_reply_none(req);

}

static void workspace_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{

    if (fi) {

	if (fi->fh) {
	    struct workspace_fh_struct *fh=(struct workspace_fh_struct *) (uintptr_t) fi->fh;

	    logoutput("FGETATTR (thread %i)", (int) gettid());

	    (* fh->object->module_calls.fgetattr) (req, fh);

	    return;

	}

    }

    struct inode_struct *inode=NULL;
    struct workspace_mount_struct *workspace_mount=(struct workspace_mount_struct *) fuse_req_userdata(req);

    logoutput("GETATTR (thread %i)", (int) gettid());

    if (ino==FUSE_ROOT_ID) {

	inode=&workspace_mount->rootinode;

    } else {

	inode=find_inode(ino);

    }

    if (inode) {
	struct call_info_struct call_info=CALL_INFO_INIT;
	unsigned int error=0;
	const struct fuse_ctx *ctx=fuse_req_ctx(req);

	call_info.pid=ctx->pid;
	call_info.uid=ctx->uid;
	call_info.gid=ctx->gid;
	call_info.umask=ctx->umask;

	call_info.pathinfo.path=NULL;
	call_info.pathinfo.len=0;
	call_info.pathinfo.flags=0;

	call_info.workspace_mount=workspace_mount;

	if (get_path(&call_info, inode->alias, &error)==0) {
	    struct workspace_object_struct *object=call_info.object;

	    logoutput("GETATTR: path %s", call_info.pathinfo.path);

	    (* object->module_calls.getattr) (req, inode->alias, &call_info);

	    return;

	} else {

	    fuse_reply_err(req, error);

	}

	free_path_pathinfo(&call_info.pathinfo);

    } else {

	fuse_reply_err(req, ENOENT);

    }

}

static void workspace_setattr(fuse_req_t req, fuse_ino_t ino, struct stat *st, int fuse_set, struct fuse_file_info *fi)
{

    if (fi) {

	if (fi->fh) {
	    struct workspace_fh_struct *fh=(struct workspace_fh_struct *) (uintptr_t) fi->fh;

	    logoutput("FSETATTR (thread %i)", (int) gettid());

	    (* fh->object->module_calls.fsetattr) (req, fh, st, fuse_set);

	    return;

	}

    }

    struct inode_struct *inode=NULL;
    struct workspace_mount_struct *workspace_mount=(struct workspace_mount_struct *) fuse_req_userdata(req);

    logoutput("SETATTR (thread %i)", (int) gettid());

    if (ino==FUSE_ROOT_ID) {

	inode=&workspace_mount->rootinode;

    } else {

	inode=find_inode(ino);

    }

    if (inode) {
	struct call_info_struct call_info=CALL_INFO_INIT;
	unsigned int error=0;
	const struct fuse_ctx *ctx=fuse_req_ctx(req);

	call_info.pid=ctx->pid;
	call_info.uid=ctx->uid;
	call_info.gid=ctx->gid;
	call_info.umask=ctx->umask;

	call_info.pathinfo.path=NULL;
	call_info.pathinfo.len=0;
	call_info.pathinfo.flags=0;

	call_info.workspace_mount=workspace_mount;

	if (get_path(&call_info, inode->alias, &error)==0) {
	    struct workspace_object_struct *object=call_info.object;

	    (* object->module_calls.setattr) (req, inode->alias, &call_info, st, fuse_set);

	    return;

	} else {

	    fuse_reply_err(req, error);

	}

	free_path_pathinfo(&call_info.pathinfo);

    } else {

	fuse_reply_err(req, ENOENT);

    }

}

static void workspace_mkdir(fuse_req_t req, fuse_ino_t ino, const char *name, mode_t mode)
{
    struct inode_struct *pinode=NULL;
    struct workspace_mount_struct *workspace_mount=(struct workspace_mount_struct *) fuse_req_userdata(req);

    if (ino==FUSE_ROOT_ID) {

	pinode=&workspace_mount->rootinode;

    } else {

	pinode=find_inode(ino);

    }

    logoutput("MKDIR, name: %s (thread %i)", name, (int) gettid());

    if (pinode) {
	struct entry_struct *entry = NULL;
	struct entry_struct *parent = pinode->alias;
	struct name_struct xname={NULL, 0, 0};
	unsigned int error=0;

	xname.name=(char *) name;
	xname.len=strlen(name);

	calculate_nameindex(&xname);

	entry=find_entry(parent, &xname, &error);

	if (! entry) {
	    struct call_info_struct call_info=CALL_INFO_INIT;
	    const struct fuse_ctx *ctx=fuse_req_ctx(req);

	    call_info.pid=ctx->pid;
	    call_info.uid=ctx->uid;
	    call_info.gid=ctx->gid;
	    call_info.umask=ctx->umask;

	    call_info.pathinfo.path=NULL;
	    call_info.pathinfo.len=0;
	    call_info.pathinfo.flags=0;

	    call_info.workspace_mount=workspace_mount;

	    if (get_path_extra(&call_info, parent, &xname, &error)==0) {
		struct workspace_object_struct *object=call_info.object;

		(* object->module_calls.mkdir) (req, pinode, &xname, &call_info, mode);

		return;

	    } else {

		fuse_reply_err(req, error);

	    }

	    free_path_pathinfo(&call_info.pathinfo);

	} else {

	    fuse_reply_err(req, EEXIST);

	}

    } else {

	fuse_reply_err(req, ENOENT);

    }

}

static void workspace_mknod(fuse_req_t req, fuse_ino_t ino, const char *name, mode_t mode, dev_t rdev)
{
    struct inode_struct *pinode=NULL;
    struct workspace_mount_struct *workspace_mount=(struct workspace_mount_struct *) fuse_req_userdata(req);

    logoutput("MKNOD, name: %s (thread %i)", name, (int) gettid());

    if (ino==FUSE_ROOT_ID) {

	pinode=&workspace_mount->rootinode;

    } else {

	pinode=find_inode(ino);

    }

    if (pinode) {
	struct entry_struct *entry = NULL;
	struct entry_struct *parent = pinode->alias;
	struct name_struct xname={NULL, 0, 0};
	unsigned int error=0;

	xname.name=(char *) name;
	xname.len=strlen(name);

	calculate_nameindex(&xname);

	entry=find_entry(parent, &xname, &error);

	if (! entry) {
	    struct call_info_struct call_info=CALL_INFO_INIT;
	    const struct fuse_ctx *ctx=fuse_req_ctx(req);

	    call_info.pid=ctx->pid;
	    call_info.uid=ctx->uid;
	    call_info.gid=ctx->gid;
	    call_info.umask=ctx->umask;

	    call_info.pathinfo.path=NULL;
	    call_info.pathinfo.len=0;
	    call_info.pathinfo.flags=0;

	    call_info.workspace_mount=workspace_mount;

	    if (get_path_extra(&call_info, parent, &xname, &error)==0) {
		struct workspace_object_struct *object=call_info.object;

		(* object->module_calls.mknod) (req, pinode, &xname, &call_info, mode, rdev);

		return;

	    } else {

		fuse_reply_err(req, error);

	    }

	    free_path_pathinfo(&call_info.pathinfo);

	} else {

	    fuse_reply_err(req, EEXIST);

	}

    } else {

	fuse_reply_err(req, ENOENT);

    }

}

static void workspace_symlink(fuse_req_t req, const char *link, fuse_ino_t ino, const char *name)
{
    struct inode_struct *pinode=NULL;
    struct workspace_mount_struct *workspace_mount=(struct workspace_mount_struct *) fuse_req_userdata(req);

    logoutput("SYMLINK, name: %s (thread %i)", name, (int) gettid());

    if (ino==FUSE_ROOT_ID) {

	pinode=&workspace_mount->rootinode;

    } else {

	pinode=find_inode(ino);

    }

    if (pinode) {
	struct entry_struct *entry = NULL;
	struct entry_struct *parent = pinode->alias;
	struct name_struct xname={NULL, 0, 0};
	unsigned int error=0;

	xname.name=(char *) name;
	xname.len=strlen(name);

	calculate_nameindex(&xname);

	entry=find_entry(parent, &xname, &error);

	if (! entry) {
	    struct call_info_struct call_info=CALL_INFO_INIT;
	    const struct fuse_ctx *ctx=fuse_req_ctx(req);

	    call_info.pid=ctx->pid;
	    call_info.uid=ctx->uid;
	    call_info.gid=ctx->gid;
	    call_info.umask=ctx->umask;

	    call_info.pathinfo.path=NULL;
	    call_info.pathinfo.len=0;
	    call_info.pathinfo.flags=0;

	    call_info.workspace_mount=workspace_mount;

	    if (get_path_extra(&call_info, parent, &xname, &error)==0) {
		struct workspace_object_struct *object=call_info.object;

		(* object->module_calls.symlink) (req, pinode, &xname, &call_info, link);

		return;

	    } else {

		fuse_reply_err(req, error);

	    }

	    free_path_pathinfo(&call_info.pathinfo);

	} else {

	    fuse_reply_err(req, EEXIST);

	}

    } else {

	fuse_reply_err(req, ENOENT);

    }

}

static void workspace_rmdir(fuse_req_t req, fuse_ino_t ino, const char *name)
{
    struct inode_struct *pinode=NULL;
    struct workspace_mount_struct *workspace_mount=(struct workspace_mount_struct *) fuse_req_userdata(req);

    logoutput("RMDIR, name: %s (thread %i)", name, (int) gettid());

    if (ino==FUSE_ROOT_ID) {

	pinode=&workspace_mount->rootinode;

    } else {

	pinode=find_inode(ino);

    }

    if (pinode) {
	struct entry_struct *entry = NULL;
	struct entry_struct *parent = pinode->alias;
	struct name_struct xname={NULL, 0, 0};
	unsigned int error=0;

	xname.name=(char *) name;
	xname.len=strlen(name);

	calculate_nameindex(&xname);

	entry=find_entry(parent, &xname, &error);

	if (entry) {
	    struct call_info_struct call_info=CALL_INFO_INIT;
	    const struct fuse_ctx *ctx=fuse_req_ctx(req);

	    call_info.pid=ctx->pid;
	    call_info.uid=ctx->uid;
	    call_info.gid=ctx->gid;
	    call_info.umask=ctx->umask;

	    call_info.pathinfo.path=NULL;
	    call_info.pathinfo.len=0;
	    call_info.pathinfo.flags=0;

	    call_info.workspace_mount=workspace_mount;

	    if (get_path(&call_info, entry, &error)==0) {
		struct workspace_object_struct *object=call_info.object;

		(* object->module_calls.rmdir) (req, entry, &call_info);

		return;

	    } else {

		fuse_reply_err(req, error);

	    }

	    free_path_pathinfo(&call_info.pathinfo);

	} else {

	    fuse_reply_err(req, ENOENT);

	}

    } else {

	fuse_reply_err(req, ENOENT);

    }

}

static void workspace_unlink(fuse_req_t req, fuse_ino_t ino, const char *name)
{
    struct inode_struct *pinode=NULL;
    struct workspace_mount_struct *workspace_mount=(struct workspace_mount_struct *) fuse_req_userdata(req);

    logoutput("UNLINK, name: %s (thread %i)", name, (int) gettid());

    if (ino==FUSE_ROOT_ID) {

	pinode=&workspace_mount->rootinode;

    } else {

	pinode=find_inode(ino);

    }

    if (pinode) {
	struct entry_struct *entry = NULL;
	struct entry_struct *parent = pinode->alias;
	struct name_struct xname={NULL, 0, 0};
	unsigned int error=0;

	xname.name=(char *) name;
	xname.len=strlen(name);

	calculate_nameindex(&xname);

	entry=find_entry(parent, &xname, &error);

	if (entry) {
	    struct call_info_struct call_info=CALL_INFO_INIT;
	    const struct fuse_ctx *ctx=fuse_req_ctx(req);

	    call_info.pid=ctx->pid;
	    call_info.uid=ctx->uid;
	    call_info.gid=ctx->gid;
	    call_info.umask=ctx->umask;

	    call_info.pathinfo.path=NULL;
	    call_info.pathinfo.len=0;
	    call_info.pathinfo.flags=0;

	    call_info.workspace_mount=workspace_mount;

	    if (get_path(&call_info, entry, &error)==0) {
		struct workspace_object_struct *object=call_info.object;

		(* object->module_calls.unlink) (req, entry, &call_info);

		return;

	    } else {

		fuse_reply_err(req, error);

	    }

	    free_path_pathinfo(&call_info.pathinfo);

	} else {

	    fuse_reply_err(req, ENOENT);

	}

    } else {

	fuse_reply_err(req, ENOENT);

    }

}

static void workspace_readlink(fuse_req_t req, fuse_ino_t ino)
{
    struct inode_struct *inode=NULL;
    struct workspace_mount_struct *workspace_mount=(struct workspace_mount_struct *) fuse_req_userdata(req);

    logoutput("READLINK (thread %i)", (int) gettid());

    if (ino==FUSE_ROOT_ID) {

	inode=&workspace_mount->rootinode;

    } else {

	inode=find_inode(ino);

    }

    if (inode) {
	struct call_info_struct call_info=CALL_INFO_INIT;
	unsigned int error=0;
	const struct fuse_ctx *ctx=fuse_req_ctx(req);

	call_info.pid=ctx->pid;
	call_info.uid=ctx->uid;
	call_info.gid=ctx->gid;
	call_info.umask=ctx->umask;

	call_info.pathinfo.path=NULL;
	call_info.pathinfo.len=0;
	call_info.pathinfo.flags=0;

	call_info.workspace_mount=workspace_mount;

	if (get_path(&call_info, inode->alias, &error)==0) {
	    struct workspace_object_struct *object=call_info.object;

	    (* object->module_calls.readlink) (req, inode->alias, &call_info);

	    return;

	} else {

	    fuse_reply_err(req, error);

	}

	free_path_pathinfo(&call_info.pathinfo);

    } else {

	fuse_reply_err(req, ENOENT);

    }

}

unsigned char compare_uripath(struct workspace_object_struct *a, struct workspace_object_struct *b)
{

    if ( a==b) {

	return 1;

    } else if ( ! a || ! b ) {

	/* since objecta and objectb are different, (see above) and if one of them is not set
           then the other must be set, then they are not the same 
           simular logic you find futher */

	return 0;

    //} else {
	//struct resource_struct *ra=a->resource;
	//struct resource_struct *rb=b->resource;

	//if (ra==rb) {

	//    return 1;

	//} else if ( ! ra || ! rb ) {

	//    return 0;

	//} else if (ra->group==rb->group) {
	//    struct resource_group_struct *group=ra->resource_group;

	//    return (* group->group_calls->compare) (ra, rb);

	//} 

    }

    return 0;

}

void workspace_rename(fuse_req_t req, fuse_ino_t pino, const char *name, fuse_ino_t pino_new, const char *name_new)
{
    struct inode_struct *pinode, *pinode_new;
    struct workspace_mount_struct *workspace_mount=(struct workspace_mount_struct *) fuse_req_userdata(req);
    unsigned int error=0;

    logoutput("RENAME (thread %i)", (int) gettid());

    if (pino==FUSE_ROOT_ID) {

	pinode=&workspace_mount->rootinode;

    } else {

	pinode=find_inode(pino);

    }

    if (pino_new==FUSE_ROOT_ID) {

	pinode_new=&workspace_mount->rootinode;

    } else {

	pinode_new=find_inode(pino_new);

    }

    if (pinode && pinode_new) {
	struct entry_struct *entry=NULL, *parent=pinode ->alias;
	struct name_struct xname={NULL, 0, 0};

	xname.name=(char *) name;
	xname.len=strlen(name);
	calculate_nameindex(&xname);

	/* the entry to be renamed has to exist */

	entry=find_entry(parent, &xname, &error);

	if (entry) {
	    struct call_info_struct call_info=CALL_INFO_INIT;
	    const struct fuse_ctx *ctx=fuse_req_ctx(req);

	    call_info.pid=ctx->pid;
	    call_info.uid=ctx->uid;
	    call_info.gid=ctx->gid;
	    call_info.umask=ctx->umask;

	    call_info.pathinfo.path=NULL;
	    call_info.pathinfo.len=0;
	    call_info.pathinfo.flags=0;

	    call_info.workspace_mount=workspace_mount;

	    if (get_path(&call_info, entry, &error)==0) {
		struct entry_struct *entry_new, *parent_new=pinode_new->alias;
		struct name_struct xname_new={NULL, 0, 0};

		xname_new.name=(char *) name_new;
		xname_new.len=strlen(name);
		calculate_nameindex(&xname_new);

		/* the entry to be renamed has to exist */

		error=0;
		entry_new=find_entry(parent_new, &xname_new, &error);

		if (entry_new) {
		    struct call_info_struct call_info_new=CALL_INFO_INIT;

		    call_info_new.pid=ctx->pid;
		    call_info_new.uid=ctx->uid;
		    call_info_new.gid=ctx->gid;
		    call_info_new.umask=ctx->umask;

		    call_info_new.pathinfo.path=NULL;
		    call_info_new.pathinfo.len=0;
		    call_info_new.pathinfo.flags=0;

		    call_info_new.workspace_mount=workspace_mount;

		    if (get_path(&call_info_new, entry_new, &error)==0) {
			struct workspace_object_struct *object=call_info.object;
			struct workspace_object_struct *object_new=call_info_new.object;

			if (compare_uripath(object, object_new)==1) {

			    (*object->module_calls.rename_cached) (req, entry, &call_info, entry_new, &call_info_new);

			    return;

			} else {

			    fuse_reply_err(req, EXDEV);
			    free_path_pathinfo(&call_info.pathinfo);

			}

		    } else {

			fuse_reply_err(req, error);

		    }

		} else if (error==ENOENT) {
		    struct call_info_struct call_info_new=CALL_INFO_INIT;

		    call_info_new.pid=ctx->pid;
		    call_info_new.uid=ctx->uid;
		    call_info_new.gid=ctx->gid;
		    call_info_new.umask=ctx->umask;

		    call_info_new.pathinfo.path=NULL;
		    call_info_new.pathinfo.len=0;
		    call_info_new.pathinfo.flags=0;

		    call_info_new.workspace_mount=workspace_mount;

		    if (get_path_extra(&call_info_new, parent_new, &xname_new, &error)==0) {
			struct workspace_object_struct *object=call_info.object;
			struct workspace_object_struct *object_new=call_info_new.object;

			if (compare_uripath(object, object_new)==1) {

			    (*object->module_calls.rename_noncached) (req, entry, &call_info, pinode, &xname_new, &call_info_new);

			    return;

			} else {

			    fuse_reply_err(req, EXDEV);
			    free_path_pathinfo(&call_info.pathinfo);

			}

		    } else {

			fuse_reply_err(req, error);

		    }

		} else {

		    fuse_reply_err(req, error);

		}

		free_path_pathinfo(&call_info.pathinfo);

	    } else {

		fuse_reply_err(req, error);

	    }

	} else {

	    fuse_reply_err(req, ENOENT);

	}

    } else {

	fuse_reply_err(req, ENOENT);

    }

}

static void workspace_opendir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
    struct inode_struct *inode=NULL;
    struct workspace_mount_struct *workspace_mount=(struct workspace_mount_struct *) fuse_req_userdata(req);

    logoutput("OPENDIR (thread %i)", (int) gettid());

    if (ino==FUSE_ROOT_ID) {

	inode=&workspace_mount->rootinode;

    } else {

	inode=find_inode(ino);

    }

    if (inode) {
	struct call_info_struct call_info=CALL_INFO_INIT;
	unsigned int error=0;
	const struct fuse_ctx *ctx=fuse_req_ctx(req);
	struct directory_struct *directory=NULL;

	directory=get_directory(inode, 1, &error);

	if (! directory || error>0) {

	    error=(error==0) ? ENOMEM : error;
	    fuse_reply_err(req, error);
	    free_path_pathinfo(&call_info.pathinfo);
	    return;

	}

	call_info.pid=ctx->pid;
	call_info.uid=ctx->uid;
	call_info.gid=ctx->gid;
	call_info.umask=ctx->umask;

	call_info.pathinfo.path=NULL;
	call_info.pathinfo.len=0;
	call_info.pathinfo.flags=0;

	call_info.workspace_mount=workspace_mount;

	if (get_path(&call_info, inode->alias, &error)==0) {
	    struct workspace_object_struct *object=call_info.object;
	    struct workspace_dh_struct *dh=malloc(sizeof(struct workspace_dh_struct));

	    if (dh) {

		dh->parent=inode->alias;
		dh->entry=NULL;
		dh->object=object;
		dh->pathinfo.path=call_info.pathinfo.path;
		dh->pathinfo.len=call_info.pathinfo.len;
		dh->pathinfo.flags=call_info.pathinfo.flags;
		dh->directory=directory;

		dh->synctime.tv_sec=0;
		dh->synctime.tv_nsec=0;

		dh->relpath=call_info.relpath;
		dh->mode=0;
		if (directory->count>0) dh->mode |= _WORKSPACE_READDIR_MODE_NONEMPTY;
		get_current_time(&dh->synctime);

		call_info.pathinfo.path=NULL;
		call_info.pathinfo.len=0;
		call_info.pathinfo.flags=0;

		fi->fh=(uint64_t) (uintptr_t) dh;
		dh->fi=fi;

		(* object->module_calls.opendir) (req, dh);

		return;

	    } else {

		fuse_reply_err(req, ENOMEM);

	    }

	} else {

	    fuse_reply_err(req, error);

	}

	free_path_pathinfo(&call_info.pathinfo);

    } else {

	fuse_reply_err(req, ENOENT);

    }

}

static void workspace_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t offset, struct fuse_file_info *fi)
{
    struct workspace_dh_struct *dh=(struct workspace_dh_struct *) ( uintptr_t) fi->fh;

    logoutput("READDIR (thread %i)", (int) gettid());

    if (dh->mode & _WORKSPACE_READDIR_MODE_FINISH) {

	fuse_reply_buf(req, NULL, 0);

	return;

    } else {
	struct workspace_object_struct *object=dh->object;

    	(* object->module_calls.readdir) (req, size, offset, dh);

    }

}

static void workspace_readdirplus(fuse_req_t req, fuse_ino_t ino, size_t size, off_t offset, struct fuse_file_info *fi)
{
    struct workspace_dh_struct *dh=(struct workspace_dh_struct *) ( uintptr_t) fi->fh;

    logoutput("READDIRPLUS (thread %i)", (int) gettid());

    if (dh->mode & _WORKSPACE_READDIR_MODE_FINISH) {

	fuse_reply_buf(req, NULL, 0);

	return;

    } else {
	struct workspace_object_struct *object=dh->object;

	(* object->module_calls.readdirplus) (req, size, offset, dh);

    }

}

static void workspace_fsyncdir(fuse_req_t req, fuse_ino_t ino, int datasync, struct fuse_file_info *fi)
{
    struct workspace_dh_struct *dh=(struct workspace_dh_struct *) ( uintptr_t) fi->fh;
    struct workspace_object_struct *object=dh->object;

    logoutput("FSYNCDIR (thread %i)", (int) gettid());

}


static void workspace_releasedir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
    struct workspace_dh_struct *dh=(struct workspace_dh_struct *) ( uintptr_t) fi->fh;
    struct workspace_object_struct *object=dh->object;

    logoutput("RELEASEDIR (thread %i)", (int) gettid());

    (* object->module_calls.releasedir) (req, dh);

    free_path_pathinfo(&dh->pathinfo);

    free(dh);
    fi->fh=0;

}

static void workspace_create(fuse_req_t req, fuse_ino_t ino, const char *name, mode_t mode, struct fuse_file_info *fi)
{
    struct inode_struct *pinode=NULL;
    struct workspace_mount_struct *workspace_mount=(struct workspace_mount_struct *) fuse_req_userdata(req);

    if (ino==FUSE_ROOT_ID) {

	pinode=&workspace_mount->rootinode;

    } else {

	pinode=find_inode(ino);

    }

    logoutput("CREATE, name: %s (thread %i)", name, (int) gettid());

    if (pinode) {
	struct entry_struct *entry = NULL;
	struct entry_struct *parent = pinode->alias;
	struct name_struct xname={NULL, 0, 0};
	unsigned int error=0;

	xname.name=(char *) name;
	xname.len=strlen(name);

	calculate_nameindex(&xname);

	entry=find_entry(parent, &xname, &error);

	if (! entry) {
	    struct call_info_struct call_info=CALL_INFO_INIT;
	    const struct fuse_ctx *ctx=fuse_req_ctx(req);

	    call_info.pid=ctx->pid;
	    call_info.uid=ctx->uid;
	    call_info.gid=ctx->gid;
	    call_info.umask=ctx->umask;

	    call_info.pathinfo.path=NULL;
	    call_info.pathinfo.len=0;
	    call_info.pathinfo.flags=0;

	    call_info.workspace_mount=workspace_mount;

	    if (get_path_extra(&call_info, parent, &xname, &error)==0) {
		struct workspace_fh_struct *fh=malloc(sizeof(struct workspace_fh_struct));
		struct workspace_object_struct *object=call_info.object;

		logoutput("CREATE: %s, calls %s", call_info.pathinfo.path, object->module_calls.name);

		if (fh) {

		    fh->entry=entry;
		    fh->object=object;
		    fh->pathinfo.path=call_info.pathinfo.path;
		    fh->pathinfo.len=call_info.pathinfo.len;
		    fh->pathinfo.path=call_info.pathinfo.path;
		    fh->relpath=call_info.relpath;

		    call_info.pathinfo.path=NULL;
		    call_info.pathinfo.len=0;
		    call_info.pathinfo.flags=0;

		    fi->fh=(uint64_t) (uintptr_t) fh;
		    fh->fi=fi;

		    (* object->module_calls.create) (req, pinode, &xname, fh, mode);

		    return;

		} else {

		    fuse_reply_err(req, ENOMEM);

		}

	    } else {

		fuse_reply_err(req, error);

	    }

	    free_path_pathinfo(&call_info.pathinfo);

	} else {

	    fuse_reply_err(req, EEXIST);

	}

    } else {

	fuse_reply_err(req, ENOENT);

    }

}

static void workspace_open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
    struct inode_struct *inode=NULL;
    struct workspace_mount_struct *workspace_mount=(struct workspace_mount_struct *) fuse_req_userdata(req);

    logoutput("OPEN (thread %i)", (int) gettid());

    if (ino==FUSE_ROOT_ID) {

	inode=&workspace_mount->rootinode;

    } else {

	inode=find_inode(ino);

    }

    if (inode) {
	struct call_info_struct call_info=CALL_INFO_INIT;
	unsigned int error=0;
	const struct fuse_ctx *ctx=fuse_req_ctx(req);

	call_info.pid=ctx->pid;
	call_info.uid=ctx->uid;
	call_info.gid=ctx->gid;
	call_info.umask=ctx->umask;

	call_info.pathinfo.path=NULL;
	call_info.pathinfo.len=0;
	call_info.pathinfo.flags=0;

	call_info.workspace_mount=workspace_mount;

	if (get_path(&call_info, inode->alias, &error)==0) {
	    struct workspace_object_struct *object=call_info.object;
	    struct workspace_fh_struct *fh=malloc(sizeof(struct workspace_fh_struct));

	    logoutput("OPEN: %s", call_info.pathinfo.path);

	    if (fh) {

		fh->entry=inode->alias;
		fh->object=object;
		fh->relpath=call_info.relpath;
		fh->pathinfo.path=call_info.pathinfo.path;
		fh->pathinfo.len=call_info.pathinfo.len;
		fh->pathinfo.flags=call_info.pathinfo.flags;
		fh->flags = (fi->flags & O_ACCMODE) | O_NOFOLLOW;

		call_info.pathinfo.path=NULL;
		call_info.pathinfo.len=0;
		call_info.pathinfo.flags=0;

		fi->fh=(uint64_t) (uintptr_t) fh;
		fh->fi=fi;

		(* object->module_calls.open) (req, fh);

		return;

	    } else {

		fuse_reply_err(req, ENOMEM);

	    }

	} else {

	    fuse_reply_err(req, error);

	}

	free_path_pathinfo(&call_info.pathinfo);

    } else {

	fuse_reply_err(req, ENOENT);

    }

}

static void workspace_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t offset, struct fuse_file_info *fi)
{
    struct workspace_fh_struct *fh=(struct workspace_fh_struct *) ( uintptr_t) fi->fh;
    struct workspace_object_struct *object=fh->object;

    logoutput("READ (thread %i)", (int) gettid());

    (* object->module_calls.read) (req, size, offset, fh);

}

static void workspace_write(fuse_req_t req, fuse_ino_t ino, const char *buff, size_t size, off_t offset, struct fuse_file_info *fi)
{
    struct workspace_fh_struct *fh=(struct workspace_fh_struct *) ( uintptr_t) fi->fh;
    struct workspace_object_struct *object=fh->object;

    logoutput("WRITE (thread %i)", (int) gettid());

    (* object->module_calls.write) (req, buff, size, offset, fh);

}

static void workspace_fsync(fuse_req_t req, fuse_ino_t ino, int datasync, struct fuse_file_info *fi)
{
    struct workspace_fh_struct *fh=(struct workspace_fh_struct *) ( uintptr_t) fi->fh;
    struct workspace_object_struct *object=fh->object;

    logoutput("FSYNC (thread %i)", (int) gettid());

    (* object->module_calls.fsync) (req, datasync, fh);

}


static void workspace_release(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
    struct workspace_fh_struct *fh=(struct workspace_fh_struct *) ( uintptr_t) fi->fh;
    struct workspace_object_struct *object=fh->object;

    logoutput("RELEASE (thread %i)", (int) gettid());

    (* object->module_calls.release) (req, fh);

}

static void workspace_statfs(fuse_req_t req, fuse_ino_t ino)
{
    struct workspace_mount_struct *workspace_mount=(struct workspace_mount_struct *) fuse_req_userdata(req);
    struct statvfs st;
    unsigned int error=0;

    logoutput("STATFS: ino %lli (thread %i)", (long long) ino, (int) gettid());

    memset(&st, 0, sizeof(statvfs));

    /* should the statvfs be taken of the path or the root ?? */

    if (statvfs("/", &st)==0) {

	// take some values from the default

	/* note the fs does not provide opening/reading/writing of files, so info about blocksize etc
	   is useless, so do not override the default from the root */ 

	st.f_bsize=4096; 		/* good?? */
	st.f_frsize=st.f_bsize; 	/* no fragmentation on this fs */

	st.f_files=(fsfilcnt_t) workspace_mount->nrinodes;
	st.f_ffree=(fsfilcnt_t) UINT64_MAX - st.f_files ; /* inodes are of unsigned long int, 4 bytes:32 */
	st.f_favail=st.f_ffree;

	// do not know what to put here... just some default values... no fsid.... just zero

	st.f_fsid=0;
	st.f_flag=0;
	st.f_namemax=255;

	fuse_reply_statfs(req, &st);

	return;

    } else {

	error=errno;

    }

    error:

    fuse_reply_err(req, error);

    logoutput("statfs error: %i", error);

}

#ifdef NO_FSNOTIFY

static void workspace_fsnotify(fuse_req_t req, fuse_ino_t ino, uint32_t mask)
{
    struct inode_struct *inode=NULL;
    struct workspace_mount_struct *workspace_mount=(struct workspace_mount_struct *) fuse_req_userdata(req);

    logoutput("FSNOTIFY (thread %i)", (int) gettid());

    if (ino==FUSE_ROOT_ID) {

	inode=&workspace_mount->rootinode;

    } else {

	inode=find_inode(ino);

    }

    if (inode) {
	struct call_info_struct call_info=CALL_INFO_INIT;
	unsigned int error=0;
	const struct fuse_ctx *ctx=fuse_req_ctx(req);

	call_info.pid=ctx->pid;
	call_info.uid=ctx->uid;
	call_info.gid=ctx->gid;
	call_info.umask=ctx->umask;

	call_info.pathinfo.path=NULL;
	call_info.pathinfo.len=0;
	call_info.pathinfo.flags=0;

	call_info.workspace_mount=workspace_mount;

	if (get_path(&call_info, inode->alias, &error)==0) {
	    struct workspace_object_struct *object=call_info.object;

	    (* object->module_calls.fsnotify) (req, inode->alias, &call_info, mask);

	    return;

	} else {

	    fuse_reply_err(req, error);

	}

	free_path_pathinfo(&call_info.pathinfo);

    } else {

	fuse_reply_err(req, ENOENT);

    }

}

#endif

static void workspace_init (void *userdata, struct fuse_conn_info *conn)
{

    logoutput("INIT (thread %i)", (int) gettid());

}

static void workspace_destroy (void *userdata)
{

    logoutput("DESTROY (thread %i)", (int) gettid());


}

static void workspace_getxattr(fuse_req_t req, fuse_ino_t ino, const char *name, size_t size)
{
    struct inode_struct *inode;
    struct workspace_mount_struct *workspace_mount=(struct workspace_mount_struct *) fuse_req_userdata(req);

    logoutput("GETXATTR, name %s (thread %i)", name, (int) gettid());

    if (strcmp(name, "system.posix_acl_access")==0 || strcmp(name, "system.posix_acl_default")==0) goto out;

    inode=find_inode(ino);

    if ( inode ) {
	struct entry_struct *entry=NULL;

	entry=inode->alias;

	if ( entry) {

	    if (entry==workspace_mount->rootinode.alias) {

		if (strcmp(name, "pathmax")==0) {

		    if (size==0) {
			size_t count=0;

			/* pathmax */

			count+=log10(get_pathmax()) + 2;

			fuse_reply_xattr(req, count);

		    } else {
			size_t count=0;

			/* pathmax */

			count+=log10(get_pathmax()) + 2;

			if (count<size) {
			    char *buff=NULL;
			    char result[count];

			    buff=malloc(size);

			    if (buff) {

				sprintf(result, "%i", (int) get_pathmax());

				memset(buff, 0, size);
				memcpy(buff, result, count);

				logoutput("workspace_getxattr: reply buff %s", buff);

				fuse_reply_buf(req, buff, size);

				free(buff);

			    } else {

				fuse_reply_err(req, ENOMEM);

			    }

			} else {

			    fuse_reply_err(req, ERANGE);

			}

		    }

		    return;

		}

	    }

	}

    }

    out:

    fuse_reply_err(req, ENOATTR);

}

static void workspace_listxattr(fuse_req_t req, fuse_ino_t ino, size_t size)
{
    struct inode_struct *inode;
    struct workspace_mount_struct *workspace_mount=(struct workspace_mount_struct *) fuse_req_userdata(req);

    logoutput("LISTXATTR (thread %i)", (int) gettid());

    inode=find_inode(ino);

    if ( inode ) {
	struct entry_struct *entry=NULL;

	entry=inode->alias;

	if ( entry ) {

	    if (entry==workspace_mount->rootinode.alias) {

		if (size==0) {
		    size_t count=0;

		    /* pathmax */

		    count+=strlen("pathmax") + 2;

		    fuse_reply_xattr(req, count);

		} else {
		    size_t count=0;

		    /* pathmax */

		    count+=strlen("pathmax") + 2;

		    if (count<=size) {
			char *buff=NULL;
			char result[count];

			buff=malloc(size);

			if (buff) {
			    int len=0;

			    len=sprintf(result, "%i", (int) get_pathmax());

			    memset(buff, '\0', size);
			    memcpy(buff, result, count);

			    logoutput("workspace_listxattr: reply buff %s", buff);

			    fuse_reply_buf(req, buff, size);

			    free(buff);

			} else {

			    fuse_reply_err(req, ENOMEM);

			}

		    } else {

			fuse_reply_err(req, ERANGE);

		    }

		}

		return;

	    }

	}

    }

    if (size==0) {

	fuse_reply_xattr(req, 0);

    } else {

	fuse_reply_buf(req, NULL, 0);

    }

}

static void workspace_signal_handler(struct beventloop_struct *bloop, void *data, int signo)
{

    logoutput("workspace_signal_handler");

    if ( signo==SIGHUP || signo==SIGINT || signo==SIGTERM ) {

	logoutput("workspace_signal_handler: got signal (%i)", signo);

	clear_all_workspaces();
	bloop->status=BEVENTLOOP_STATUS_DOWN;

    } else if ( signo==SIGIO ) {

	logoutput("workspace_signal_handler: received SIGIO signal");

    } else if ( signo==SIGPIPE ) {

	logoutput("workspace_signal_handler: received SIGPIPE signal");

    } else if ( signo==SIGCHLD ) {

	logoutput("workspace_signal_handler: received SIGCHLD signal");

    } else if ( signo==SIGUSR1 ) {

	logoutput("workspace_signal_handler: received SIGUSR1 signal");

    }

}

struct fuse_lowlevel_ops workspace_oper = {
    .init	= workspace_init,
    .destroy	= workspace_destroy,
    .lookup	= workspace_lookup,
    .forget	= workspace_forget,
    .getattr	= workspace_getattr,
    .setattr	= workspace_setattr,
    .mkdir	= workspace_mkdir,
    .mknod	= workspace_mknod,
    .rmdir	= workspace_rmdir,
    .unlink	= workspace_unlink,
    .symlink	= workspace_symlink,
    .readlink	= workspace_readlink,
    .opendir	= workspace_opendir,
    .readdir	= workspace_readdir,
/*
    .readdirplus= workspace_readdirplus,

*/
    .releasedir	= workspace_releasedir,
    .fsyncdir	= workspace_fsyncdir,
    .create	= workspace_create,
    .open	= workspace_open,
    .read	= workspace_read,
    .write	= workspace_write,
    .fsync	= workspace_fsync,
    .release	= workspace_release,
    .statfs	= workspace_statfs,
/*
    .fsnotify   = workspace_fsnotify,
*/
    .listxattr  = workspace_listxattr,
    .getxattr	= workspace_getxattr,
};

int main(int argc, char *argv[])
{
    int res=0;
    unsigned int error=0;

    umask(0);

    open_logoutput(); 
    program_name=argv[0];

    /* parse commandline options and initialize the fuse options */

    if (parse_arguments(argc, argv, &error)==-1) {

	if (error>0) fprintf(stderr, "Error, cannot parse arguments (error: %i).\n", error);

	goto skipeverything;

    }

    /* read the different workspaces */

    if (fs_options.basemap) {

	read_workspace_files(fs_options.basemap);

    } else {

	read_workspace_files(FUSE_WORKSPACE_BASEMAP);

    }

    initialize_workerthreads(&workerthreads_queue);
    set_max_numberthreads(&workerthreads_queue, 6);

    /* init the hash lookup tables */

    //if (init_pathcache_group(&error)==-1) {

	//fprintf(stderr, "Error, cannot intialize pathcache (error: %i).\n", error);
	//exit(1);

    //}

    if (init_inode_hashtable(&error)==-1) {

	fprintf(stderr, "Error, cannot intialize inode hash table (error: %i).\n", error);
	exit(1);

    }

    if (init_directory_hashtable(&error)==-1) {

	fprintf(stderr, "Error, cannot intialize directory hash table (error: %i).\n", error);
	exit(1);

    }

    res = fuse_daemonize(0);

    if ( res!=0 ) {

        logoutput("Error daemonize.");
        goto out;

    }

    /*
	initialize the eventloop (using epoll)
    */

    if (init_beventloop(NULL, &error)==-1) {

        logoutput("Error creating eventloop, error: %i.", error);
        goto out;

    }

    /*
	add signal handler to eventloop
    */

    if (set_beventloop_signal(NULL, 1, workspace_signal_handler, &error)==-1) {

	logoutput("Error adding signal handler to eventloop: %i.", error);
        goto out;

    }

    /*
	add timer handler to eventloop
    */

    if (set_beventloop_timer(NULL, 1, &error)==-1) {

	logoutput("Error adding timer handler to eventloop: %i.", error);
        goto out;

    }

    /*
	initialize fs change notify
    */

    if (init_fssync(&error)==-1) {

	logoutput("Error initializing fs sync, error: %i", error);
	goto out;

    }

    if (init_fschangenotify(&error)==-1) {

	logoutput("Error initializing fschange notify, error: %i", error);
	goto out;

    }

    /*
	monitor the sessions
    */

    if (monitor_usersessions(update_workspaces, NULL, &error)==-1) {


	logoutput("Error initializing usersessions monitor, error: %i", error);
	goto out;

    }

    list_usersessions();

    res=start_beventloop(NULL);

    out:

    logoutput("main:destroy workerthreads");

    destroy_workerthreads_queue(&workerthreads_queue);

    logoutput("main:end fschangenotify");

    end_fschangenotify();

    logoutput("main:destroy eventloop");

    destroy_beventloop(NULL);

    skipeverything:

    close_logoutput();

    return error>0 ? 1 : 0;

    notforked:

    if (error>0) {

	fprintf(stderr, "Error (error: %i).\n", error);

    }

    return error>0 ? 1 : 0;

}
