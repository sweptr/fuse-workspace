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

#include "global-defines.h"

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <err.h>

#include <inttypes.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/fsuid.h>

#include <pwd.h>
#include <grp.h>
#include <pthread.h>
#include <dirent.h>

#ifndef ENOATTR
#define ENOATTR ENODATA        /* No such attribute */
#endif

#include "workerthreads.h"
#include "fuse-workspace.h"
#include "entry-management.h"
#include "utils.h"

#include "beventloop-utils.h"
#include "monitorsessions.h"
#include "workspaces.h"
#include "path-resolution.h"

#include "workspaces.h"
#include "resources.h"
#include "objects.h"
#include "module/virtual/browsevirtual.h"
#include <linux/fuse.h>
#include <sys/mount.h>

#ifdef LOGGING

#include <syslog.h>

static unsigned char loglevel=1;

#define logoutput_debug(...) if (loglevel >= 5) syslog(LOG_DEBUG, __VA_ARGS__)
#define logoutput_info(...) if (loglevel >= 4) syslog(LOG_INFO, __VA_ARGS__)
#define logoutput_notice(...) if (loglevel >= 3) syslog(LOG_NOTICE, __VA_ARGS__)
#define logoutput_warning(...) if (loglevel >= 2) syslog(LOG_WARNING, __VA_ARGS__)
#define logoutput_error(...) if (loglevel >= 1) syslog(LOG_ERR, __VA_ARGS__)

#define logoutput(...) if (loglevel >= 1) syslog(LOG_DEBUG, __VA_ARGS__)

#else

static inline void dummy_nolog()
{
    return;

}

#define logoutput_debug(...) dummy_nolog()
#define logoutput_info(...) dummy_nolog()
#define logoutput_notice(...) dummy_nolog()
#define logoutput_warning(...) dummy_nolog()
#define logoutput_error(...) dummy_nolog()

#define logoutput(...) dummy_nolog()

#endif

extern struct fs_options_struct fs_options;
extern struct workerthreads_queue_struct workerthreads_queue;
extern struct fuse_lowlevel_ops workspace_oper;
extern char *program_name;

extern const char *dotdotname;
extern const char *dotname;

struct fusedata_struct {
    struct fuse_buf				fbuf;
    struct workspace_mount_struct		*workspace_mount;
    struct fusedata_struct			*next;
};

struct fusequeue_struct {
    struct fusedata_struct			*first;
    struct fusedata_struct			*last;
    pthread_mutex_t				mutex;
};

static struct fusequeue_struct 			fusequeue;

static struct workspace_base_struct 		*base_list=NULL;
static struct workspace_user_struct 		*users_list=NULL;
static struct workspace_mount_struct 		*mounts_list=NULL;
static pthread_mutex_t				mounts_mutex=PTHREAD_MUTEX_INITIALIZER;

/* functions to handle the adding and maintaining workspaces 

    - monitor the users (default in /var/run/xdgsession)
    - monitor the workspace files (default in /etc/fuse-workspace/workspaces)
    - add fuse-workspace(s) when a sessions starts, and remove it when it ends
    - 
*/

/* function to get the "real" path from a template, which has has the 
   strings $HOME and $USER in it, which have to be replaced by the real value

   this can be programmed in a more generic way, but here only a small number fixed variables
   is to be looked for.. 

   return value: the converted string, which has to be freed later 
*/

char *get_path_from_template(char *template, struct workspace_user_struct *workspace_user, char *buff, size_t len0)
{
    char *conversion=NULL;
    char *p1, *p2, *p1_keep;
    unsigned int len1, len2, len3, len4, len5;
    pathstring path1;

    logoutput("get_path_from_template: template %s", template);

    len1=strlen(template);

    len2=strlen("$HOME");
    len3=strlen(workspace_user->private_home);
    len4=strlen("$USER");
    len5=strlen(workspace_user->private_user);

    p1=template;
    p2=path1;

    findnext:

    p1_keep=p1;
    p1=strchrnul(p1, '$');

    if ( *p1=='$' ) {

	if (p1 + len2 <= template + len1) {

	    if ( strncmp(p1, "$HOME", len2)==0 ) {

		if (p1>p1_keep) {

		    memcpy(p2, p1_keep, p1-p1_keep);
		    p2+=p1-p1_keep;

		}

		memcpy(p2, workspace_user->private_home, len3);
		p2+=len3;
		p1+=len2;

		goto findnext;

	    }

	}

	if (p1 + len4 <= template + len1) {

	    if ( strncmp(p1, "$USER", len4)==0 ) {

		if (p1>p1_keep) {

		    memcpy(p2, p1_keep, p1-p1_keep);
		    p2+=p1-p1_keep;

		}

		memcpy(p2, workspace_user->private_user, len5);
		p2+=len5;
		p1+=len4;

		goto findnext;

	    }

	}

	/* when here: a $ is found, but it's not one of above */

	p1++;

    } else {

	/* $ not found, p1 points to end of string: maybe there is some left over */

	if ( p1>p1_keep ) {

	    memcpy(p2, p1_keep, p1-p1_keep);
	    p2+=p1-p1_keep;

	}

	/* terminator */

	*p2='\0';

    }

    if (p2!=path1) {

	/* size including the \0 terminator */

	len1=p2-path1+1;

	if ( buff ) {

	    /* store in the supplied buffer */

	    if ( len1<=len0 ) {

		conversion=buff;
		memcpy(conversion, path1, len1);

	    }

	} else {

	    /* create a new buffer */

	    conversion=malloc(len1);
	    if (conversion) memcpy(conversion, path1, len1);

	}

    }

    if (conversion) {

	logoutput("get_path_from_template: result %s", conversion);

    }

    return conversion;

}

signed char test_object_exist(char *template, struct workspace_user_struct *workspace_user, unsigned int *error)
{
    pathstring path;
    signed char result=-1;

    if (! template) {

	*error=EINVAL;
	return -1;

    }

    logoutput("test_object_exist: template %s", template);

    if ( get_path_from_template(template, workspace_user, path, sizeof(pathstring))) {
	struct stat st;

	if (stat(path, &st)==-1) {

	    if (errno!=ENOENT) {

		*error=errno;

	    }

	    result=-1;

	} else {

	    result=0;

	}

    }

    return result;

}

unsigned char user_is_groupmember(char *username, struct group *grp)
{
    unsigned char found=0;
    char **member;

    member=grp->gr_mem;

    while(*member) {

	if (strcmp(username, *member)==0) {

	    found=1;
	    break;

	}

	member++;

    }

    return found;

}

unsigned char ismounted(char *path)
{
    unsigned int len=strlen(path);
    char tmppath[strlen(path)+1];
    char *slash=NULL;
    unsigned char ismounted=0;
    struct stat st;

    memcpy(tmppath, path, len+1);
    slash=strrchr(tmppath, '/');

    if (slash && stat(tmppath, &st)==0) {
	dev_t dev=st.st_dev;

	*slash='\0';

	if (stat(tmppath, &st)==0) {

	    if (dev!=st.st_dev) ismounted=1;

	}

	*slash='/';

    }

    return ismounted;

}

char *create_subdirectory(char *path, char *subpath, int mode, uid_t uidnr, gid_t gidnr, unsigned int *error)
{
    char *createpath=NULL, *buff=NULL;
    unsigned int lenp, lenb;
    uid_t uidnr_keep=0;
    gid_t gidnr_keep=0;

    logoutput("create_subdirectory %s in %s", subpath, path);

    if ( uidnr>0 ) uidnr_keep=setfsuid(uidnr);
    if ( gidnr>0 ) gidnr_keep=setfsgid(gidnr);

    *error=0;

    lenb=strlen(subpath);

    buff=malloc(lenb+1);
    if ( ! buff ) {

	*error=ENOMEM;
	goto out;

    }

    lenp = strlen(path) + 2 + lenb;

    createpath=malloc(lenp);
    if ( ! createpath ) {

	*error=ENOMEM;
	goto out;

    }

    memset(createpath, '\0', lenp);

    memset(buff, '\0', lenb+1);
    memcpy(buff, subpath, lenb);

    if ( realpath(path, createpath) ) {
	char *p, *s;
	unsigned int len, lens;
	struct stat st;


	len=strlen(createpath);

	s=buff;

	while(1) {

	    p=strchr(s, '/');

	    /* skip starting/double slashes */

	    if ( p==s ) {

		s++;
		if (*s=='\0') break;

		continue;

	    }

	    /* append piece of path from s to p to returnpath */

	    *(createpath+len)='/';
	    len++;

	    if (p) *p='\0';
	    lens=strlen(s);

	    memcpy(createpath+len, s, lens);
	    len+=lens;
	    *(createpath+len)='\0';

	    /* check it does exist before creating */

	    if (mkdir(createpath, mode)==-1) {

		if (errno==EEXIST) {

		    errno=0;

		} else {

		    *error=errno;
		    goto out;

		}

	    }

	    if (p) {

		*p='/';
		s=p+1;

	    } else {

		break;

	    }

	}


    } else {

	if (createpath) {

	    free(createpath);
	    createpath=NULL;

	}

    }

    out:

    if (buff) free(buff);

    if (*error>0) {

	if (createpath) {

	    free(createpath);
	    createpath=NULL;

	}

    }

    if ( uidnr>0 ) uidnr_keep=setfsuid(uidnr_keep);
    if ( gidnr>0 ) gidnr_keep=setfsgid(gidnr_keep);

    return createpath;

}

/*  function which creates a directory
    it does this by walking the provided path and create every "higher" directory

    - path: the path to create
    - mode: permissions, like in mkdir
    - uidnr and gidnr: if non zero, change to this user/group
*/

int create_directory(char *path, int mode, unsigned int *error)
{
    char *createpath=NULL;
    char *p, *s;
    unsigned int len, lens;
    int result=0;
    struct stat st;

    *error=0;

    logoutput("create_directory %s", path);

    len=strlen(path)+1;
    createpath=malloc(len);

    if ( ! createpath ) {

	*error=ENOMEM;
	result=-1;
	goto out;

    }

    memset(createpath, '\0', len);

    s=path;
    len=0;

    while(1) {

	p=strchr(s, '/');

	if (p) {

	    /* skip starting/double slashes */

	    if ( p==s ) {

		s++;
		continue;

	    }

	    *p='\0';

	}

	/* append piece of path from s to p to createpath */

	*(createpath+len)='/';
	len++;

	lens=strlen(s);
	memcpy(createpath+len, s, lens);
	len+=lens;

	*(createpath+len)='\0';

	if (mkdir(createpath, mode)==-1) {

	    if (errno==EEXIST) {

		/* if already exist no problem */

		errno=0;

	    } else {

		*error=errno;
		result=-1;

		goto out;

	    }

	}


	if (p) {

	    *p='/';
	    s=p+1;

	} else {

	    /* no slash found: at the end */

	    break;

	}

    }

    out:

    if (createpath) free(createpath);

    return result;

}


void read_workspace_file(char *workspacefile, char *name)
{
    FILE *fp;
    char line[512];
    char *option;
    char *value;
    struct workspace_base_struct *workspace_base;
    int res, len;
    char *sep;

    logoutput("read_workspace_file, open %s, name %s", workspacefile, name);

    memset(line, '\0', 330);

    fp=fopen(workspacefile, "r");

    if ( ! fp ) {

        logoutput("read_workspace_file, error %i when trying to open", errno);

	return;

    }

    workspace_base=malloc(sizeof(struct workspace_base_struct));

    if ( ! workspace_base ) {

	logoutput("read_workspace_file, error creating a new workspace_base");

	fclose(fp);

	return;

    }

    workspace_base->flags=0;

    workspace_base->name=strdup(name);

    workspace_base->ingrouppolicy=WORKSPACE_RULE_POLICY_NONE;
    workspace_base->filepolicy=WORKSPACE_RULE_POLICY_NONE;

    workspace_base->mount_path_template=NULL;

    workspace_base->ingroup=(gid_t) -1;
    workspace_base->filehastoexist=NULL;

    workspace_base->next=NULL;
    workspace_base->prev=NULL;

    /* add to list.. no lock required, there is one thread doing this */

    if ( base_list ) base_list->prev=workspace_base;
    workspace_base->next=base_list;
    base_list=workspace_base;

    /* type */

    workspace_base->type=0;

    if (strncmp(name, "dev.", 4)==0) {

	workspace_base->type=WORKSPACE_TYPE_DEVICES;

    } else if (strncmp(name, "network.", 3)==0) {

	workspace_base->type=WORKSPACE_TYPE_NETWORK;

    } else if (strncmp(name, "file.", 4)==0) {

	workspace_base->type=WORKSPACE_TYPE_FILE;

    }

    while (!feof(fp)) {

	if ( ! fgets(line, 330, fp)) continue;

	sep=strchr(line, '\n');
	if (sep) *sep='\0';

	sep=strchr(line, '=');
	if ( ! sep ) continue;

	*sep='\0';
	value=sep+1;
	option=line;

	convert_to(option, UTILS_CONVERT_SKIPSPACE | UTILS_CONVERT_TOLOWER);

	if ( strncmp(option, "#", 1)==0 || strlen(option)==0) {

	    /* skip comments and empty lines */
	    continue;

	} else if ( strcmp(option, "mountpoint")==0 ) {

	    /* MountPoint=templatemountpoint */

	    workspace_base->mount_path_template=strdup(value);

	} else if ( strcmp(option, "useringroup")==0 ) {
	    struct group *grp;

	    grp=getgrnam(value);

	    if (grp) {

		/* UserInGroup=%somegroup% */

		/* TODO: lookup group */

		workspace_base->ingroup=grp->gr_gid;

	    }

	} else if ( strcmp(option, "ingrouppolicy")==0 ) {

	    /* InGroupPolicy */

	    convert_to(value, UTILS_CONVERT_SKIPSPACE | UTILS_CONVERT_TOLOWER);

	    if ( strcmp(value, "required")==0 ) {

		workspace_base->ingrouppolicy=WORKSPACE_RULE_POLICY_REQUIRED;

	    } else if ( strcmp(value, "sufficient")==0 ) {

		workspace_base->ingrouppolicy=WORKSPACE_RULE_POLICY_SUFFICIENT;

	    }

	} else if ( strcmp(option, "filehastoexist")==0 ) {

	    /* FileHasToExist=$HOME/.somefile */

	    workspace_base->filehastoexist=strdup(value);

	} else if ( strcmp(option, "filepolicy")==0 ) {

	    /* FilePolicy */

	    convert_to(value, UTILS_CONVERT_SKIPSPACE | UTILS_CONVERT_TOLOWER);

	    if ( strcmp(value, "required")==0 ) {

		workspace_base->filepolicy=WORKSPACE_RULE_POLICY_REQUIRED;

	    } else if ( strcmp(value, "sufficient")==0 ) {

		workspace_base->filepolicy=WORKSPACE_RULE_POLICY_SUFFICIENT;

	    }

	}

    }

    fclose(fp);

    /* all records read, test it's valid, consistent */

    if (  ! workspace_base->mount_path_template ) {

	/* paths have to be set */

	logoutput("error reading workspace file %s: mount path not set", workspace_base->name);

    } else if ( workspace_base->ingroup==(gid_t) -1  && ! workspace_base->filehastoexist ) {

	/* at least one of ingroup and filehastoexist must be defined */

	logoutput("error reading workspace file %s: both ingroup and filehastoexist not set", workspace_base->name);

    } else if ( workspace_base->filepolicy==WORKSPACE_RULE_POLICY_NONE && workspace_base->ingrouppolicy==WORKSPACE_RULE_POLICY_NONE ) {

	/* at least one of ingroup and filehastoexist must be required or sufficient */

	logoutput("error reading workspace file %s: both ingroup and filehastoexist not set", workspace_base->name);

    } else {

	workspace_base->flags |= WORKSPACE_FLAG_OK;

    }

}


void read_workspace_files(char *path)
{
    DIR *dp;

    dp=opendir(path);

    if (dp) {
	char *lastpart;
	struct dirent *de;
	unsigned int len0=strlen(path);

	while((de=readdir(dp))) {

	    if ( strcmp(de->d_name, ".")==0 || strcmp(de->d_name, "..")==0 ) continue;

	    logoutput("read_workspace_files: found %s", de->d_name);

	    lastpart=strrchr(de->d_name, '.');

	    if (lastpart) {

		if ( strcmp(lastpart, ".workspace")==0 ) {
		    unsigned int len1=len0 + 2 + strlen(de->d_name);
		    char workspacefile[len1];

		    memset(workspacefile, '\0', len1);
		    snprintf(workspacefile, len1, "%s/%s", path, de->d_name);

		    read_workspace_file(workspacefile, de->d_name);

		}

	    }

	}

	closedir(dp);

    } else {

	logoutput("read_workspace_files: cannot open directory %s, error %i", path, errno);

    }

}

unsigned char isrootentry(struct entry_struct *entry)
{
    return (entry->inode->ino==FUSE_ROOT_ID) ? 1 : 0;
}

void free_workspace_mount(struct workspace_mount_struct *workspace_mount)
{
    struct entry_struct *rootentry=NULL;

    rootentry=workspace_mount->rootinode.alias;

    if (rootentry) {

	/* here also free all entries and inodes and objects on this workspace ? */

	destroy_entry(rootentry);
	workspace_mount->rootinode.alias=NULL;

    }

    if (workspace_mount->fuseparam.mountpoint) {

	free(workspace_mount->fuseparam.mountpoint);
	workspace_mount->fuseparam.mountpoint=NULL;

    }

    free(workspace_mount);

}

struct workspace_mount_struct *create_workspace_mount(unsigned int *error)
{
    struct workspace_mount_struct *workspace_mount=NULL;
    struct entry_struct *rootentry=NULL;
    struct name_struct xname={NULL, 0, 0};

    xname.name=(char *) dotname;
    xname.len=strlen(xname.name);
    calculate_nameindex(&xname);

    rootentry=create_entry(NULL, &xname);

    workspace_mount=malloc(sizeof(struct workspace_mount_struct));

    if ( workspace_mount && rootentry) {
	struct inode_struct *rootinode=&workspace_mount->rootinode;

	workspace_mount->workspace_user=NULL;
	workspace_mount->workspace_base=NULL;

	workspace_mount->fuseparam.mountpoint=NULL;
	workspace_mount->fuseparam.session=NULL;
	workspace_mount->fuseparam.chan=NULL;

	workspace_mount->next=NULL;
	workspace_mount->prev=NULL;

	workspace_mount->flags=0;
	workspace_mount->nrinodes=1;
	workspace_mount->beventloop=NULL;

	init_inode(rootinode);
	rootinode->alias=rootentry;
	rootentry->inode=rootinode;

	rootinode->ino=FUSE_ROOT_ID;
	rootinode->nlookup=1;
	rootinode->mode=S_IFDIR | S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH;
	rootinode->nlink=2;
	rootinode->uid=0;
	rootinode->gid=0;
	rootinode->rdev=0;
	rootinode->size=_INODE_DIRECTORY_SIZE;

	get_current_time(&rootinode->mtim);
	memcpy(&rootinode->ctim, &rootinode->mtim, sizeof(struct timespec));

	memcpy(&rootentry->synctime, &rootinode->mtim, sizeof(struct timespec));

	init_xdata(&workspace_mount->bevent_xdata);
	workspace_mount->beventloop=get_main_beventloop();

    }

    return workspace_mount;

    error:

    if (workspace_mount) free_workspace_mount(workspace_mount);

    return NULL;

}

void free_workspace_user(struct workspace_user_struct *workspace_user)
{

    if (workspace_user) {

	if (workspace_user->private_user) {

	    free(workspace_user->private_user);
	    workspace_user->private_user=NULL;

	}

	if (workspace_user->private_home) {

	    free(workspace_user->private_home);
	    workspace_user->private_home=NULL;

	}

	if (workspace_user->temp_files) {

	    free(workspace_user->temp_files);
	    workspace_user->temp_files=NULL;

	}

	free(workspace_user);

    }

}

void notify_kernel_delete(struct workspace_mount_struct *workspace, fuse_ino_t pino, fuse_ino_t ino, char *name)
{
    int res=0;

    if (workspace->fuseparam.chan) {

#if FUSE_VERSION >= 29

	res=fuse_lowlevel_notify_delete(workspace->fuseparam.chan, pino, ino, name, strlen(name));

#else

	res=-ENOSYS;

#endif

	if (res==-ENOSYS) fuse_lowlevel_notify_inval_entry(workspace->fuseparam.chan, pino, name, strlen(name));

    }

}

void notify_kernel_create(struct workspace_mount_struct *workspace, fuse_ino_t pino, char *name)
{
    int res=0;

    if (workspace->fuseparam.chan) {

#if FUSE_VERSION >= 29

	res=fuse_lowlevel_notify_create(workspace->fuseparam.chan, pino, name, strlen(name));

#else

	res=-ENOSYS;

#endif

	if (res==-ENOSYS) fuse_lowlevel_notify_inval_entry(workspace->fuseparam.chan, pino, name, strlen(name));

    }

}

void notify_kernel_change(struct workspace_mount_struct *workspace, fuse_ino_t ino, uint32_t mask)
{

    /* TODO: */

}

/* function which processes one fuse option by adding it to the fuse arguments list 
   important here is that every fuse option has to be prefixed by a -o */

static int custom_add_fuseoption(struct fuse_args *fs_fuse_args, char *fuseoption)
{
    int len=strlen("-o")+strlen(fuseoption)+1;
    char option[len];

    memset(option, '\0', len);
    snprintf(option, len, "-o%s", fuseoption);

    return fuse_opt_add_arg(fs_fuse_args, option);

}

/*
    function to be done in a seperate thread
    here the data which is read from the VFS is 
    processed by the fuse fs call (fuse_session_process_buf)
*/

static void process_fusebuffer(void *data)
{
    struct fusedata_struct *fusedata=NULL;

    readqueue:

    pthread_mutex_lock(&fusequeue.mutex);

    fusedata=fusequeue.first;

    if (fusedata) {

	if (fusedata->next) {

	    fusequeue.first=fusedata->next;

	} else {

	    fusequeue.first=NULL;
	    fusequeue.last=NULL;

	}

    }

    pthread_mutex_unlock(&fusequeue.mutex);

    if (fusedata) {
	struct workspace_mount_struct *workspace=fusedata->workspace_mount;

	fuse_session_process_buf(workspace->fuseparam.session, &fusedata->fbuf, workspace->fuseparam.chan);

	free(fusedata->fbuf.mem);
	free(fusedata);
	fusedata=NULL;

	goto readqueue;

    }

}

static void send_fuse_error_reply(unsigned int fd, unsigned int error, uint64_t unique)
{
    struct fuse_out_header out;
    struct iovec iov[1];
    ssize_t size=0;

    out.unique=unique;
    out.error=error;

    iov[0].iov_base=(void *) &out;
    iov[0].iov_len=sizeof(struct fuse_out_header);

    out.len=iov[0].iov_len;

    size=writev(fd, iov, 1);

    if (size==-1) {

	logoutput("send_fuse_error_reply: error %i sending reply", errno);

    }

}


/*
 * process an event on a fuse fd
 * main function is to read the event and start a new thread to handle the event
 * first walk through the permanent worker threads for a free one
 * if not found one create a temporary worker thread
 *
 * parameters:
 * . event
 */

static int process_fuse_event(int fd, void *data, uint32_t events)
{
    int result=0;
    struct workspace_mount_struct *workspace=(struct workspace_mount_struct *) data;

    if ( events & (EPOLLERR | EPOLLHUP) ) {

	/* the remote site (the VFS) is disconnected (=unmounted) or some error */

        logoutput( "process_fuse_event: event %i causes exit", events);

	clear_workspace_mount(workspace);

    } else if ( ! (events & EPOLLIN) ) {

	/* only react on incoming events */
	/* huh?? this should not happen; this function is called from eventloop when some data is available on fd
	*/

        logoutput( "process_fuse_event: fd %i not available for read", fd);
        result=-EIO;

    } else {
	int lenread;
	unsigned int error=0;

	/* read the data coming from VFS */

	readbuffer:

	lenread=read(fd, workspace->fuseparam.buff.mem, workspace->fuseparam.buffsize);
	error=errno;

	if (lenread==-1) {

	    if (error==ENODEV) {

		/* unmount */

		fuse_session_exit(workspace->fuseparam.session);
		goto out;

	    } else if (error==EAGAIN || error==EWOULDBLOCK || error==ENOENT) {

		goto readbuffer;

	    } else if (error==EINTR) {

		result=-error;
		goto out;

	    } else if (error>0) {

		result=-error;
		goto out;

	    }

	} else if ((size_t) lenread < sizeof(struct fuse_in_header)) {

	    result=-EIO;
	    goto out;

	} else {
	    struct fusedata_struct *fusedata;
	    char *data=NULL;
	    unsigned int error=0;

	    /* no error, just a normal operation: data is read, get it on a special container (fusedata) and put that
	    on an internal queue (fusequeue) to be processed by the right callback (getattr, lookup, setattr etc) */

	    fusedata=malloc(sizeof(struct fusedata_struct));
	    data=malloc(lenread);

	    if (fusedata && data) {

		memmove(data, workspace->fuseparam.buff.mem, lenread);

		fusedata->fbuf.mem=data;
		fusedata->fbuf.size=lenread;
		fusedata->fbuf.fd=0;
		fusedata->fbuf.flags=0;
		fusedata->workspace_mount=workspace;
		fusedata->next=NULL;

		pthread_mutex_lock(&fusequeue.mutex);

		if (! fusequeue.last) {

		    fusequeue.last=fusedata;
		    fusequeue.first=fusedata;

		} else {

		    fusequeue.last->next=fusedata;
		    fusequeue.last=fusedata;

		}

		pthread_mutex_unlock(&fusequeue.mutex);

		work_workerthread(&workerthreads_queue, -1, process_fusebuffer, NULL, &error);

	    } else {

		error=ENOMEM;

	    }

	    if (error>0) {
		struct fuse_in_header *in = (struct fuse_in_header *) workspace->fuseparam.buff.mem;

		logoutput( "process_fuse_event: error %i processing fuse request", error);

		send_fuse_error_reply(fd, error, in->unique);

		goto out;

	    }

	}

    }

    out:

    return result;

}

int mount_workspace_mount(struct workspace_mount_struct *workspace_mount, char *mountpoint, unsigned int *error)
{
    int result=0;
    struct fuse_args workspace_fuse_args = FUSE_ARGS_INIT(0, NULL);

    *error=0;

    /*
	initialize the buffer to read the data from the VFS -> userspace
	for this workspace (=mountpoint)
    */

    workspace_mount->fuseparam.buffsize=getpagesize() + 0x1000;

    workspace_mount->fuseparam.buff.size=0;
    workspace_mount->fuseparam.buff.flags=0;
    workspace_mount->fuseparam.buff.fd=0;
    workspace_mount->fuseparam.buff.pos=0;

    workspace_mount->fuseparam.buff.mem=malloc(workspace_mount->fuseparam.buffsize);

    if (workspace_mount->fuseparam.buff.mem) {

	memset(workspace_mount->fuseparam.buff.mem, '\0', workspace_mount->fuseparam.buffsize);
	workspace_mount->fuseparam.initialized=1;

    } else {

	*error=ENOMEM;
	result=-1;
	goto out;

    }

    /*
	construct the options to parse to mount command and session setup
    */

    fuse_opt_add_arg(&workspace_fuse_args, program_name);

    custom_add_fuseoption(&workspace_fuse_args, "allow_other");
    custom_add_fuseoption(&workspace_fuse_args, "fsname=fuse-workspace");

    if (workspace_mount->workspace_base->type==WORKSPACE_TYPE_DEVICES) {

	custom_add_fuseoption(&workspace_fuse_args, "subtype=devices");

    } else if (workspace_mount->workspace_base->type==WORKSPACE_TYPE_NETWORK) {

	custom_add_fuseoption(&workspace_fuse_args, "subtype=network");

    } else if (workspace_mount->workspace_base->type==WORKSPACE_TYPE_FILE) {

	custom_add_fuseoption(&workspace_fuse_args, "subtype=file");

    }

    /* mount */

    workspace_mount->fuseparam.chan=fuse_mount(mountpoint, &workspace_fuse_args);

    if (workspace_mount->fuseparam.chan) {

	/* if mount successfull add it to the eventloop and assign a session */

	if ( add_to_beventloop(fuse_chan_fd(workspace_mount->fuseparam.chan), EPOLLIN, process_fuse_event, (void *) workspace_mount, &workspace_mount->bevent_xdata, workspace_mount->beventloop)) {

	    workspace_mount->fuseparam.session=fuse_lowlevel_new(&workspace_fuse_args, &workspace_oper, sizeof(workspace_oper), (void *) workspace_mount);

	    if (workspace_mount->fuseparam.session) {

		fuse_session_add_chan(workspace_mount->fuseparam.session, workspace_mount->fuseparam.chan);
		workspace_mount->fuseparam.mountpoint=mountpoint;
		add_xdata_to_list(&workspace_mount->bevent_xdata);

	    } else {

		fuse_session_destroy(workspace_mount->fuseparam.session);

		workspace_mount->fuseparam.session=NULL;
		workspace_mount->fuseparam.chan=NULL;

		*error=EIO;
		result=-1;

	    }

	} else {

	    fuse_chan_destroy(workspace_mount->fuseparam.chan);

	    *error=EIO;
	    result=-1;

	}

    }

    out:

    fuse_opt_free_args(&workspace_fuse_args);

    return result;

}

void umount_workspace_mount(struct workspace_mount_struct *workspace_mount)
{

    /*

	umount
	- close channel
	- close files
	- close connections per object/resource on this workspace
	- stop threads busy with this workspace

    */

    remove_xdata_from_beventloop(&workspace_mount->bevent_xdata);

    if (workspace_mount->fuseparam.session) {

	fuse_session_destroy(workspace_mount->fuseparam.session);
	workspace_mount->fuseparam.session=NULL;
	workspace_mount->fuseparam.chan=NULL;

    } else if (workspace_mount->fuseparam.chan) {

	fuse_session_destroy(workspace_mount->fuseparam.session);
	workspace_mount->fuseparam.chan=NULL;

    }

    if (workspace_mount->fuseparam.mountpoint) {

	umount2(workspace_mount->fuseparam.mountpoint, MNT_DETACH);

    }

}

void clear_workspace_mount(struct workspace_mount_struct *workspace_mount)
{

    pthread_mutex_lock(&mounts_mutex);

    umount_workspace_mount(workspace_mount);

    if (workspace_mount==mounts_list) mounts_list=workspace_mount->next;
    if (workspace_mount->prev) workspace_mount->prev->next=workspace_mount->next;
    if (workspace_mount->next) workspace_mount->next->prev=workspace_mount->prev;

    pthread_mutex_unlock(&mounts_mutex);

    free(workspace_mount);
    workspace_mount=NULL;

}

void clear_all_workspaces()
{
    struct workspace_mount_struct *workspace_mount=NULL;

    pthread_mutex_lock(&mounts_mutex);

    workspace_mount=mounts_list;

    while(workspace_mount) {

	mounts_list=workspace_mount->next;

	umount_workspace_mount(workspace_mount);
	free(workspace_mount);

	workspace_mount=mounts_list;

    }

    pthread_mutex_unlock(&mounts_mutex);

}

static int add_workspace_root_object(struct workspace_mount_struct *workspace_mount, unsigned int *error)
{
    struct workspace_object_struct *rootobject=NULL;

    rootobject=get_workspace_object();

    if (rootobject) {

	rootobject->inode=&workspace_mount->rootinode;
	workspace_mount->rootinode.object=rootobject;
	rootobject->workspace_mount=workspace_mount;

	rootobject->primary=1;

	set_module_calls_virtual(&rootobject->module_calls);

	*error=0;

	return 0;

    }

    *error=ENOMEM;
    return -1;

}

void add_usersession(char *user, uid_t uid, unsigned int *error)
{
    struct workspace_user_struct *workspace_user=NULL;

    *error=0;

    if (user) {

	logoutput("add_usersession: new entry for %s", user);

	workspace_user=users_list;

	while (workspace_user) {

	    if ( strcmp(workspace_user->private_user, user)==0 ) break;
	    workspace_user=workspace_user->next;

	}

    } else if (uid>0 && uid != (uid_t) -1) {

	logoutput("add_usersession: new entry for %i", (int) uid);

	workspace_user=users_list;

	while (workspace_user) {

	    if ( workspace_user->private_uidnr==uid ) break;
	    workspace_user=workspace_user->next;

	}

    } else {

	*error=EINVAL;
	return;

    }

    if ( workspace_user ) {

	workspace_user->nrsessions++;

    } else {
	struct passwd *pws;
	unsigned char found=0;
	struct workspace_base_struct *workspace_base=NULL;

	/* create a reference for this user */

	workspace_user=malloc(sizeof(struct workspace_user_struct));

	if ( ! workspace_user ) {

	    *error=ENOMEM;
	    return;

	}

	workspace_user->nrsessions=1;

	if (user) {

	    pws=getpwnam(user);

	} else {

	    pws=getpwuid(uid);

	}

	if ( pws ) {

	    workspace_user->private_user=strdup(pws->pw_name);

	    if ( ! workspace_user->private_user ) {

		*error=ENOMEM;
		free_workspace_user(workspace_user);
		workspace_user=NULL;
		return;

	    }

	    workspace_user->private_uidnr=pws->pw_uid;
	    workspace_user->private_gidnr=pws->pw_gid;

	    workspace_user->private_home=check_path(pws->pw_dir);

	    if (! workspace_user->private_home) {

		*error=ENOMEM;
		free_workspace_user(workspace_user);
		workspace_user=NULL;
		return;

	    }

	} else {

	    /* this should not happen, user is known 
               leave the user struct */

	    free_workspace_user(workspace_user);
	    workspace_user=NULL;
	    *error=errno;
	    return;

	}

	/* create the personal temporary files as subdirectory in ~/.cache */

	workspace_user->temp_files=create_subdirectory(workspace_user->private_home, ".cache/fuse-workspace", 
                                                              S_IFDIR | S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH, 
                                                              workspace_user->private_uidnr, workspace_user->private_gidnr, error);

	if ( ! workspace_user->temp_files ) {

	    logoutput("add_usersession: unable to set the private temporary files, cannot continue");

	    free_workspace_user(workspace_user);
	    workspace_user=NULL;
	    *error=errno;

	    return;

	} else {

	    logoutput("add_usersession: set private temp files to %s", workspace_user->temp_files);

	}

	if ( users_list ) users_list->prev=workspace_user;
	workspace_user->next=users_list;
	users_list=workspace_user;

	/* lookup in workspaces... which applies */

	workspace_base=base_list;

	while(workspace_base) {

	    if ( ! (workspace_base->flags & WORKSPACE_FLAG_OK) ) goto next;

	    logoutput("add_usersession: test %s to apply", workspace_base->name);
	    found=0;

	    if ( workspace_base->ingroup>=0 && workspace_base->ingroup != (gid_t) -1) {

		/* test user is part of this group */

		if ( workspace_base->ingrouppolicy==WORKSPACE_RULE_POLICY_SUFFICIENT || workspace_base->ingrouppolicy==WORKSPACE_RULE_POLICY_REQUIRED ) {
		    struct group *grp=getgrgid(workspace_base->ingroup);

		    if (grp && grp->gr_gid==workspace_user->private_gidnr) {

			if ( workspace_base->ingrouppolicy==WORKSPACE_RULE_POLICY_SUFFICIENT ) found=1;

		    } else if ( user_is_groupmember(workspace_user->private_user, grp)==1 ) {

			if ( workspace_base->ingrouppolicy==WORKSPACE_RULE_POLICY_SUFFICIENT ) found=1;

		    } else {

			if ( workspace_base->ingrouppolicy==WORKSPACE_RULE_POLICY_REQUIRED ) {

			    /* required, and when here none of above applies: skip */

			    workspace_base=workspace_base->next;
			    continue;

			}

		    }

		}

	    }

	    if (found==0) {

		if ( workspace_base->filehastoexist ) {

		    /* test file is present, only if policy tells so */

		    if ( workspace_base->filepolicy==WORKSPACE_RULE_POLICY_SUFFICIENT || workspace_base->filepolicy==WORKSPACE_RULE_POLICY_REQUIRED ) {

			if ( test_object_exist(workspace_base->filehastoexist, workspace_user, error)==0) {

			    /* object exist */

			    found=1;

			} else if (*error>0) {

			    logoutput("add_usersession: error %i:%s while testing %s", *error, strerror(*error), workspace_base->filehastoexist);

			}

		    }

		}

	    }

	    if ( found==1 ) {
		char *mountpoint=NULL;
		struct workspace_mount_struct *workspace_mount=NULL;
		int res;

		/* mountpoint */

		if (workspace_base->mount_path_template) {

		    mountpoint=get_path_from_template(workspace_base->mount_path_template, workspace_user, NULL, 0);

		    if ( ! mountpoint ) {

			logoutput("add_usersession: error creating directory from %s", workspace_base->mount_path_template);

			*error=ENOMEM;
			goto error;

		    }

		}

		if (create_directory(mountpoint, S_IFDIR | S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH, error) == -1) {

		    logoutput("add_usersession: error %i:%s creating directory %s", *error, strerror(*error), mountpoint);
		    goto error;

		} else {

		    logoutput("add_usersession: mountpoint %s created", mountpoint);

		}

		/* the directory mountpoint should be empty... here test it...*/

		if (ismounted(mountpoint)==1) {

		    logoutput("add_usersession: cannot add a workspace at %s, already mounted", mountpoint);
		    *error=EIO; /* a good errorcode ? */
		    goto error;

		}

		workspace_mount=create_workspace_mount(error);

		if ( workspace_mount ) {

		    workspace_mount->workspace_base=workspace_base;
		    workspace_mount->workspace_user=workspace_user;

		    if (add_workspace_root_object(workspace_mount, error)==-1) {

			logoutput("add_usersession: error mounting %s: error %i:%s", mountpoint, *error, strerror(*error));

			free_workspace_mount(workspace_mount);
			mountpoint=NULL;

		    } else {

			if (mount_workspace_mount(workspace_mount, mountpoint, error)==-1) {

			    logoutput("add_usersession: error mounting %s: error %i:%s", mountpoint, *error, strerror(*error));

			    free_workspace_mount(workspace_mount);
			    mountpoint=NULL;

			} else {

			    pthread_mutex_lock(&mounts_mutex);

			    if ( mounts_list ) mounts_list->prev=workspace_mount;
			    workspace_mount->next=mounts_list;
			    mounts_list=workspace_mount;

			    pthread_mutex_unlock(&mounts_mutex);

			}

		    }

		}

		goto next;

		/* */

		error:

		/* remove from list */

		if (workspace_mount) {

		    pthread_mutex_lock(&mounts_mutex);

		    if (workspace_mount==mounts_list) mounts_list=workspace_mount->next;
		    if (workspace_mount->prev) workspace_mount->prev->next=workspace_mount->next;
		    if (workspace_mount->next) workspace_mount->next->prev=workspace_mount->prev;

		    free(workspace_mount);
		    workspace_mount=NULL;

		    pthread_mutex_unlock(&mounts_mutex);

		}

		/* more ?? */

		logoutput("add_usersession: error handling/TODO");

	    }

	    next:

	    workspace_base=workspace_base->next;

	}


    }

}

void remove_usersession(char *user, uid_t uid, unsigned int *error)
{

    logoutput("remove_usersession: remove session TODO");

}

void update_workspaces(char *user, uid_t uid, unsigned char what)
{
    if (what==1) {
	unsigned int error=0;

	add_usersession(user, uid, &error);

    } else if (what==0) {
	unsigned int error=0;

	remove_usersession(user, uid, &error);

    }

}

void increase_inodes_workspace(void *data)
{
    struct workspace_mount_struct *workspace_mount=(struct workspace_mount_struct *) data;

    workspace_mount->nrinodes++;

}

void decrease_inodes_workspace(void *data)
{
    struct workspace_mount_struct *workspace_mount=(struct workspace_mount_struct *) data;

    workspace_mount->nrinodes--;

}
