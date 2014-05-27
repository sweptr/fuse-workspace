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
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <err.h>

#include <inttypes.h>
#include <ctype.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <pthread.h>
#include <sys/syscall.h>

#ifndef ENOATTR
#define ENOATTR ENODATA        /* No such attribute */
#endif

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

#include "fuse-workspace.h"
#include "readdir-utils.h"

struct linux_dirent {
    unsigned long				d_ino;
    unsigned long				d_off;
    unsigned short				d_reclen;
    char					d_name[];
};

static int get_direntry_getdents(struct readdir_struct *r, struct name_struct *xname, unsigned char *type, unsigned int *error)
{
    struct linux_dirent *linux_de;
    char *dep;

    readnext:

    if (r->type.getdents.pos >= r->type.getdents.read) {
	int bytes=0;

	errno=0;

	bytes=syscall(SYS_getdents, r->fd, r->type.getdents.buffer, r->type.getdents.size);

	if (bytes<=0) {

	    if (bytes==-1) *error=errno;

	    return bytes;

	}

	r->type.getdents.pos=0;
	r->type.getdents.read=bytes;

    }

    dep = r->type.getdents.buffer + r->type.getdents.pos;
    linux_de=(struct linux_dirent *) dep;

    if (strcmp(linux_de->d_name, ".")==0 || strcmp(linux_de->d_name, "..")==0) {

	r->type.getdents.pos+=linux_de->d_reclen;
	goto readnext;

    }

    *type=*(dep  + linux_de->d_reclen - 1);
    xname->name=linux_de->d_name;

    r->type.getdents.pos+=linux_de->d_reclen;

    return 1;

}

static void close_getdents(struct readdir_struct *r)
{

    if (r) {

	if (r->type.getdents.buffer) {

	    free(r->type.getdents.buffer);
	    r->type.getdents.buffer=NULL;

	}

	free(r);

    }

}

struct readdir_struct *init_readdir_getdents(char *path, int fd, unsigned int *error)
{
    struct readdir_struct *r=NULL;

    r=malloc(sizeof(struct readdir_struct));

    if (! r) {

	*error=ENOMEM;
	goto error;

    }

    memset(r, 0, sizeof(struct readdir_struct));

    r->fd=fd;

    r->type.getdents.buffer=malloc(_READDIR_GETDENTS_BUFFSIZE);

    if ( ! r->type.getdents.buffer ) {

	close_getdents(r);
	*error=ENOMEM;
	goto error;

    }

    r->type.getdents.size=_READDIR_GETDENTS_BUFFSIZE;
    r->type.getdents.pos=0;
    r->type.getdents.read=0;

    r->get_direntry = get_direntry_getdents;
    r->close = close_getdents;

    return r;

    error:

    return NULL;

}

static int get_direntry_readdir(struct readdir_struct *r, struct name_struct *xname, unsigned char *type, unsigned int *error)
{
    struct dirent *result=NULL;

    readnext:

    *error=readdir_r(r->type.readdir.dp, (struct dirent *) r->type.readdir.de, &result);

    if (*error==0) {

	if (result) {

	    if (strcmp(result->d_name, ".")==0 || strcmp(result->d_name, "..")==0) goto readnext;

	    *type=result->d_type;
	    xname->name=result->d_name;

	    return 1;

	} else {

	    return 0;

	}

    }

    return -1;

}

static void close_readdir(struct readdir_struct *r)
{

    if (r) {

	if (r->type.readdir.dp) {

	    closedir(r->type.readdir.dp);
	    r->type.readdir.dp=NULL;

	}

	if (r->type.readdir.de) {

	    free(r->type.readdir.de);
	    r->type.readdir.de=NULL;

	}

	free(r);

    }

}

struct readdir_struct *init_readdir_readdir(char *path, int fd, unsigned int *error)
{
    struct readdir_struct *r;
    int name_max=0;
    unsigned int recsize=0;

    r=malloc(sizeof(struct readdir_struct));

    if (! r) {

	*error=ENOMEM;
	goto error;

    }

    memset(r, 0, sizeof(struct readdir_struct));

    name_max=pathconf(path, _PC_NAME_MAX);

    if (name_max==0 || name_max==-1) name_max=256;

    recsize=offsetof(struct dirent, d_name) + 1 + name_max;

    r->type.readdir.de=malloc(recsize);

    if (! r->type.readdir.de) {

	close_readdir(r);
	*error=ENOMEM;
	goto error;

    }

    r->type.readdir.size=recsize;

    r->type.readdir.dp=opendir(path);

    if ( ! r->type.readdir.dp) {

	close_readdir(r);
	*error=errno;
	goto error;

    }

    r->get_direntry = get_direntry_readdir;
    r->close = close_readdir;

    return r;

    error:

    return NULL;

}


