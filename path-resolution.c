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
#include <sys/epoll.h>

#include <pthread.h>

#ifndef ENOATTR
#define ENOATTR ENODATA        /* No such attribute */
#endif

#define LOG_LOGAREA LOG_LOGAREA_PATH_RESOLUTION

#include <fuse/fuse_lowlevel.h>

#include "logging.h"
#include "simpleoverlayfs.h"
#include "entry-management.h"
#include "path-resolution.h"
#include "utils.h"

const char *rootpath="/";
const char *dotdotname="..";
const char *dotname=".";

int get_path(struct call_info_struct *call_info, const char *name)
{
    int nreturn=0;
    struct entry_struct *parent=NULL;

    if (name) {

	parent=call_info->entry;

    } else {

	name=call_info->entry->name;
	parent=call_info->entry->parent;

    }

    if ( isrootentry(parent) ) {
	int len=strlen(name);

	call_info->pathinfo.path=malloc(len+2);

	if (call_info->pathinfo.path) {
	    char *pathstart=call_info->pathinfo.path;

	    *pathstart='/';
	    pathstart++;

	    memcpy(pathstart, name, len);

	    pathstart+=len;
	    *pathstart='\0';

	    call_info->pathinfo.flags=PATHINFOFLAGS_ALLOCATED;
	    call_info->pathinfo.len=len+1;

	} else {

	    nreturn=-ENOMEM;

	}

    } else {
	pathstring path;
	char *pathstart = path + sizeof(pathstring) - 1;
	int len, pathlen=0;

	*pathstart='\0';

	len=strlen(name);
	pathstart-=len;
	memcpy(pathstart, name, len);

	pathstart--;
	*pathstart='/';

	pathlen+=len+1;

	while (parent) {

	    name=parent->name;

	    len=strlen(name);
	    pathstart-=len;
	    memcpy(pathstart, name, len);

	    pathstart--;
	    *pathstart='/';

	    pathlen+=len+1;

	    parent=parent->parent;

	    if ( isrootentry(parent) ) break;

	}

	/* create a path just big enough */

	call_info->pathinfo.path=malloc(pathlen+1);

	if ( call_info->pathinfo.path ) {

    	    memcpy(call_info->pathinfo.path, pathstart, pathlen+1);
	    call_info->pathinfo.flags=PATHINFOFLAGS_ALLOCATED;
	    call_info->pathinfo.len=pathlen;

	} else {

    	    nreturn=-ENOMEM;

	}

    }

    if (nreturn<0) {

	logoutput("get_path: error %i", nreturn);

    } else {

	logoutput("get_path: path: %s", call_info->pathinfo.path);

    }

    return nreturn;

}

void free_path_pathinfo(struct pathinfo_struct *pathinfo)
{
    if ((pathinfo->flags & PATHINFOFLAGS_ALLOCATED) && ! (pathinfo->flags & PATHINFOFLAGS_INUSE)) {

	if (pathinfo->path) {

	    free(pathinfo->path);
	    pathinfo->path=NULL;

	}

	pathinfo->flags-=PATHINFOFLAGS_ALLOCATED;

    }

}

struct entry_struct *check_notifyfs_path(char *path)
{
    char *pos, *slash;
    struct entry_struct *parent_entry, *entry=NULL;

    parent_entry=get_rootentry();
    entry=parent_entry;

    pos=path;

    while(1) {

        /*  walk through path from begin to end and 
            check every part */

        slash=strchr(pos, '/');

        if ( slash==pos ) {

            /* ignore the starting slash*/

            pos++;

            /* if nothing more (==only a slash) stop here */

            if (strlen(pos)==0) {

        	// entry=parent_entry;
        	break;

	    }

            continue;

        }

        if ( slash ) {

	    /* replace the slash by a \0: make the name a string: zero terminated */

            *slash='\0';

        }

        entry=find_entry_table(parent_entry, pos, 1);

        if ( slash ) {

            /* make slash a slash again (was turned into a \0) */

            *slash='/';
            pos=slash;

        }

	if ( ! entry || ! slash ) break;

	parent_entry=entry;

    }

    out:

    return entry;

}

