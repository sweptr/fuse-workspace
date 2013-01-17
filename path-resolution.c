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

int get_path(struct path_info_struct *path_info, const char *name)
{
    int nreturn=0;
    struct entry_struct *parent=path_info->parent;

    if ( isrootentry(parent) ) {
	int len=strlen(name);

	path_info->path=malloc(len+2);

	if (path_info->path) {
	    char *pathstart=path_info->path;

	    *pathstart='/';
	    pathstart++;

	    memcpy(pathstart, name, len);

	    pathstart+=len;
	    *pathstart='\0';

	    path_info->freepath=1;

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

	path_info->path=malloc(pathlen+1);

	if ( path_info->path ) {

    	    memcpy(path_info->path, pathstart, pathlen+1);
	    path_info->freepath=1;

	} else {

    	    nreturn=-ENOMEM;

	}

    }

    if (nreturn<0) {

	logoutput("get_path: error %i", nreturn);

    } else {

	logoutput("get_path: path: %s", path_info->path);

    }

    return nreturn;

}

void clear_path_info(struct path_info_struct *path_info)
{

    if ( path_info->freepath==1 ) {

	free(path_info->path);
	path_info->path=NULL;

	path_info->freepath=0;

    }

}
