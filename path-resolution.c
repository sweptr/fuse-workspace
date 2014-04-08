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

#include <pthread.h>

#ifndef ENOATTR
#define ENOATTR ENODATA        /* No such attribute */
#endif

#include "simpleoverlayfs.h"
#include "entry-management.h"
#include "path-resolution.h"
#include "utils.h"
#include "options.h"
#include "simple-list.h"

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

extern struct overlayfs_options_struct overlayfs_options;

struct pathcache_struct {
    struct entry_struct 	*entry;
    char 			*path;
    unsigned int		len;
    struct timespec		eval_moment;
    struct pathcache_struct 	*next;
};

static struct pathcache_struct *pathcache_list=NULL;
static pthread_mutex_t pathcache_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct simple_group_struct pathcache_group;

const char *rootpath="/";
const char *dotdotname="..";
const char *dotname=".";

static unsigned int pathmax=2;
static pthread_mutex_t pathmax_mutex = PTHREAD_MUTEX_INITIALIZER;


static unsigned int calculate_pathcache_hash(struct entry_struct *entry)
{
    if (entry->inode) return entry->inode->ino % pathcache_group.len;

    return 0;

}

int pathcache_hashfunction(void *data)
{
    struct pathcache_struct *pathcache=(struct pathcache_struct *) data;

    return calculate_pathcache_hash(pathcache->entry);

}

int init_pathcache_group(unsigned int *error)
{
    int result=0;

    result=initialize_group(&pathcache_group, pathcache_hashfunction, 64, error);

    if (result<0) {

	*error=abs(result);
	result=-1;

    }

    return result;

}

/* lookup pathcache in hash table */

static char *lookup_pathcache(struct call_info_struct *call_info)
{
    struct pathcache_struct *pathcache=NULL;
    void *index=NULL;
    unsigned int hashvalue=0;

    lock_list_group(&pathcache_group);

    /* first check a path is present for parent */

    hashvalue=calculate_pathcache_hash(call_info->entry->parent);

    pathcache=get_next_element(&pathcache_group, &index, hashvalue);

    while(pathcache) {

	if (call_info->entry->parent==pathcache->entry) {
	    unsigned int len = strlen(call_info->entry->name);

	    call_info->pathinfo.path=malloc(pathcache->len + 2 + len);

	    if (call_info->pathinfo.path) {
		char *pos=call_info->pathinfo.path;

		memcpy(pos, pathcache->path, pathcache->len);
		pos+=pathcache->len;
		*pos = '/';
		pos++;
		memcpy(pos, call_info->entry->name, len);
		pos+=len;
		*pos = '\0';

		call_info->pathinfo.len=pathcache->len;
		call_info->pathinfo.flags=PATHINFOFLAGS_ALLOCATED;

	    }

	    get_current_time(&pathcache->eval_moment);

	    goto unlock;

	}

	pathcache=get_next_element(&pathcache_group, &index, hashvalue);

    }

    /* second check a path is present for entry */

    hashvalue=calculate_pathcache_hash(call_info->entry);
    index=NULL;

    pathcache=get_next_element(&pathcache_group, &index, hashvalue);

    while(pathcache) {

	if (call_info->entry==pathcache->entry) {

	    call_info->pathinfo.path=malloc(pathcache->len+1);

	    if (call_info->pathinfo.path) {
		char *pos=call_info->pathinfo.path;

		memcpy(pos, pathcache->path, pathcache->len);
		pos+=pathcache->len;
		*pos = '\0';
		call_info->pathinfo.len=pathcache->len;
		call_info->pathinfo.flags=PATHINFOFLAGS_ALLOCATED;

	    }

	    get_current_time(&pathcache->eval_moment);

	    break;

	}

	pathcache=get_next_element(&pathcache_group, &index, hashvalue);

    }

    unlock:

    unlock_list_group(&pathcache_group);

    return call_info->pathinfo.path;

}

void clean_pathcache()
{
    struct timespec current_time;
    unsigned int hashvalue=0;
    void *index=NULL;
    struct pathcache_struct *pathcache=NULL;

    lock_list_group(&pathcache_group);

    get_current_time(&current_time);

    while (hashvalue<pathcache_group.len) {

	index=NULL;

	pathcache=get_next_element(&pathcache_group, &index, hashvalue);

	while(pathcache) {

	    if (is_later(&current_time, &pathcache->eval_moment, 1, 0)==1) {
		struct pathcache_struct *next_pathcache=get_next_element(&pathcache_group, &index, hashvalue);
		struct simple_list_struct *element=(struct simple_list_struct *) index;

		move_from_used(&pathcache_group, element);

		free(element);

		if (pathcache->path) {

		    free(pathcache->path);
		    pathcache->path=NULL;

		}

		free(pathcache);

		pathcache=next_pathcache;

	    } else {

		pathcache=get_next_element(&pathcache_group, &index, hashvalue);

	    }

	}

	hashvalue++;

    }

    unlock_list_group(&pathcache_group);

}

int get_path(struct call_info_struct *call_info, unsigned int *error)
{
    int result=0;

    if ( isrootentry(call_info->entry->parent) ) {
	char *name=call_info->entry->name;
	unsigned int len=strlen(name);

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

	    *error=ENOMEM;
	    result=-1;

	}

    } else if (! lookup_pathcache(call_info)) {
	unsigned int maxlen=pathmax, pathlen=0;
	char path[maxlen];
	char *pathstart = NULL;
	unsigned short len=0;
	char *name=call_info->entry->name;
	struct entry_struct *parent=call_info->entry->parent;

	pathstart = path + maxlen - 1;
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

    	    *error=ENOMEM;
    	    result=-1;

	}

    }

    return result;

}

int get_path_extra(struct call_info_struct *call_info, const char *name, unsigned int *error)
{
    int result=0;

    if ( isrootentry(call_info->entry) ) {
	unsigned short len=strlen(name);

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

	    *error=ENOMEM;
	    result=-1;

	}

    } else if (! lookup_pathcache(call_info)) {
	unsigned short len=strlen(name);
	unsigned int maxlen=pathmax + len + 1, pathlen=0;
	char path[maxlen + 1];
	char *pathstart = NULL;
	struct entry_struct *parent=call_info->entry;

	pathstart = path + maxlen ;
	*pathstart='\0';

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

    	    *error=ENOMEM;
    	    result=-1;

	}

    }

    return result;

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

void add_pathcache(struct pathinfo_struct *pathinfo, struct entry_struct *entry)
{

    if ((pathinfo->flags & PATHINFOFLAGS_ALLOCATED) && ! (pathinfo->flags & PATHINFOFLAGS_INUSE)) {

	if (pathinfo->path) {
	    struct pathcache_struct *pathcache=NULL;

	    pthread_mutex_lock(&pathcache_mutex);

	    pathcache=pathcache_list;

	    while(pathcache) {

		if (pathcache->entry==entry) {

		    if (strcmp(pathcache->path, pathinfo->path)!=0) {

			pathcache->path=pathinfo->path;
			pathcache->len=pathinfo->len;

			pathinfo->path=NULL;
			pathinfo->flags-=PATHINFOFLAGS_ALLOCATED;

		    }

		    break;

		}

		pathcache=pathcache->next;

	    }

	    if (! pathcache) {

		pathcache=malloc(sizeof(struct pathcache_struct));

		if (pathcache) {

		    pathcache->path=pathinfo->path;
		    pathcache->entry=entry;
		    pathcache->len=pathinfo->len;
		    get_current_time(&pathcache->eval_moment);

		    pthread_mutex_lock(&pathcache_mutex);

		    pathcache->next=pathcache_list;
		    pathcache_list=pathcache;

		    pathinfo->path=NULL;
		    pathinfo->flags-=PATHINFOFLAGS_ALLOCATED;

		}

	    }

	    pthread_mutex_unlock(&pathcache_mutex);

	}

    }

}

void adjust_pathmax(unsigned int len)
{
    pthread_mutex_lock(&pathmax_mutex);

    if (len>pathmax) pathmax=len;

    pthread_mutex_unlock(&pathmax_mutex);
}

unsigned int get_pathmax()
{
    return pathmax;
}
